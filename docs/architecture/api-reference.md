# API Reference & Developer Guide

This document describes the API architecture of the **BlueTeam / Agentix** platform. It provides details on endpoints, request/response models, authentication mechanisms, and Server-Sent Events (SSE) streaming payload structures.

---

## 1. API Architecture Overview

The platform splits API boundaries into two layers to isolate public interfaces from core reasoning engine operations:
1. **Agentix Gateway (External - Port 8001)**: Exposes public REST endpoints, handles user authentication via PostgreSQL-backed local JSON Web Tokens (JWT), and performs session ownership checks to prevent Insecure Direct Object Reference (IDOR) attacks.
2. **Agentix Core API (Internal - Port 8000)**: Coordinates the ReAct loops, manages session workspaces, interacts with databases (Redis and Postgres/pgvector), and communicates with FastMCP servers (such as `TriageCore`).

```
                    [ External Network ]
                             │
                             ▼ (JWT Bearer Token / Port 8001)
                    ┌─────────────────┐
                    │ Agentix Gateway │
                    └────────┬────────┘
                             │
                             ▼ (X-Internal-Api-Key / Port 8000)
                    ┌─────────────────┐
                    │  Agentix Core   │
                    └─────────────────┘
```

---

## 2. Authentication & Headers

### 2.1. Gateway Authentication (JWT)
External clients must log in to receive an access token. All subsequent requests to protected endpoints must include the token in the HTTP `Authorization` header:

```http
Authorization: Bearer <jwt-access-token>
```

### 2.2. Internal API Authentication (`X-Internal-Api-Key`)
Communication from the Gateway to the Core API is protected by a shared secret key configured in the environment (`AGENTIX_INTERNAL_API_KEY`). Requests must include this key in the header:

```http
X-Internal-Api-Key: <shared-api-secret-key>
```
*Note: Exempt endpoints include `/health`, `/docs`, and `/openapi.json`.*

---

## 3. Agentix Gateway (External Web API - Port 8001)

### 3.1. User Login
Authenticates users against the database and returns a JWT access token.

* **Endpoint**: `POST /web/login`
* **Content-Type**: `application/json`
* **Request Payload**:
  ```json
  {
    "username": "agentix-analyst",
    "password": "Password-2026!"
  }
  ```
* **Response Payload (HTTP 200)**:
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer"
  }
  ```
* **Errors**:
  - `HTTP 401 Unauthorized`: Incorrect username or password.

### 3.2. Chat & Investigate (SSE Stream)
Starts a new chat session or continues an existing one, returning a Server-Sent Events (SSE) stream of the agent's progress.

* **Endpoint**: `POST /web/chat`
* **Content-Type**: `application/json`
* **Headers**: `Authorization: Bearer <JWT>`
* **Request Payload**:
  ```json
  {
    "message": "Investigate alert with ID wazuh-alert-8923 and summarize the results.",
    "session_id": "8b9f71c-4b53-488f-9a71-bf17bde91c1b", // Optional: reuse existing session
    "agent": "soc_analyst" // Optional persona: soc_analyst | threat_intel | log_analyst
  }
  ```
* **Response**: `text/event-stream` containing JSON payloads (see Section 5).
* **Errors**:
  - `HTTP 400 Bad Request`: Message is empty.
  - `HTTP 403 Forbidden`: The user is not the owner of the requested `session_id` (IDOR protection).
  - `HTTP 404 Not Found`: Session ID does not exist in Redis.

### 3.3. Get Authenticated User Info
* **Endpoint**: `GET /web/me`
* **Headers**: `Authorization: Bearer <JWT>`
* **Response Payload (HTTP 200)**:
  ```json
  {
    "uid": "agentix-analyst",
    "role": "analyst",
    "email": "analyst@company.local"
  }
  ```

---

## 4. Agentix Core API (Internal API - Port 8000)

### 4.1. Create Session
Registers a new session in Redis and initializes its filesystem sandbox workspace.

* **Endpoint**: `POST /v1/session`
* **Headers**: `X-Internal-Api-Key: <secret>`
* **Request Payload**:
  ```json
  {
    "user_id": "agentix-analyst"
  }
  ```
* **Response Payload (HTTP 200)**:
  ```json
  {
    "session_id": "8b9f71c-4b53-488f-9a71-bf17bde91c1b",
    "message": "Session created successfully. Use this ID for /chat/stream",
    "workspace_enabled": true
  }
  ```

### 4.2. Chat Stream
Executes the ReAct reasoning loop step-by-step for the specified session and streams output as Server-Sent Events.

* **Endpoint**: `POST /v1/chat/stream`
* **Headers**: `X-Internal-Api-Key: <secret>`
* **Request Payload**:
  ```json
  {
    "session_id": "8b9f71c-4b53-488f-9a71-bf17bde91c1b",
    "message": "Investigate alert with ID wazuh-alert-8923 and summarize the results.",
    "agent": "soc_analyst"
  }
  ```
* **Response**: `text/event-stream` (SSE format).

### 4.3. Destroy Session
Cleans up workspace folders (deletes session directory) and removes all session state from Redis.

* **Endpoint**: `DELETE /v1/session/{session_id}`
* **Headers**: `X-Internal-Api-Key: <secret>`
* **Response Payload (HTTP 200)**:
  ```json
  {
    "session_id": "8b9f71c-4b53-488f-9a71-bf17bde91c1b",
    "workspace_cleanup": "Workspace directories removed successfully.",
    "session_cleared": true
  }
  ```

### 4.4. Get Workspace Info
Retrieves disk space usage statistics for the session workspace.

* **Endpoint**: `GET /v1/session/{session_id}/workspace`
* **Headers**: `X-Internal-Api-Key: <secret>`
* **Response Payload (HTTP 200)**:
  ```json
  {
    "session_id": "8b9f71c-4b53-488f-9a71-bf17bde91c1b",
    "workspace": {
      "total_bytes": 1024500,
      "files_count": 4,
      "quota_bytes": 52428800
    }
  }
  ```

---

## 5. SSE Payload & ReAct Step Structure

Streaming responses are returned in standard Server-Sent Events (SSE) format, where each event payload starts with `data: ` and ends with `\n\n`. The final event is marked by `data: [DONE]`.

Each payload chunk represents a single **ReAct Step** and follows this JSON structure:

```json
{
  "type": "thought", // Steps: session | thought | action | observation | answer | error
  "content": "Analyzing Wazuh event log details to locate source IP address.",
  "tool": null,
  "tool_input": null,
  "tool_output": null
}
```

### 5.1. Event Types

| Step `type` | Description | Accompanying Fields |
|:---|:---|:---|
| `session` | Broadcasts metadata or workspace initialization changes. | `session_id` |
| `thought` | The agent's chain-of-thought reasoning step. | `content` (Markdown string) |
| `action` | The agent initiates a tool execution call. | `tool` (name), `tool_input` (arguments dict) |
| `observation` | The result returned from the tool execution. | `tool`, `tool_output` (string response payload) |
| `answer` | The final structured output delivered to the user. | `content` (Markdown report) |
| `error` | Sent if the ReAct loop or connection crashes. | `content` (Error message details) |

### 5.2. Example Stream Lifecycle

1. **Session Initialized**:
   ```data
   data: {"type": "session", "session_id": "8b9f71c-4b53-488f-9a71-bf17bde91c1b"}
   ```
2. **Agent Thought**:
   ```data
   data: {"type": "thought", "content": "I should retrieve the alert details for alert ID '8923' using the SIEM logs.", "tool": null, "tool_input": null, "tool_output": null}
   ```
3. **Agent Tool Call Action**:
   ```data
   data: {"type": "action", "content": "", "tool": "query_siem_logs", "tool_input": {"query": "rule.id:100002 AND id:8923"}, "tool_output": null}
   ```
4. **Tool Response Observation**:
   ```data
   data: {"type": "observation", "content": "", "tool": "query_siem_logs", "tool_input": null, "tool_output": "{\"alert_id\": \"8923\", \"severity\": 7, \"description\": \"OS Credential Dumping\", \"agent_id\": \"002\", \"src_ip\": \"198.51.100.22\"}"}
   ```
5. **Agent Thought**:
   ```data
   data: {"type": "thought", "content": "The alert shows host credential dumping on host-2. I need to run VirusTotal lookup on the source IP.", "tool": null, "tool_input": null, "tool_output": null}
   ```
6. **Agent Final Answer**:
   ```data
   data: {"type": "answer", "content": "### Incident Triage Summary\n* **Alert**: Credential Dumping\n* **Host**: agent-002\n* **Attacker IP**: 198.51.100.22\n\n**Recommendation**: Isolate host-002 and block IP at the firewall.", "tool": null, "tool_input": null, "tool_output": null}
   ```
7. **Stream End**:
   ```data
   data: [DONE]
   ```
