# Security Model & Hardening Guide

Security architecture, threat model, and hardening guide for the Agentix / BlueTeam platform.

> **Scope:** This document covers platform-level security. For security configurations
> of components like Wazuh/Elasticsearch, refer to the respective product documentation.

---

## Security Layers Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    EXTERNAL REQUESTS                         │
│              (Browser / API Client / Wazuh)                 │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTPS / JWT
┌──────────────────────────▼──────────────────────────────────┐
│                 API GATEWAY (Port 8001)                      │
│   • JWT validation       • Rate limiting                     │
│   • CORS enforcement     • Origin whitelisting               │
│   • Request logging      • Header sanitization              │
└──────────────────────────┬──────────────────────────────────┘
                           │ X-Internal-Api-Key (Internal)
┌──────────────────────────▼──────────────────────────────────┐
│                  CORE API (Port 8000)                        │
│   • Tool sandbox         • Workspace isolation              │
│   • Disk quota           • Path traversal protection        │
│   • HITL approval        • Structlog audit trail            │
└────────────┬─────────────────────────┬───────────────────────┘
             │ FastMCP Protocol        │ Redis / Postgres
┌────────────▼────────────┐  ┌────────▼────────────────────────┐
│  TRIAGE CORE (Port 8081)│  │  DATA LAYER                      │
│  Playbook execution      │  │  • Redis: session state          │
│  SOC tool adapters       │  │  • Postgres: agent config        │
└─────────────────────────┘  └──────────────────────────────────┘
```

---

## 1. Authentication and Authorization

### 1.1 Dual-Layer Auth Model

| Layer | Mechanism | Enforcement Point |
|---|---|---|
| **External (Browser → Gateway)** | JWT Bearer Token | `X-Authorization: Bearer <token>` |
| **Internal (Gateway → Core)** | Pre-shared key | `X-Internal-Api-Key: <key>` |
| **WebHook (Wazuh → Gateway)** | Path-based secret token | `/webhook/wazuh/{token}` |

### 1.2 JWT Validation (Gateway Layer)

The Gateway validates the JWT on every request. `user_id` and `roles` are extracted from the token payload and forwarded to Core via `X-User-Id` / `X-User-Roles` headers.

**Critical Configuration:**

```env
# .env
AGENTIX_JWT_SECRET=<strong random string of at least 32 characters>
AGENTIX_JWT_ALGORITHM=HS256       # or RS256
AGENTIX_JWT_EXPIRE_MINUTES=60
```

> [!WARNING]
> The default value `dev-internal-key-change-me-in-production` must **never** be used in production. Generate `AGENTIX_INTERNAL_API_KEY` with `openssl rand -hex 32`.

### 1.3 Internal API Key (Gateway → Core)

The Core API checks the `X-Internal-Api-Key` header on all requests coming from the Gateway.
If this header does not match, the request is rejected with `403 Forbidden`.

```python
# Check in src/Agentix/agentix/api/server.py
if request.headers.get("X-Internal-Api-Key") != settings.agentix_internal_api_key:
    raise HTTPException(status_code=403, detail="Forbidden")
```

### 1.4 WebHook Token Validation

Webhooks from Wazuh include a secret token as a path parameter:

```
POST /webhook/wazuh/{WAZUH_WEBHOOK_SECRET_TOKEN}
```

This token is defined in `.env` and validated by the Gateway.

---

## 2. Network Security

### 2.1 CORS Policy

The Gateway only allows origins listed in `GATEWAY_ALLOWED_ORIGINS`:

```env
GATEWAY_ALLOWED_ORIGINS=https://app.yourdomain.com,https://soc.yourdomain.com
```

Using `*` (wildcard) **in production** is insecure — it should never be done.

### 2.2 Service Isolation (Docker)

All services must be deployed on the Docker Compose **internal network**. Only the Gateway should be exposed to the outside world:

```yaml
# docker-compose.yml (recommended structure)
services:
  gateway:
    ports:
      - "8001:8001"    # Only externally exposed port
  core:
    # Port is not exposed — internal network only
    expose:
      - "8000"
  triage:
    expose:
      - "8081"
  redis:
    # Must never be exposed externally
    expose:
      - "6379"
  postgres:
    expose:
      - "5432"
```

### 2.3 TLS / HTTPS

In production, a reverse proxy (nginx / Traefik) should be placed in front of the Gateway and TLS termination should be handled there:

```nginx
server {
    listen 443 ssl;
    ssl_certificate     /etc/ssl/certs/agentix.crt;
    ssl_certificate_key /etc/ssl/private/agentix.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://gateway:8001;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 3. File System Security (SessionWorkspace)

### 3.1 Path Traversal Protection

On every tool invocation, the file path is passed through `SessionWorkspace.resolve_path()`.
If the path escapes the session root, a `PermissionError` is raised:

```python
def resolve_path(self, relative_path: str, subdirectory: str = "outputs") -> Path:
    base = self.root / subdirectory
    resolved = (base / relative_path).resolve()

    # Critical security check:
    if not str(resolved).startswith(str(self.root.resolve())):
        raise PermissionError(
            f"Access denied: '{relative_path}' is outside the workspace boundary."
        )
    return resolved
```

**Covered Attack Vectors:**

```
../../../etc/passwd          → PermissionError ✓
../../.env                   → PermissionError ✓
outputs/../../../etc/shadow  → PermissionError ✓
```

### 3.2 Disk Quota Enforcement

Maximum disk usage is limited per session. `check_quota()` is called before every write:

```env
AGENTIX_SESSION_QUOTA_MB=100    # Default: 100 MB per session
```

When exceeded:
```python
raise PermissionError("Session workspace quota exceeded: X / Y bytes.")
```

### 3.3 Session Ownership Validation

Workspace access is restricted by `owner_id`. Access to another user's session returns `False`:

```python
def validate_access(self, owner_id: str) -> bool:
    if self.owner_id == "anonymous":
        return True  # Development mode
    return self.owner_id == owner_id
```

> [!IMPORTANT]
> Ensure `owner_id = "anonymous"` is never used in production. This condition grants cross-access to all users.

### 3.4 Workspace Directory Structure

```
workspace/sessions/{session_id}/
├── downloads/     # Temporary files downloaded by tools (deleted on cleanup)
├── outputs/       # Persistent reports (PRESERVED on cleanup)
├── uploads/       # User uploads (PRESERVED on cleanup)
├── temp/          # Temporary processing files (deleted on cleanup)
└── .session_meta.json  # Session metadata (owner_id, quota, status)
```

### 3.5 Process Sandbox Execution Isolation

Commands executed inside the sandbox environment ([executor.py](../../src/Agentix/agentix/sandbox/executor.py)) are isolated in a dedicated process group (`process_group=0` in subprocess initiation). 

This prevents the execution of command pipelines or backgrounded scripts from spawning untracked orphan processes (zombies) that leak memory and CPU resources on the host system. 
When a subprocess execution hits its timeout, the system terminates the entire process group using `SIGKILL`:

```python
# Terminate the entire process group to clean up all children
os.killpg(proc.pid, signal.SIGKILL)
```

### 3.6 Tool Input Payload Limitation

To prevent memory exhaustion (Out of Memory - OOM) attacks and database serialization failures, all large input dictionary payloads (such as `extra_context` and `data` in [soc_tools.py](../../src/TriageCore/triage_core/tools/soc_tools.py)) are validated before processing:

- Input dictionary arguments are capped at a maximum of **64KB (65,536 bytes)** JSON-serialized payload size.
- If the size exceeds this threshold, the execution fails fast with a size violation error.

---

## 4. Human-in-the-Loop (HITL) Security

### 4.1 Tools Requiring Approval

Irreversible or high-risk tool invocations (`requires_confirmation=True`) are not executed without user approval:

```python
# Check in Orchestrator (core/orchestrator.py)
if tool.requires_confirmation(**t_args) and not t_args.get("approved"):
    # Save state, request approval
    await self._memory.set_metadata(session_id, "draft_history", messages)
    yield ReActStep(StepType.CONFIRM, ...)
    return  # Execution stops
```

### 4.2 Approval Flow

```
User Request
     │
     ▼
Orchestrator: tool.requires_confirmation() == True?
     │ Yes
     ▼
draft_history is saved to Redis
CONFIRM step is yielded (Teams/Slack notification sent)
     │
     ▼
User responds with "yes" / "confirm" / "approve"
     │
     ▼
draft_history is loaded, tool runs with force_approved=True
```

**Accepted Confirmation Keywords:**
```python
POSITIVE_CONFIRMATIONS = {
    "yes", "confirm", "evet", "onay", "y", "approve", "ok", "tamam", "go", "proceed"
}
```

All other responses are treated as "cancel".

### 4.3 Examples of Risky Tools

The following tools should be marked with `requires_confirmation=True`:

- `isolate_agent` — Disconnects the agent from the network
- `disable_user_account` — Disables a user account
- `block_ip_firewall` — Blocks an IP in the firewall
- `delete_file` — Deletes a file
- `run_shell_command` — Executes a shell command

---

## 5. Secrets Management

### 5.1 Environment Variable Security

All sensitive values are stored in `.env` files and must never be committed to Git:

```bash
# Must be present in .gitignore:
.env
*.env
*.env.local
!.env.example
```

### 5.2 Secret Generation

```bash
# Generate a strong random value for AGENTIX_INTERNAL_API_KEY
openssl rand -hex 32

# For JWT secret
openssl rand -base64 48

# For webhook token
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 5.3 Production Secret Checklist

| Secret | Minimum Length | Recommendation |
|---|---|---|
| `AGENTIX_INTERNAL_API_KEY` | 32 char hex | `openssl rand -hex 32` |
| `AGENTIX_JWT_SECRET` | 32 char | `openssl rand -base64 48` |
| `NEXTAUTH_SECRET` | 32 char | `openssl rand -base64 32` |
| `WAZUH_API_PASSWORD` | 16+ char | Complexity policy |
| `THEHIVE_API_KEY` | UUID-based | Generate from TheHive UI |

---

## 6. Audit and Logging

### 6.1 Structlog Configuration

All security events are logged in structured JSON format:

```python
logger.info("workspace.initialized", session_id=..., owner=...)
logger.warning("orchestrator.confirmation_required", tool=...)
logger.error("auth.failed", reason="invalid_internal_key", remote_ip=...)
```

### 6.2 Critical Log Events to Monitor

| Log Event | Meaning | Action |
|---|---|---|
| `auth.failed` | Invalid API key / JWT | Create alert |
| `workspace.quota_exceeded` | Disk quota exceeded | Review session |
| `path_traversal_attempt` | `../` attack | Block immediately + alert |
| `orchestrator.confirmation_required` | HITL triggered | Teams notification sent |
| `orchestrator.resume.approved` | Approval granted | Tool executing |
| `orchestrator.resume.rejected` | Rejected | Tool cancelled |

### 6.3 Log Retention

In production, logs should be shipped to Wazuh / Elasticsearch:

```env
AGENTIX_LOG_LEVEL=INFO     # DEBUG only in development
```

---

## 7. Threat Model

### STRIDE Analysis

| Threat | Component | Existing Control | Risk |
|---|---|---|---|
| **Spoofing** | Gateway → Core | `X-Internal-Api-Key` | 🟡 Medium (reduced with network isolation) |
| **Tampering** | Webhook payload | Path token + body hash | 🟡 Medium |
| **Repudiation** | Tool invocations | Structlog audit trail | 🟢 Low |
| **Info Disclosure** | SessionWorkspace | Path traversal block + quota | 🟢 Low |
| **Denial of Service** | Core API | Quota enforcement | 🟡 Medium (rate limiting can be added) |
| **Elevation of Privilege** | HITL bypass | `requires_confirmation` + draft_history | 🟢 Low |

### Known Risks and Recommendations

> [!CAUTION]
> **High Priority:** `AGENTIX_INTERNAL_API_KEY` provides only pre-shared key protection. It is recommended to strengthen it with mutual TLS (mTLS) in production.

> [!WARNING]
> **Medium Priority:** `draft_history` stored in Redis is not encrypted. In sensitive environments, Redis encryption-at-rest should be enabled or Redis Cluster ACLs should be used.

> [!NOTE]
> **Improvement:** Adding rate limiting (e.g., `slowapi`) to the API Gateway layer reduces DoS risk.

---

## 8. Production Hardening Checklist

### Required Steps

- [ ] All `dev-*` and `your-*` values in `.env` have been replaced with secure values
- [ ] `AGENTIX_INTERNAL_API_KEY` is at least 32-character random hex
- [ ] `AGENTIX_JWT_SECRET` is a strong random value
- [ ] `WAZUH_API_VERIFY_SSL=true` (for production Wazuh)
- [ ] All ports except Gateway are closed to external network
- [ ] Docker network configured with `internal: true`
- [ ] HTTPS enforced via TLS reverse proxy (nginx/Traefik)
- [ ] `GATEWAY_ALLOWED_ORIGINS` contains only production domains
- [ ] Log retention policy and Wazuh alerting rules are active

### Recommended Additional Security

- [ ] Redis AUTH password enabled (`requirepass <strong-password>`)
- [ ] Postgres user configured with minimum privileges
- [ ] `AGENTIX_SESSION_QUOTA_MB` adjusted per business requirements
- [ ] API rate limiting added (e.g., `slowapi`)
- [ ] Secrets rotation procedure documented
- [ ] Penetration test performed (at least annually)

---

## Related Documents

- [API Reference](./api-reference.md)
- [Testing Guide](../guides/6_testing-guide.md)
- [Deployment Guide](../guides/deployment-guide.md)
- [Attack Simulation Guide](../guides/7_attack-simulation.md)
