# System Deployment Guide

This document describes the topology of the system containers, their network configuration, port allocation, and how to spin up the local development environment.

---

## 1. Container Topology

The BlueTeam/Agentix system runs in a multi-container network. We partition containers into two primary Docker Compose deployments:
1. **Security Infrastructure** (`Infrastructure/docker-compose.yml`): Runs Wazuh SIEM, TheHive Case Management, and Cortex Enrichment.
2. **AI Agent Core** (`src/docker-compose.yml`): Runs the Agentix Gateway, Agentix Core API, TriageCore FastMCP server, Redis, Postgres, and Langfuse.

```
       [Host Network]
             │
             ├── Port 8001 ────────> [ Agentix Gateway    ]  (public REST + JWT)
             │                              │ X-Internal-Api-Key
             │                              ▼
             │                       [ Agentix Core API   ]  (port 8000, internal only)
             │                              │ FastMCP / SSE
             │                              ▼
             ├── Port 8081 ────────> [ TriageCore Server  ]  (FastMCP Engine)
             │                              │ (Integration Calls)
             ├── Port 55000 ───────> [ Wazuh Manager      ]
             ├── Port 9000 ────────> [ TheHive Case Mgmt  ]
             └── Port 9001 ────────> [ Cortex Enrichment  ]
```

---

## 2. Port Mapping & Network Allocation

All containers belong to the bridge network `agentix_net` to allow resolved DNS communication (e.g. `TriageCore` reaching Wazuh by querying `http://wazuh-manager:55000`).

| Container Service | Internal Port | External (Host) Port | Protocol | Description |
|:---|:---|:---|:---|:---|
| **agentix-gateway** | 8001 | `8001` | HTTP | Public REST API — JWT auth, CORS, IDOR protection. |
| **agentix-api** | 8000 | *(internal only)* | HTTP | Core ReAct engine — not exposed to host directly. |
| **triage-core** | 8081 | `8081` | SSE/HTTP | FastMCP server exposing SIEM, Case Management, and Enrichment tools. |
| **postgres** | 5432 | `25432` | TCP | pgvector database for agent config and embeddings (`agentix_db`). |
| **redis** | 6379 | `26379` | TCP | Session state, conversation history, draft_history. |
| **langfuse** | 3000 | `3010` | HTTP | LLM observability dashboard. |
| **wazuh-manager** | 55000 / 1514 | `55000` / `1514` | HTTPS / UDP | Wazuh SIEM and Manager API. Port 1514 receives agent log streams. |
| **thehive** | 9000 | `9000` | HTTP | TheHive Case Management web console and API. |
| **cortex** | 9001 | `9001` | HTTP | Cortex analyzer/responder API interface. |
| **elasticsearch** | 9200 | `9200` | HTTPS | Storage backend for Wazuh log indexes. |
| **cassandra** | 9042 | *(internal only)* | TCP | Database backend for TheHive. Not exposed to host. |

---

## 3. Order of Deployment

To ensure services initialize correctly without timeout errors, run the compose scripts in the following order:

### 1. Launch Security Infrastructure
The databases (Elasticsearch, Cassandra) and security services take longer to run initialization migrations.
```bash
cd Infrastructure
docker compose up -d
```
You can monitor progress using:
```bash
docker compose ps
# Verify Wazuh manager API is up:
curl -k -u wazuh-wui:wazuh-wui https://localhost:55000/
```

### 2. Launch Agentix & MCP Services
Once Wazuh, TheHive, and Cortex are healthy, spin up the AI orchestration layer:
```bash
cd ../src
docker compose up -d
```
This launches TriageCore (FastMCP), the Core API, the Gateway, Redis, Postgres, and Langfuse.

---

## 4. Production Deployment Considerations

> [!WARNING]
> The default Docker Compose configs are tailored for **local development and testing**. If deploying to a production or staging environment:
> 1. **Change Default Credentials**: Change the default Wazuh credentials (`wazuh-wui:wazuh-wui`) and Elasticsearch admin keys in your `.env` file.
> 2. **Enable SSL/TLS**: Ensure the API Gateway uses HTTPS by configuring a reverse proxy (such as Nginx or Traefik) with valid Let's Encrypt certificates.
> 3. **Isolate Sandbox Workspace**: The `sessions/` workspace should be mounted on a partition with disk-quota limits configured, preventing a malfunctioning loops from exhausting the host's disk space.
