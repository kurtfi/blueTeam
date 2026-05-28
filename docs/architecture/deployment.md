# System Deployment Guide

This document describes the topology of the system containers, their network configuration, port allocation, and how to spin up the local development environment.

---

## 1. Container Topology

The BlueTeam/Agentix system runs in a multi-container network. We partition containers into two primary Docker Compose deployments:
1. **Security Infrastructure** (`Infrastructure/docker-compose.yml`): Runs Wazuh SIEM, TheHive Case Management, and Cortex Enrichment.
2. **AI Agent Core** (`src/Agentix/docker-compose.yml`): Runs the Agentix Gateway, Agentix Orchestrator core, and the TriageCore FastMCP server.

```
       [Host Network]
             │
             ├── Port 8000 ────────> [ Agentix Gateway ] ─── (internal API)
             │                              │
             │                              ▼
             ├── Port 8080 ────────> [ TriageCore Server ] ── (FastMCP Engine)
             │                              │
             │                              ▼ (Integration Calls)
             ├── Port 55000 ───────> [ Wazuh Manager ]
             ├── Port 9000 ────────> [ TheHive Case Mgmt ]
             └── Port 9001 ────────> [ Cortex Enrichment ]
```

---

## 2. Port Mapping & Network Allocation

All containers belong to the bridge network `agentix_net` to allow resolved DNS communication (e.g. `TriageCore` reaching Wazuh by querying `http://wazuh-manager:55000`).

| Container Service | internal Port | External (Host) Port | Protocol | Description |
|:---|:---|:---|:---|:---|
| **agentix-gateway** | 8000 | `8000` | HTTP | Public API Endpoint for submitting investigations and managing agent workflows. |
| **soc-mcp-server** | 8080 | `8080` | SSE/HTTP | FastMCP server exposing SIEM, Case Management, and Enrichment tools. |
| **wazuh-manager** | 55000 / 1514 | `55000` / `1514` | HTTPS / UDP | Wazuh SIEM and Manager API. Port 1514 receives agent log streams. |
| **thehive** | 9000 | `9000` | HTTP | TheHive Case Management web console and API. |
| **cortex** | 9001 | `9001` | HTTP | Cortex analyzer/responder API interface. |
| **elasticsearch** | 9200 | `9200` | HTTPS | Storage backend database for Wazuh log indexes. |
| **cassandra** | 9042 | None | TCP | Database backend for TheHive. Not mapped to the host (isolated). |
| **redis** | 6379 | `6379` | TCP | Caching, session state history storage, and workspace lock queues. |

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
cd ../src/Agentix
docker compose up -d
```
This launches the FastMCP server, connects it to the security tools, and starts the API gateway.

---

## 4. Production Deployment Considerations

> [!WARNING]
> The default Docker Compose configs are tailored for **local development and testing**. If deploying to a production or staging environment:
> 1. **Change Default Credentials**: Change the default Wazuh credentials (`wazuh-wui:wazuh-wui`) and Elasticsearch admin keys in your `.env` file.
> 2. **Enable SSL/TLS**: Ensure the API Gateway uses HTTPS by configuring a reverse proxy (such as Nginx or Traefik) with valid Let's Encrypt certificates.
> 3. **Isolate Sandbox Workspace**: The `sessions/` workspace should be mounted on a partition with disk-quota limits configured, preventing a malfunctioning loops from exhausting the host's disk space.
