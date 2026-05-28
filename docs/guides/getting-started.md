# Getting Started Guide

This guide walks you through setting up the BlueTeam/Agentix environment on your local machine, provisioning your first security containers, and running test investigations.

---

## 📋 Prerequisites

Ensure your system meets the following version requirements before starting:

| Dependency | Minimum Version | Verified Version | Purpose |
|:---|:---|:---|:---|
| **Python** | `3.12` | `3.12.3` | Core orchestration runtime |
| **uv** | `0.1.0` | `0.1.4` | Project dependency manager |
| **Docker Engine** | `20.10+` | `26.1.4` | Multi-container support |
| **Docker Compose** | `V2` | `2.27.1` | Orchestrating containers |

---

## 🛠️ Step-by-Step Installation

### Step 1: Clone and Set Up Workspace
First, clone the repository and navigate into the root directory:
```bash
git clone https://github.com/firatkurt/blueTeam.git
cd blueTeam
```

Install packages and development tools using `uv`:
```bash
uv sync --all-extras --dev
```

### Step 2: Configure Environment Variables
Copy the configuration template:
```bash
cp .env.example .env
```
Open the `.env` file in your text editor. Add your LLM keys (such as `OPENAI_API_KEY` or `GEMINI_API_KEY`). If you plan to run models locally, verify Ollama is running and download your preferred model:
```bash
ollama run gemma:2b
```

### Step 3: Run the Security Stack
Spin up the Docker services for Wazuh SIEM, TheHive, and Cortex:
```bash
cd src/Infrastructure
docker compose up -d
```
Verify the services are running correctly:
```bash
docker compose ps
```

### Step 4: Run the Agentix API and MCP Services
Open a new terminal session, navigate back to the root, and execute the run script:
```bash
cd src/Agentix
uv run uvicorn agentix.api.app:app --host 0.0.0.0 --port 8000 --reload
```
You should see:
```
INFO:     Started server process [83921]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

---

## 🧪 Verifying the Deployment

Run a cURL request to verify the agent can analyze Wazuh logs and query Cortex:

```bash
curl -X POST http://localhost:8000/api/v1/investigate \
  -H "Authorization: Bearer dev-internal-key-change-me-in-production" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "soc_analyst",
    "prompt": "Identify any alert with severity level higher than 5 in Wazuh and analyze its source IP using Cortex."
  }'
```

### Expected Output Format
The API should reply with an HTTP 200 containing a markdown summary:
```json
{
  "session_id": "8b9f71c-4b53-488f-9a71-bf17bde91c1b",
  "status": "COMPLETED",
  "response": "### Incident Investigation Summary\n\n1. **Alert Detected**: Found Wazuh alert with ID `1716892301.2831` (Severity level: 7) - Multiple SSH login failures.\n2. **IP Analysis**: Enriched IP address `203.0.113.50` using Cortex VirusTotal analyzer.\n   - **Reputation**: 12/90 security vendors marked this IP as malicious.\n3. **Recommendation**: Initiate a firewall block rule on the source IP and notify the system administrator."
}
```

---

## ❓ Troubleshooting Common Issues

### 1. `uv` commands fail or cannot find Python 3.12
- **Cause**: Python 3.12 is not installed or not registered in your PATH.
- **Solution**: Install Python 3.12 (e.g. using `brew install python@3.12` on macOS, or download from official python site) and tell `uv` to use it:
  ```bash
  uv python pin 3.12
  ```

### 2. Wazuh containers exit immediately or throw disk errors
- **Cause**: Elasticsearch requires a higher virtual memory allocation.
- **Solution**: Run the following command on your host shell (Linux/macOS WSL):
  ```bash
  sudo sysctl -w vm.max_map_count=262144
  ```

### 3. API requests return `401 Unauthorized`
- **Cause**: The `Authorization` header token does not match the configured `AGENTIX_INTERNAL_API_KEY` env variable.
- **Solution**: Check your `.env` file at the root. Make sure the value matches the one sent in the Bearer token header.
