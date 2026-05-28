# SOC Infrastructure Environment

This directory contains the necessary configurations and scripts to quickly spin up a complete Security Operations Center (SOC) stack locally using Docker. The environment is pre-configured and automated to seamlessly integrate with **Agentix**.

## What is Installed?

When you set up this environment, the following core components are automatically deployed and configured:

1. **Wazuh (SIEM & EDR)**
   - **Wazuh Manager**: Collects logs and events.
   - **Wazuh Indexer**: Stores indexed data.
   - **Wazuh Dashboard**: The web UI for exploring logs and alerts.
2. **TheHive (Incident Response Platform)**
   - A case management system where security alerts are promoted into actionable cases.
   - Pre-loaded with custom MITRE ATT&CK case templates.
3. **Cortex (Enrichment Engine)**
   - An observable analysis and active response engine.
   - Used by TheHive (and Agentix) to analyze IP addresses, hashes, and domains.
4. **Backend Databases**
   - **Cassandra** (for TheHive data)
   - **Elasticsearch** (for TheHive indexing and Cortex storage)

## How to Install

The entire installation and initial configuration process is completely automated.

1. Navigate to this `Infrastructure` directory:
   ```bash
   cd Infrastructure
   ```

2. Run the setup script:
   ```bash
   ./setup_environment.sh
   ```

3. **What the script does automatically:**
   - Clears out old data if requested and downloads necessary Docker images.
   - Starts all containers via `docker-compose.yml`.
   - Waits for all services to become healthy.
   - Automates the first-time database setup for Cortex via UI interactions.
   - Creates necessary default users, organizations (`agentix-lab`), and generates API Keys for both Cortex and TheHive.
   
At the end of the script, it will print out the **API Keys**. Make sure to copy these and place them in your `.env` files `src/Agentix/.env` so that other tools can authenticate.

## Configuring Cortex Analyzers (VirusTotal, AbuseIPDB)

By default, Cortex needs third-party API keys to actually perform threat intelligence lookups (e.g., checking if an IP is malicious).

To allow Agentix and TheHive to search using **VirusTotal** or **AbuseIPDB**, you must manually configure these keys inside the Cortex UI.

### Steps to Configure:

1. **Log into Cortex:**
   - Go to: `http://localhost:9001`
   - Use the **Analyst** credentials created by the script:
     - **Username**: `agentix-analyst`
     - **Password**: `Agentix-Lab-2025!`
     *(If you need administrative access to the platform itself, you can use `admin` / `secret`)*

2. **Navigate to Organization Analyzers:**
   - At the top menu, click on **Organization** (which should be `agentix-lab`).
   - Click on the **Analyzers** tab.

3. **Enable and Configure Analyzers:**
   - Search for **AbuseIPDB**.
   - Click **Enable**.
   - A configuration modal will pop up. Enter your personal `key` (API Key) for AbuseIPDB and save.
   - Next, search for **VirusTotal**.
   - Click **Enable**.
   - Enter your personal `key` for VirusTotal and save.

Once these analyzers are enabled and configured with valid API keys, Cortex will successfully enrich observables (IPs, Hashes) requested by Agentix or TheHive.
