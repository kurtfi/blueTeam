#!/bin/bash
# setup_environment.sh

echo "============================================="
echo "   BlueTeam / Agentix SOC Environment Setup  "
echo "============================================="

# 1. Prerequisites check
for cmd in docker uv python3; do
    if ! command -v $cmd &> /dev/null; then
        echo "✗ Error: $cmd could not be found. Please install it."
        exit 1
    fi
done
echo "✓ All prerequisites (docker, uv, python3) found."

# 2. Dependencies
echo "→ Installing Python dependencies and Playwright browsers..."
uv sync
uv run playwright install chromium

# 3. Start Docker Compose
echo "→ Starting Docker Compose services (including Wazuh, TheHive, Cortex)..."
docker compose up -d

# 4. Health Checks
echo "→ Waiting for services to become ready (This may take a few minutes)..."

check_service() {
    local name=$1
    local url=$2
    local retries=3
    local wait_time=45
    
    echo "  Checking $name at $url"
    for ((i=1; i<=retries; i++)); do
        if curl -s -k -f "$url" > /dev/null; then
            echo "  ✓ $name is ready!"
            return 0
        else
            echo "  ~ $name not ready (Attempt $i/$retries). Waiting ${wait_time}s..."
            sleep $wait_time
        fi
    done
    echo "  ✗ $name failed to start after $retries attempts. Please check docker logs."
    exit 1
}

check_service_wazuh_api() {
    local retries=3
    local wait_time=45
    echo "  Checking Wazuh API at https://localhost:55000"
    for ((i=1; i<=retries; i++)); do
        result=$(curl -s -k -o /dev/null -w "%{http_code}" "https://localhost:55000")
        if [ "$result" = "401" ] || [ "$result" = "200" ]; then
            echo "  ✓ Wazuh API is ready!"
            return 0
        else
            echo "  ~ Wazuh API not ready (Attempt $i/$retries). Waiting ${wait_time}s..."
            sleep $wait_time
        fi
    done
    echo "  ✗ Wazuh API failed to start after $retries attempts. Please check docker logs."
    exit 1
}

# We check TheHive and Cortex API statuses
check_service "TheHive" "http://localhost:9000/api/status"
check_service "Cortex" "http://localhost:9001/api/status"

# Wazuh dashboard typically responds to /login
check_service "Wazuh Dashboard" "https://localhost:5601/login"
check_service_wazuh_api

# 5. Execute Setup Scripts
echo "→ Initializing Cortex Setup..."
uv run python scripts/cortex_browser_init.py
CORTEX_OUTPUT=$(uv run python scripts/cortex_browser_setup.py)
echo "$CORTEX_OUTPUT"
# Extract the API Key from the python script output
CORTEX_KEY=$(echo "$CORTEX_OUTPUT" | grep "Successfully generated API key:" | awk -F': ' '{print $2}' | tr -d '\r')

echo "→ Initializing TheHive Setup..."
THEHIVE_OUTPUT=$(uv run python scripts/init_thehive_v5.py)
echo "$THEHIVE_OUTPUT"
# Extract the API Key from the python script output
THEHIVE_KEY=$(echo "$THEHIVE_OUTPUT" | grep "API key generated successfully:" | awk -F': ' '{print $2}' | tr -d '\r')

# Pass TheHive API Key to the template setup script
export THEHIVE_API_KEY="$THEHIVE_KEY"
uv run python scripts/setup_thehive.py

# 6. Extract API Keys
# Keys are successfully captured from TheHive and Cortex outputs directly
if [ -z "$THEHIVE_KEY" ]; then THEHIVE_KEY="<Failed to extract>"; fi
if [ -z "$CORTEX_KEY" ]; then CORTEX_KEY="<Failed to extract>"; fi

# 7. Print Summary
echo ""
echo "================================================================="
echo "                  SOC ENVIRONMENT IS READY!                      "
echo "================================================================="
echo "The installation process is complete. Wazuh SIEM, TheHive,"
echo "and Cortex enrichment services have been successfully deployed."
echo ""
echo "--- ENVIRONMENT LINKS & CREDENTIALS ---"
echo ""
echo "1. WAZUH (SIEM & Dashboard)"
echo "   URL: https://localhost:5601"
echo "   API: https://localhost:55000"
echo "   User: wazuh-wui"
echo "   Pass: wazuh-wui"
echo ""
echo "2. THEHIVE (Case Management)"
echo "   URL: http://localhost:9000"
echo "   Admin User: admin@thehive.local / secret"
echo "   Analyst User: analyst@thehive.local / secret"
echo "   -> The Analyst API Key has been generated for Agentix use."
echo ""
echo "3. CORTEX (Enrichment & Analyzers)"
echo "   URL: http://localhost:9001"
echo "   Admin User: admin / secret"
echo "   Analyst User: agentix-analyst / Agentix-Lab-2025!"
echo "   -> The Analyst API Key has been generated for Agentix use."
echo ""
echo "--- API KEYS ---"
echo "The following API keys have been generated for the Analyst users."
echo "You must manually add these keys to your .env files."
echo ""
echo "   THEHIVE_API_KEY=$THEHIVE_KEY"
echo "   CORTEX_API_KEY=$CORTEX_KEY"
echo ""
echo "⚠️  IMPORTANT: Please manually create/update the following files with"
echo "    the keys above so that Agentix components can authenticate:"
echo "    - Infrastructure/.env"
echo "    - src/Agentix/.env"
echo ""
echo "--- HOW TO TEST ---"
echo "To test if the environment is working correctly, run a simulated attack:"
echo "   cd ../attack_simulations"
echo "   uv run python sim_t1003_008.py"
echo "================================================================="
