# Adding a New Agent Persona

The platform utilizes a persona-based configuration system. Each agent (such as a firewall operator, log analyst, or threat intelligence specialist) is defined by a YAML configuration file. The orchestrator and router load these definitions dynamically.

---

## 1. Persona Configuration Structure

All agent persona files are located in:
`src/Agentix/agentix/agents/configs/`

Here is an example structure of a persona file (`firewall_operator.yaml`):

```yaml
agent_id: "firewall_operator"
name: "Firewall Operator Agent"
description: "Specialist in analyzing network rules, analyzing traffic flow, and configuring gateway firewall blocklists."

system_prompt: |
  You are an expert security engineer specializing in network firewalls and containment.
  Your job is to review network access alerts, investigate source/destination IP addresses, and configure block rules to contain threats.
  Always explain which network interface you are modifying and the duration of block rules.
  For all block operations, you MUST output a tool call to 'block_gateway_ip'.
  Be brief and structured in your explanations.

# List of tools this agent is permitted to run
allowed_tools:
  - "list_firewall_rules"
  - "block_gateway_ip"
  - "unblock_gateway_ip"
  - "query_cortex_ip"
  - "read_session_file"
```

---

## 2. Setting Up the Agent Persona

Follow these steps to write and register a new agent:

### Step 1: Create the Config File
Create a new file under `src/Agentix/agentix/agents/configs/threat_hunter.yaml`:
```bash
touch src/Agentix/agentix/agents/configs/threat_hunter.yaml
```
Write the persona details, specifying their unique role, prompt instructions, and tools:
```yaml
agent_id: "threat_hunter"
name: "Advanced Threat Hunter"
description: "Performs proactive threat hunt queries across Wazuh alerts and performs host audits."
system_prompt: |
  You are a senior threat hunter. Your objective is to hunt for indicators of compromise (IOCs) across endpoints.
  Analyze logs for anomalous patterns such as credential dumping, process hollowing, or suspicious network beacons.
allowed_tools:
  - "query_wazuh_alerts"
  - "fetch_agent_syslogs"
  - "query_misp_threat_intel"
```

### Step 2: Intent Router Discovery
You do not need to register the agent in code! The `AgentRouter` class (located in `src/Agentix/agentix/agents/router.py`) automatically walks the configs folder on startup:

```python
# The router scans the configs directory dynamically
class AgentRouter:
    def __init__(self, configs_dir: Path):
        self.personas = self.load_all_configs(configs_dir)
```

The router will read `threat_hunter.yaml`, parse its description, and include it in the LLM intent classification schemas. When a user sends a prompt like:
*"Hunt for suspicious logon activity on server-01"*
The router will dynamically route the request to the `threat_hunter` agent.

---

## 3. Testing Your Agent Persona

You can test that your new persona is successfully loaded and routed by executing the test routing script:

```bash
cd src/Agentix
uv run python scripts/test_yaml_agent.py --prompt "Hunt for credential dumping patterns on host-3"
```
Verify the output log showing:
`Routed prompt to agent: threat_hunter`
