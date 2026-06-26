# Attack Simulation & Validation Guide

This guide describes the **Attack Simulator** module, its integration with the Agentix Gateway and TriageCore, and how to verify detection and response coverage.

---

## 🔍 Overview

The **Attack Simulator** is a MITRE ATT&CK attack simulation framework built to test and validate Agentix's autonomous incident response playbooks. It simulates attacker techniques (e.g., credential dumping, lateral movement, data exfiltration) by generating wazuh SIEM alerts and forwarding them to the core agentic triage pipeline.

---

## ⚙️ Key Capabilities

The simulator dashboard includes three main panels:
1. **Scenarios List**: Choose single or bulk MITRE ATT&CK scenarios to execute.
2. **Run History & Audit**: Monitor previous execution runs, playbook matching rates, and detailed verdicts.
3. **Bulk Simulations**: Run large-scale, automated scenario flows to generate coverage gap reports.

---

## 🚀 Recent Simulation Enhancements

To improve user experience, analysis depth, and data cleanliness, the following enhancements have been implemented:

### 1. Session-Level Audit Grouping

Previously, the **Run Results Audit Sequence** table displayed a flat list of every individual alert event. For multi-step scenarios, this caused excessive clutter and duplicate session records.

* **Improvement**: Events are now grouped on the client side by their unique `session_id`.
* **Behavior**: Each unique session occupies exactly one row in the table, clearly showing:
  * **Session ID** (linked to the corresponding Agentix session)
  * **Expected Playbooks** (the sequence of playbooks configured for the scenario steps)
  * **Actual Playbook** (the playbook triggered by the agent)
  * **Verdict** (`TRUE_POSITIVE` if mitigated, `FALSE_POSITIVE`, or `UNDETERMINED`)
  * **Actions** (interactive control to view individual events)

### 2. Interactive Session Events Modal

To inspect the raw alerts and step execution details for a specific session without cluttering the main dashboard, an interactive modal was introduced:

* **Trigger**: Clicking the **View Events (<count>)** button in the actions column of a session row opens the modal.
* **Modal Details**: A glassmorphic, animated overlay (`#events-modal`) displaying the complete sequence of events:
  * **Sequence Number**: Execution order in the scenario DAG.
  * **MITRE Technique**: The technique code (e.g., `T1003.008`) and description.
  * **Execution Response Time**: Time taken for the simulation webhook to respond.
  * **Timestamp**: Exact alert trigger time.
* **Dismissal**: Easily closed by clicking the close button or clicking anywhere outside the modal boundary.

### 3. Agent Type Filtering on Sessions Screen

To allow analysts to isolate alert logs by specific agent personas, a new agent filter has been added to the main Sessions List view in the Gateway:

* **UI Element**: A `#filter-agent` dropdown select box in the filter bar.
* **Options**:
  * **All Agents**: Default view (shows all active and completed sessions).
  * **SOC Analyst**: Filters sessions handled by the `soc_analyst` agent configuration.
  * **Simulation Analyst**: Filters sessions handled by the `simulation_analyst` agent configuration.
* **Database Optimization**: Runs as a server-side filter (`agent_name` column condition on the `sessions` table) to maintain fast pagination.

### 4. Bulk Scenario Selection & Category Filtering

To improve usability when running large-scale simulation tests:
* **Height Adjustment**: The **Select Scenarios** list selection area height was more than doubled (changed from a dynamic `min-height: 350px` to a fixed `height: 800px`) so that analysts can see and select multiple scenario options at once without scrolling excessively.
* **Category Filtering**: A new **Scenario Category** dropdown filter was added directly above the selection list (`#bulk-category-select`). Selecting a category (e.g., *Discovery*, *Credential Access*, *Lateral Movement*, *Execution*, *Exfiltration*) dynamically filters the scenario list using client-side category matching.

### 5. Database Mock Runs Cleanup

To keep the database clean from garbage/mock records generated during automated test suites (e.g., `pytest` runs), a cleanup procedure was executed:

* **Target**: Removed all records from `simulator.simulation_runs` where `scenario_id` was `NULL`.
* **Cascade Deletes**: Linked tables (`simulator.simulation_results`) utilize foreign keys with `ON DELETE CASCADE`, meaning telemetry results associated with these mock runs were cleaned up automatically.
* **Script Location**: A python script is located in `scratch/cleanup_db.py` to run database purging when needed.

---

## 🧪 Verification & Troubleshooting

### Check Endpoint Filtering
You can query the gateway sessions endpoint directly to verify the agent name filter:
```bash
# Get sessions handled only by the SOC Analyst agent
curl -X GET "http://localhost:8001/web/sessions?agent_name=soc_analyst&limit=20&offset=0" \
  -H "Authorization: Bearer <jwt-token>"
```

### Force Browser Refresh
If you do not see the **Agent** dropdown filter or the **View Events** action button, clear your browser cache (Cmd+Shift+R / Ctrl+F5) to force the browser to reload the updated `app.js` and `index.html` static resources.
