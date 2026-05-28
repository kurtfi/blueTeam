# Technical Glossary

This glossary defines technical terms, concepts, and acronyms used throughout the BlueTeam / Agentix codebase and documentation.

---

| Term | Definition |
|:---|:---|
| **ReAct** | **Reasoning and Acting**. An agentic interaction loop pattern where an LLM alternately produces reasoning traces (thoughts) and execution commands (actions), receives feedback (observations), and updates its plan dynamically. |
| **Model Context Protocol (MCP)** | An open-source protocol (created by Anthropic) that standardizes how LLM clients share data, read resources, and trigger tool calls with external microservices securely. |
| **Human-in-the-Loop (HITL)** | A security pattern where sensitive or destructive operations (e.g. altering firewall rules or container states) must be manually reviewed and approved by a human analyst before the system executes them. |
| **SIEM** | **Security Information and Event Management**. A security system that aggregates event log data from across host systems and network devices, analyzes it for security threats, and generates alerts. |
| **EDR** | **Endpoint Detection and Response**. Security software installed on hosts that monitors endpoint events (process execution, file modifications) and provides automated threat isolation. |
| **SOAR** | **Security Orchestration, Automation, and Response**. Platforms that integrate disparate security tools and automate incident response workflows (playbooks). |
| **Wazuh** | An open-source security monitoring platform combining SIEM, vulnerability detection, and EDR capabilities. |
| **TheHive** | An open-source, scalable Security Incident Response Platform (SIRP) and case management tool tightly integrated with Cortex. |
| **Cortex** | An open-source enrichment and response engine that performs automated analysis (e.g. querying VirusTotal or AbuseIPDB) on indicators of compromise. |
| **IOC** | **Indicator of Compromise**. Forensic evidence (e.g. suspicious file hashes, malicious IP addresses, domain names) indicating a potential system compromise. |
| **Sandbox Workspace** | An isolated directory assigned to an active agent session, strictly guarded against path traversal, serving as the sole valid storage for files created by tools during investigations. |
| **FastMCP** | A lightweight Python framework used to quickly scaffold and run Model Context Protocol (MCP) servers with minimal boilerplate. |
| **Ruff** | An extremely fast Python linter and code formatter written in Rust. |
| **Mypy** | An optional static type checker for Python, used to check type hint correctness across modules. |
| **Langfuse** | An open-source LLM engineering platform providing telemetry, tracing, cost metrics, and quality evaluations for agent workflows. |
| **Draft Logs** | Unsaved/temporary execution logs cached to state databases when an agent halts at a Human-in-the-Loop gate, allowing sessions to resume seamlessly once approved. |
