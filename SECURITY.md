# Security Policy

## Supported Versions

Only the latest version of the repository is actively supported and receives security updates.

| Version | Supported |
|---------|-----------|
| Main    | ✅ Yes     |
| < Main  | ❌ No      |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please do **NOT** open a public issue. Instead, report it privately.

Please send security reports to the maintainer via email at [firatkurt@example.com] (placeholder/actual contact email). In your report, please include:

1. A description of the vulnerability and its potential impact.
2. Steps to reproduce the issue (including any proof-of-concept scripts or configuration).
3. The version of the project and environment where the issue was observed.

You will receive an acknowledgment of your report within 48 hours, along with a planned timeline for addressing the issue.

## Note on Environment Security

This project involves autonomous security agents that can interact with real systems (e.g., through Docker and SOC tools like Wazuh, TheHive, and Cortex). Since agent workspaces execute commands and write files, you must run this project in a sandboxed environment (such as the provided Docker Compose setups) to prevent accidental damage to host systems. Always follow the principle of least privilege when configuring API credentials for integrations.
