# Agentix Tool Testing Guide

This document provides example prompts to test the Agentix tools using the local Docker environment and the data seeded by `seeds.py`.

## 🗄️ Relational Databases (SQL)
Tests the `query_sql` tool.

### PostgreSQL
- **Scenario**: Retrieve all registered users.
- **Prompt**: "List all users from the default database."
- **Expected**: Alice, Bob, and Charlie from the `users` table.

### MySQL
- **Scenario**: Find products by price.
- **Prompt**: "Show me all products in the 'mysql' database that cost more than 50 dollars."
- **Expected**: The High-end Laptop and Smartphone Ultra from the `products` table.

---

## 📄 NoSQL Databases
Tests the specific NoSQL connectors.

### MongoDB
- **Scenario**: Search system logs.
- **Prompt**: "Find all logs in MongoDB with a 'WARNING' level."
- **Expected**: The 'High disk usage' log.

### Elasticsearch
- **Scenario**: Perform semantic-ish search on articles.
- **Prompt**: "Search for articles about 'FastMCP' in Elasticsearch."
- **Expected**: The 'FastMCP Explained' article.

### Neo4j (Graph)
- **Scenario**: Traverse relationships.
- **Prompt**: "Who does Alice follow in the Neo4j graph?"
- **Expected**: Bob.

---

## ✉️ Actions & Messaging
Tests the `MailService` and `MessagingBridge`.

### Email (via MailHog)
- **Scenario**: Send a notification email.
- **Prompt**: "Send an email to user@test.com with the subject 'Hello' and body 'This is a test notification from Agentix'."
- **Verification**: Check http://localhost:8025 to see the captured email.

### SMS / WhatsApp
- **Scenario**: Send a message via Twilio (requires credentials, but can be mocked).
- **Prompt**: "Send a WhatsApp message to +123456789 saying 'Your report is ready'."

---

## 🌐 Web & Data Parsing
Tests `Crawler` and `Parser`.

### Crawler (Crawl4AI)
- **Scenario**: Extract text from a website.
- **Prompt**: "Crawl the website 'https://example.com' and tell me the main heading."

### Docling Parser
- **Scenario**: Parse a document from a local path.
- **Prompt**: "Parse the document at 'src/Agentix/README.md' and provide a summary."

---

## 🧠 Memory & System
Tests `PreferenceManager`, `SessionTracker`, and `FileManager`.

### Shared Memory (Redis)
- **Scenario**: Check system health status stored in Redis.
- **Prompt**: "What is the current 'system_status' value in Redis?"
- **Expected**: 'healthy'.

### Local Files
- **Scenario**: Inspect the project structure.
- **Prompt**: "List the files in the 'src/Agentix/agentix/tools' directory."

---

## 🛡️ Secure Dynamic Connections (NEW)
Agentix supports connecting to any database *without* exposing credentials in the chat. This is done by setting environment variables following the pattern `AGENTIX_DB_{TYPE}_{ALIAS}`.

### How to use:
1.  **Set the environment variable** in your terminal:
    ```bash
    export AGENTIX_DB_SQL_EXTERNAL="mysql+aiomysql://agentix:password@localhost:3306/agentix_db"
    ```
2.  **Use the alias** in your prompt:
    "Query the `external` database and list all products."

### Test Scenarios:
- **Scenario**: Query a database defined via environment variable.
- **Requirement**: Run `export AGENTIX_DB_SQL_MYPROD="postgresql+asyncpg://agentix:password@localhost:25432/agentix_db"`.
- **Prompt**: "List all users from the `myprod` database."
- **Verification**: The tool should resolve `myprod` to the DSN set in the environment variable.

---

## 🚀 Combined (Orchestration)
Tests the Agent's ability to chain tools and handle dynamic data.

- **Scenario**: Multi-step data retrieval and notification.
- **Prompt**: "Get the email address of Alice from the PostgreSQL 'users' table and then send her a notification saying 'Welcome to the system'."
- **Flow**: `query_sql` -> `send_email`.

---

## 🛠️ Diagnostics
If you suspect a connection issue, run the following command in the terminal to verify the environment health:
```bash
export PYTHONPATH=$PYTHONPATH:. && python3 tests/test_connect.py
```
