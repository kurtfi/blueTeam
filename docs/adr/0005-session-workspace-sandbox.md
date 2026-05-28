# Session Workspace Sandboxing

* Status: accepted
* Deciders: Architect, Lead Security Engineer
* Date: 2026-05-28

## Context and Problem Statement

When AI agents run investigation playbooks, they frequently need to read and write files (e.g. parsing PCAP files, writing temporary firewall rules, extracting artifacts from system logs). If tools allow reading or writing files anywhere on the file system, a malicious prompt injection or an LLM hallucination could result in:
1. Deleting system files.
2. Exfiltrating sensitive host configuration (e.g. `/etc/passwd` or SSH keys).
3. Modifying other agent sessions (cross-tenant contamination).

We need to enforce strict path-level sandboxing for all file operations performed by agent sessions.

## Decision Drivers

* **Isolation**: Prevent agents from reading or writing files outside their assigned session boundary.
* **Path Traversal Protection**: Defend against path manipulation tricks (e.g., `../../etc/shadow`).
* **Cleanliness**: Automatically clean up or organize session artifacts.

## Considered Options

1. **System-wide Access**: Run all agent actions with standard OS file privileges (no sandbox).
2. **Session Workspace Sandboxing**: Initialize a unique, isolated directory for each session. Enforce a utility class (`SessionWorkspace`) that validates all file paths against the session root directory before performing any disk operations.

## Decision Outcome

Chosen option: **Option 2 (Session Workspace Sandboxing)**. We implement `SessionWorkspace` under `src/AgenticCommon`. Every time a session starts, it creates a folder under `sessions/<session_id>/`. Any tool that performs disk I/O must resolve paths through this workspace. If a tool attempts to resolve a path that escapes the workspace boundary (e.g. via parent traversal), a `ValueError` is immediately thrown, halting tool execution.

### Positive Consequences

* **Security**: Enforces strict directory containment, neutralizing path traversal attacks and preventing agents from viewing host secrets.
* **Session Cleanliness**: Files related to a specific alert or ticket are grouped in a single folder, which can be zipped, archived, or deleted easily.

### Negative Consequences

* **Developer Overhead**: Tool writers must consciously use the session workspace abstraction instead of opening paths directly using standard Python libraries (like `open()` or `pathlib.Path`).
* **Limited Scope**: This sandboxing is only path-level, not OS-level. Process-level isolation (e.g. restricting network access or system commands) must be separately handled via Docker containers.
