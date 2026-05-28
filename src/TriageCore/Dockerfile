FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1

# Copy only TriageCore files from context
COPY src/TriageCore/pyproject.toml ./
COPY src/TriageCore/triage_core ./triage_core

# Sync dependencies standalone
RUN uv sync

EXPOSE 8081

CMD ["uv", "run", "python", "-m", "triage_core.main"]
