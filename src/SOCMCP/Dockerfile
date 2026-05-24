FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1

# Copy only SOCMCP files from context
COPY src/SOCMCP/pyproject.toml ./
COPY src/SOCMCP/soc_mcp ./soc_mcp

# Sync dependencies standalone
RUN uv sync

EXPOSE 8081

CMD ["uv", "run", "python", "-m", "soc_mcp.main"]
