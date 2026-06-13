FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

# Set the working directory
WORKDIR /app

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1

# Copy workspace setup files
COPY pyproject.toml uv.lock ./

# Copy all workspace sources
COPY src/ src/

# Sync workspace dependencies
RUN uv sync --frozen --no-install-project

# Sync full workspace
RUN uv sync --frozen

# Expose the AttackSimulator MCP port
EXPOSE 8082

# Run the AttackSimulator MCP SSE server by default
CMD ["uv", "run", "python", "-m", "attack_simulator.mcp_server"]
