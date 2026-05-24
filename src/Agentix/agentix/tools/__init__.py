"""
Agentix tool implementations.
Tools are now powered by the FastMCP engine.
"""
from fastmcp import FastMCP

# The single FastMCP application instance — all tools register against this.
# Defined in __init__.py to ensure a single shared instance across the package.
mcp = FastMCP("Agentix Unified Environment")
