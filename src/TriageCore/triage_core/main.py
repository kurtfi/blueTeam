"""
FastMCP Server Entry Point for TriageCore.
"""

import importlib
import os

import structlog

from triage_core.tools import mcp

logger = structlog.get_logger(__name__)

# SOC tools module to import
_TOOL_MODULES: list[tuple[str, str]] = [
    ("triage_core.tools.soc_tools", "SOC Tools"),
]

_loaded: list[str] = []
_skipped: list[str] = []

for _module_path, _tool_name in _TOOL_MODULES:
    try:
        importlib.import_module(_module_path)
        _loaded.append(_tool_name)
        logger.debug("tool_module_loaded", module=_module_path)
    except ImportError as e:
        _skipped.append(_tool_name)
        logger.warning(
            "tool_module_skipped",
            module=_module_path,
            tool=_tool_name,
            reason=str(e),
        )
    except Exception as e:
        _skipped.append(_tool_name)
        logger.error(
            "tool_module_failed",
            module=_module_path,
            tool=_tool_name,
            error=str(e),
        )

logger.info(
    "mcp_server.ready",
    server="TriageCore",
    loaded=len(_loaded),
    skipped=len(_skipped),
    tools=_loaded,
    unavailable=_skipped,
)

if __name__ == "__main__":
    transport = os.getenv("FASTMCP_TRANSPORT", "sse")
    port = int(os.getenv("FASTMCP_PORT", "8081"))

    from typing import Literal, cast

    transport_type = cast(Literal["stdio", "sse", "http", "streamable-http"], transport)

    logger.info("mcp_server.starting", server="TriageCore", transport=transport, port=port)
    if transport_type == "sse":
        mcp.run(transport=transport_type, port=port, host="0.0.0.0")  # type: ignore[call-arg]
    else:
        mcp.run(transport=transport_type)  # type: ignore[call-arg]
