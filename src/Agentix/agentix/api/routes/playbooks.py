import json

import structlog
from fastapi import APIRouter, Depends, HTTPException, Path, Request

from agentix.api.dependencies import get_catalog
from agentix.registry.catalog import ToolCatalog

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.get("/playbooks")
async def get_cached_playbooks(catalog: ToolCatalog = Depends(get_catalog)) -> dict[str, str]:
    """
    Return the cached playbooks markdown text from TriageCore.
    """
    return {"playbooks_markdown": getattr(catalog, "cached_playbooks", "")}


@router.get("/playbooks/summary")
async def get_cached_playbooks_json(catalog: ToolCatalog = Depends(get_catalog)):
    """
    Return the cached playbooks JSON summary from TriageCore.
    """
    data = getattr(catalog, "cached_playbooks_json", [])
    if isinstance(data, str):
        try:
            return json.loads(data)
        except Exception:
            return []
    return data or []


@router.get("/playbooks/{playbook_id}")
async def get_playbook_details(request: Request, playbook_id: str = Path(..., max_length=255)):
    """
    Call the TriageCore MCP tool 'get_playbook_details' and return the result.
    """
    session = getattr(request.app.state, "triage_core_session", None)
    if not session:
        raise HTTPException(status_code=503, detail="TriageCore MCP session is not connected.")
    try:
        result = await session.call_tool("get_playbook_details", {"playbook_id": playbook_id})
        from agentix.tools.mcp_adapter import MCPToolAdapter

        parsed_result = MCPToolAdapter._parse_result(result)

        if isinstance(parsed_result, dict):
            return parsed_result
        try:
            return json.loads(parsed_result)
        except Exception:
            if isinstance(parsed_result, str) and "not found" in parsed_result.lower():
                raise HTTPException(status_code=404, detail=parsed_result)
            return {"detail": parsed_result}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("api.get_playbook_details_failed", playbook_id=playbook_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))
