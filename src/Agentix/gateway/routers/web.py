# ruff: noqa: E501
import json
from collections.abc import AsyncGenerator
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from gateway.security.auth import auth_store, create_access_token, get_current_user, verify_password
from gateway.services.agentix_client import create_session, stream_chat, verify_session_owner

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/web", tags=["Web API"])

class LoginRequest(BaseModel):
    username: str
    password: str

class ChatRequest(BaseModel):
    message: str
    session_id: str | None = None
    agent: str | None = None

class ChatResponse(BaseModel):
    session_id: str

@router.post("/login", summary="Log in to receive an access token")
async def login(req: LoginRequest, response: Response) -> dict[str, str]:
    """
    Authenticate against the Postgres user store, generate a JWT,
    and set it as an HttpOnly, Secure, SameSite cookie.
    """
    user = await auth_store.get_user_by_username(req.username)
    if not user or not verify_password(user["password_hash"], req.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Parse permissions safely
    permissions = user.get("permissions") or []
    if isinstance(permissions, str):
        try:
            permissions = json.loads(permissions)
        except Exception:
            permissions = []

    # Generate JWT
    token = create_access_token(data={
        "uid": user["username"],
        "email": user["email"],
        "role": user["role"],
        "permissions": permissions,
    })

    # Set HttpOnly cookie
    response.set_cookie(
        key="agentix_access_token",
        value=token,
        httponly=True,
        max_age=1440 * 60,  # 24 hours
        samesite="lax",
        secure=False,  # Set to True in production with HTTPS
        path="/",
    )

    return {"status": "success", "message": "Logged in successfully"}


@router.post("/logout", summary="Log out and clear the session cookie")
async def logout(response: Response) -> dict[str, str]:
    """Clear the authentication cookie."""
    response.delete_cookie(key="agentix_access_token", path="/")
    return {"status": "success", "message": "Logged out successfully"}


@router.post("/chat", summary="Start or continue a chat session")
async def web_chat(
    req: ChatRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> StreamingResponse:
    """
    Proxy endpoint: forwards the chat message to the Agentix API core and
    streams the SSE response back to the browser client.
    """
    user_id = str(current_user.get("uid", ""))

    # 1. Establish or validate session
    session_id = req.session_id
    if not session_id:
        try:
            session_id = await create_session(user_id)
        except Exception:
            raise HTTPException(status_code=500, detail="Could not initialize session")
    else:
        # SECURITY: Verify session ownership to prevent IDOR attacks.
        is_owner = await verify_session_owner(session_id, user_id)
        if not is_owner:
            logger.warning(
                "gateway.web.idor_blocked",
                uid=user_id,
                session_id=session_id,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have access to this session.",
            )

    # 2. Proxy SSE stream from the Agentix API core
    async def event_generator() -> AsyncGenerator[str, None]:
        # Announce the session ID to the client first
        yield f"data: {json.dumps({'type': 'session', 'session_id': session_id})}\n\n"
        try:
            async for step in stream_chat(session_id, req.message, req.agent):
                yield f"data: {json.dumps(step)}\n\n"
            yield "data: [DONE]\n\n"
        except Exception as e:
            logger.error("gateway.routers.web.stream_failed", error=str(e))
            yield f"data: {json.dumps({'error': 'Streaming failed'})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/me", summary="Get current authenticated user info")
async def get_me(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    return {
        "uid": current_user.get("uid"),
        "role": current_user.get("role"),
        "email": current_user.get("email"),
    }


@router.get("/agents", summary="List all available agent personas")
async def list_agents(
    current_user: dict[str, Any] = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """Load agent configurations from YAML files."""
    from pathlib import Path

    import yaml  # type: ignore[import-untyped]

    # web.py lives at gateway/routers/web.py → parents[2] = src/Agentix/
    configs_dir = Path(__file__).parents[2] / "agentix" / "agents" / "configs"
    agents: list[dict[str, Any]] = []

    if configs_dir.exists():
        for f in configs_dir.glob("*.yaml"):
            try:
                with open(f, encoding="utf-8") as stream:
                    config = yaml.safe_load(stream)
                    agents.append({
                        "id": f.stem,
                        "name": config.get("name"),
                        "role": config.get("role"),
                        "tools": config.get("tool_filters", {}).get("names", []),
                        "model": config.get("llm", {}).get("model", ""),
                        "temperature": config.get("llm", {}).get("temperature", 0.0),
                    })
            except Exception as e:
                logger.warning(
                    "gateway.routers.web.parse_agent_failed",
                    filename=f.name,
                    error=str(e),
                )
    return agents


@router.get("/playbooks", summary="List cached playbooks from TriageCore")
async def list_playbooks_endpoint(
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, str]:
    """Return the cached playbooks markdown string."""
    from gateway.services.agentix_client import get_playbooks
    md_content = await get_playbooks()
    return {"markdown": md_content}
