import os
import httpx
import structlog
from typing import Optional, List, Dict, Any

from soc_mcp.integrations.base import ICaseManagementProvider

logger = structlog.get_logger(__name__)

class TheHiveProvider(ICaseManagementProvider):
    def _get_headers(self, api_key: str) -> dict:
        org = os.getenv("THEHIVE_ORGANISATION", "asdg")
        return {
            "Authorization": f"Bearer {api_key}",
            "X-Organisation": org,
            "Content-Type": "application/json"
        }

    async def create_case(self, title: str, description: str, severity: int = 2, tags: Optional[List[str]] = None) -> str:
        tags = tags or []
        logger.info("provider.thehive.create_case", title=title, severity=severity)
        
        thehive_url = os.getenv("THEHIVE_URL", "http://thehive:9000")
        api_key = os.getenv("THEHIVE_API_KEY", "")
        
        if not api_key:
            return "Error: THEHIVE_API_KEY environment variable is not set."
            
        headers = self._get_headers(api_key)
        payload = {
            "title": title,
            "description": description,
            "severity": severity,
            "tags": tags
        }
        
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(f"{thehive_url}/api/v1/case", json=payload, headers=headers, timeout=10.0)
                resp.raise_for_status()
                data = resp.json()
                case_id = data.get("_id") or data.get("id") or data.get("caseId", "UNKNOWN")
                return f"Case successfully created. Case ID: {case_id}"
        except Exception as e:
            logger.error("thehive.create.error", error=str(e))
            return f"Error creating case: {str(e)}"

    async def add_case_note(self, case_id: str, note: str, task_title: str = "Investigation Note") -> str:
        logger.info("provider.thehive.add_case_note", case_id=case_id)
        thehive_url = os.getenv("THEHIVE_URL", "http://thehive:9000")
        api_key = os.getenv("THEHIVE_API_KEY", "")
        if not api_key:
            return "Error: THEHIVE_API_KEY is not set."

        headers = self._get_headers(api_key)
        try:
            async with httpx.AsyncClient() as client:
                task_payload = {
                    "title": task_title,
                    "description": note,
                    "status": "Completed",
                    "group": "Documentation",
                }
                resp = await client.post(
                    f"{thehive_url}/api/v1/case/{case_id}/task",
                    json=task_payload,
                    headers=headers,
                    timeout=10.0,
                )
                resp.raise_for_status()
                task_id = resp.json().get("_id", "?")
                return f"Note successfully added. Task ID: {task_id}"
        except Exception as e:
            logger.error("thehive.note.error", error=str(e))
            return f"Error adding note: {str(e)}"

    async def update_case_status(self, case_id: str, status: str, resolution_type: str = "TruePositive", summary: str = "") -> str:
        logger.info("provider.thehive.update_case_status", case_id=case_id, status=status)
        thehive_url = os.getenv("THEHIVE_URL", "http://thehive:9000")
        api_key = os.getenv("THEHIVE_API_KEY", "")
        if not api_key:
            return "Error: THEHIVE_API_KEY is not set."

        headers = self._get_headers(api_key)
        payload: dict = {"status": status}
        if status == "Resolved":
            payload["resolutionStatus"] = resolution_type
            if summary:
                payload["summary"] = summary

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.patch(
                    f"{thehive_url}/api/v1/case/{case_id}",
                    json=payload,
                    headers=headers,
                    timeout=10.0,
                )
                resp.raise_for_status()
                return f"Case {case_id} status updated to '{status}'."
        except Exception as e:
            logger.error("thehive.status.error", error=str(e))
            return f"Error updating case status: {str(e)}"

    async def create_alert(self, title: str, description: str, source: str = "Agentix", source_ref: str = "", severity: int = 2, tags: Optional[List[str]] = None, observables: Optional[List[Dict[str, Any]]] = None) -> str:
        logger.info("provider.thehive.create_alert", title=title, source=source)
        thehive_url = os.getenv("THEHIVE_URL", "http://thehive:9000")
        api_key = os.getenv("THEHIVE_API_KEY", "")
        if not api_key:
            return "Error: THEHIVE_API_KEY is not set."

        headers = self._get_headers(api_key)
        payload = {
            "title": title,
            "description": description,
            "type": "external",
            "source": source,
            "sourceRef": source_ref or f"agentix-{title[:20].replace(' ', '-').lower()}",
            "severity": severity,
            "tags": tags or [],
            "tlp": 2,
            "pap": 2,
        }
        if observables:
            payload["observables"] = observables

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{thehive_url}/api/v1/alert",
                    json=payload,
                    headers=headers,
                    timeout=10.0,
                )
                resp.raise_for_status()
                data = resp.json()
                alert_id = data.get("_id", data.get("id", "UNKNOWN"))
                return f"Alert successfully created. Alert ID: {alert_id}"
        except Exception as e:
            logger.error("thehive.alert.error", error=str(e))
            return f"Error creating alert: {str(e)}"
