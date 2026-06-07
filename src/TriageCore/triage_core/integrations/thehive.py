import os
from typing import Any

import httpx
import structlog
from triage_core.integrations.base import ICaseManagementProvider

logger = structlog.get_logger(__name__)

class TheHiveProvider(ICaseManagementProvider):
    def _get_headers(self, api_key: str) -> dict:
        org = os.getenv("THEHIVE_ORGANISATION", "asdg")
        return {
            "Authorization": f"Bearer {api_key}",
            "X-Organisation": org,
            "Content-Type": "application/json"
        }

    async def create_case(self, title: str = "", description: str = "", severity: int = 2, tags: list[str] | None = None) -> str:
        tags = tags or []
        if not title and not description:
            return "Error: Both title and description cannot be empty."
        if not title:
            title = description[:100] + ("..." if len(description) > 100 else "")
        if not description:
            description = title

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
            logger.critical("thehive.create.error", error=str(e), alert=True, case_mgmt_failure=True)
            return f"Error creating case: {str(e)}"

    async def add_case_note(self, case_id: str, note: str, task_title: str = "Investigation Note") -> str:
        logger.info("provider.thehive.add_case_note", case_id=case_id)
        if not case_id or str(case_id).strip().upper() in ("N/A", "UNKNOWN", "NONE", "NULL"):
            return f"Error: Invalid Case ID '{case_id}'. Please make sure you have successfully created a case using the 'create_case' tool first, and use the Case ID returned by it."

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
            logger.critical("thehive.note.error", error=str(e), alert=True, case_mgmt_failure=True)
            return f"Error adding note: {str(e)}"

    # TheHive 5 valid case status values
    _STATUS_MAP = {
        # Direct matches (already valid)
        "new": "New",
        "inprogress": "InProgress",
        "in progress": "InProgress",
        "indeterminate": "Indeterminate",
        "falsepositive": "FalsePositive",
        "false positive": "FalsePositive",
        "false_positive": "FalsePositive",
        "truepositive": "TruePositive",
        "true positive": "TruePositive",
        "true_positive": "TruePositive",
        "duplicated": "Duplicated",
        "duplicate": "Duplicated",
        "other": "Other",
        # Common aliases the LLM agent might use
        "closed": "Indeterminate",
        "resolved": "Indeterminate",
        "investigating": "InProgress",
        "open": "InProgress",
        "active": "InProgress",
        "pending": "InProgress",
        "benign": "FalsePositive",
        "malicious": "TruePositive",
        "confirmed": "TruePositive",
    }

    def _normalize_status(self, status: str, resolution_type: str = "") -> str:
        """Map free-text status to a valid TheHive 5 CaseStatus value."""
        # Strip extra words like "Investigating - Low Priority"
        key = status.strip().lower().split(" - ")[0].strip()

        # For "closed"/"resolved", the resolution_type should drive the status
        if key in ("closed", "resolved") and resolution_type:
            rt_lower = resolution_type.strip().lower().replace(" ", "").replace("_", "")
            if rt_lower in ("falsepositive",):
                return "FalsePositive"
            elif rt_lower in ("truepositive",):
                return "TruePositive"
            elif rt_lower in ("duplicated", "duplicate"):
                return "Duplicated"
            elif rt_lower in ("indeterminate",):
                return "Indeterminate"
            elif rt_lower in ("other",):
                return "Other"
            # resolution_type didn't match a known value; fall through to map

        mapped = self._STATUS_MAP.get(key)
        if mapped:
            return mapped
        # If the original (case-preserved) is already a valid value, use it
        valid_values = set(self._STATUS_MAP.values())
        if status in valid_values:
            return status
        return "Indeterminate"  # safe fallback

    async def update_case_status(self, case_id: str, status: str, resolution_type: str = "TruePositive", summary: str = "") -> str:
        logger.info("provider.thehive.update_case_status", case_id=case_id, status=status)
        if not case_id or str(case_id).strip().upper() in ("N/A", "UNKNOWN", "NONE", "NULL"):
            return f"Error: Invalid Case ID '{case_id}'. Please make sure you have successfully created a case using the 'create_case' tool first, and use the Case ID returned by it."

        thehive_url = os.getenv("THEHIVE_URL", "http://thehive:9000")
        api_key = os.getenv("THEHIVE_API_KEY", "")
        if not api_key:
            return "Error: THEHIVE_API_KEY is not set."

        headers = self._get_headers(api_key)
        mapped_status = self._normalize_status(status, resolution_type)
        logger.info("provider.thehive.status_mapped", original=status, mapped=mapped_status)

        payload: dict = {"status": mapped_status}
        if summary:
            payload["summary"] = summary
        # Set impactStatus for resolved-like statuses
        if mapped_status in ("FalsePositive", "TruePositive", "Indeterminate", "Duplicated", "Other"):
            impact_map = {
                "FalsePositive": "NoImpact",
                "TruePositive": "WithImpact",
                "Indeterminate": "NotApplicable",
                "Duplicated": "NotApplicable",
                "Other": "NotApplicable",
            }
            payload["impactStatus"] = impact_map.get(mapped_status, "NotApplicable")

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.patch(
                    f"{thehive_url}/api/v1/case/{case_id}",
                    json=payload,
                    headers=headers,
                    timeout=10.0,
                )
                resp.raise_for_status()
                return f"Case {case_id} status updated to '{mapped_status}' (requested: '{status}')."
        except Exception as e:
            logger.critical("thehive.status.error", error=str(e), payload=payload, alert=True, case_mgmt_failure=True)
            return f"Error updating case status: {str(e)}"

    async def create_alert(self, title: str = "", description: str = "", source: str = "Agentix", source_ref: str = "", severity: int = 2, tags: list[str] | None = None, observables: list[dict[str, Any]] | None = None) -> str:
        if not title and not description:
            return "Error: Both title and description cannot be empty."
        if not title:
            title = description[:100] + ("..." if len(description) > 100 else "")
        if not description:
            description = title

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
            normalized_observables = []
            for obs in observables:
                # 1. Determine dataType
                data_type = obs.get("dataType") or obs.get("datatype") or obs.get("type")
                if not data_type:
                    # Try to infer type from keys
                    if "ip_address" in obs or "ip" in obs:
                        data_type = "ip"
                    elif "domain" in obs:
                        data_type = "domain"
                    elif "url" in obs:
                        data_type = "url"
                    elif "hash" in obs or "file_hash" in obs:
                        data_type = "hash"
                    else:
                        data_type = "other"
                
                # Normalize common types
                data_type = str(data_type).lower()
                if data_type in ("ip_address", "ipaddress"):
                    data_type = "ip"
                elif data_type in ("file_hash", "filehash"):
                    data_type = "hash"

                # 2. Determine data value
                data_val = obs.get("data") or obs.get("value")
                if not data_val:
                    # Check other keys
                    for key in ("ip_address", "ip", "domain", "url", "hash", "file_hash", "value"):
                        if key in obs:
                            data_val = obs[key]
                            break
                
                if data_type and data_val:
                    normalized_obs = {
                        "type": data_type,
                        "dataType": data_type,
                        "data": str(data_val)
                    }
                    # Copy other fields if present (message, tags, tlp, pap)
                    for k in ("message", "tags", "tlp", "pap"):
                        if k in obs:
                            normalized_obs[k] = obs[k]
                    normalized_observables.append(normalized_obs)
            
            payload["observables"] = normalized_observables

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
            logger.critical("thehive.alert.error", error=str(e), alert=True, case_mgmt_failure=True)
            return f"Error creating alert: {str(e)}"
