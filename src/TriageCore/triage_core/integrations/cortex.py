import asyncio
import json
import os

import httpx
import structlog
from triage_core.integrations.base import IEnrichmentProvider

logger = structlog.get_logger(__name__)


class CortexProvider(IEnrichmentProvider):
    async def get_ip_reputation(self, ip_address: str) -> str:
        logger.info("provider.cortex.get_ip_reputation", ip_address=ip_address)
        analyzers_str = os.getenv("CORTEX_IP_ANALYZERS", "VirusTotal_GetReport_3_1,AbuseIPDB_2_0")
        analyzers = [a.strip() for a in analyzers_str.split(",") if a.strip()]

        tasks = [self._analyze(ip_address, "ip", analyzer) for analyzer in analyzers]
        results = await asyncio.gather(*tasks)

        combined = []
        for name, res in zip(analyzers, results):
            combined.append(f"=== {name.upper()} REPORT ===\n{res}")
        return "\n\n".join(combined)

    async def get_file_reputation(self, file_hash: str) -> str:
        logger.info("provider.cortex.get_file_reputation", file_hash=file_hash)
        analyzers_str = os.getenv("CORTEX_FILE_ANALYZERS", "VirusTotal_GetReport_3_1")
        analyzers = [a.strip() for a in analyzers_str.split(",") if a.strip()]

        tasks = [self._analyze(file_hash, "hash", analyzer) for analyzer in analyzers]
        results = await asyncio.gather(*tasks)

        combined = []
        for name, res in zip(analyzers, results):
            combined.append(f"=== {name.upper()} REPORT ===\n{res}")
        return "\n\n".join(combined)

    async def get_domain_url_reputation(self, url_or_domain: str) -> str:
        logger.info("provider.cortex.get_domain_url_reputation", url_or_domain=url_or_domain)
        data_type = "url" if url_or_domain.startswith("http") else "domain"
        analyzers_str = os.getenv("CORTEX_DOMAIN_ANALYZERS", "VirusTotal_GetReport_3_1")
        analyzers = [a.strip() for a in analyzers_str.split(",") if a.strip()]

        tasks = [self._analyze(url_or_domain, data_type, analyzer) for analyzer in analyzers]
        results = await asyncio.gather(*tasks)

        combined = []
        for name, res in zip(analyzers, results):
            combined.append(f"=== {name.upper()} REPORT ===\n{res}")
        return "\n\n".join(combined)

    async def _analyze(self, observable: str, data_type: str, analyzer_name: str) -> str:
        cortex_url = os.getenv("CORTEX_URL", "http://localhost:9001")
        cortex_api_key = os.getenv("CORTEX_API_KEY", "")

        if not cortex_api_key:
            return "Error: CORTEX_API_KEY is not configured."

        headers = {"Authorization": f"Bearer {cortex_api_key}"}

        try:
            async with httpx.AsyncClient() as client:
                # 1. Get Analyzer ID dynamically
                analyzers_resp = await client.get(f"{cortex_url}/api/analyzer", headers=headers, timeout=10.0)
                analyzers_resp.raise_for_status()
                analyzers = analyzers_resp.json()

                analyzer_id = None
                for analyzer in analyzers:
                    if analyzer.get("name") == analyzer_name or analyzer.get("analyzerDefinitionId") == analyzer_name:
                        analyzer_id = analyzer.get("id")
                        break

                if not analyzer_id:
                    return f"Error: Analyzer '{analyzer_name}' not found or not enabled in Cortex."

                # 2. Start Job
                job_payload = {"dataType": data_type, "data": observable, "tlp": 2, "pap": 2}
                run_resp = await client.post(
                    f"{cortex_url}/api/analyzer/{analyzer_id}/run", json=job_payload, headers=headers, timeout=10.0
                )
                run_resp.raise_for_status()
                job_data = run_resp.json()
                job_id = job_data.get("id")

                if not job_id:
                    return f"Error: Job creation failed. Response: {json.dumps(job_data)}"

                # 3. Poll Job Status
                max_attempts = 15
                for attempt in range(max_attempts):
                    await asyncio.sleep(2.0)
                    status_resp = await client.get(f"{cortex_url}/api/job/{job_id}", headers=headers, timeout=10.0)
                    status_resp.raise_for_status()
                    job_status = status_resp.json()

                    status = job_status.get("status")
                    if status == "Success":
                        # 4. Fetch Report
                        report_resp = await client.get(
                            f"{cortex_url}/api/job/{job_id}/report", headers=headers, timeout=10.0
                        )
                        report_resp.raise_for_status()
                        report_data = report_resp.json()

                        full_report = report_data.get("report", {}).get("full", {})
                        summary_report = report_data.get("report", {}).get("summary", {})

                        return f"Cortex Analysis Successful | Job ID: {job_id} | Analyzer: {analyzer_name} | Status: {status}\nSummary Report: {json.dumps(summary_report)}\nFull Report Details (First 1000 chars): {json.dumps(full_report)[:1000]}"
                    elif status == "Failure":
                        err_msg = job_status.get("errorMessage", "Unknown error")
                        return f"Cortex Analysis Failed | Job ID: {job_id} | Error: {err_msg}"

                return f"Cortex Analysis Timeout | Job ID: {job_id} | Final Status: {status or 'Unknown'}"

        except Exception as e:
            logger.critical("cortex.analysis.error", error=str(e), alert=True, enrichment_failure=True)
            return f"Error during Cortex analysis: {str(e)}"
