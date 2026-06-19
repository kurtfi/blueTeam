"""
Configuration loader for AttackSimulator.
"""

import os
import structlog
from agentic_common.settings import settings

logger = structlog.get_logger(__name__)

# Base DSN derived from AgenticCommon settings or env override
DATABASE_URL = os.getenv(
    "ATTACK_SIMULATOR_DATABASE_URL", 
    settings.agentix_postgres_url.replace("+asyncpg", "")
)

# Target Agentix Webhook URL
WEBHOOK_URL = os.getenv(
    "AGENTIX_WEBHOOK_URL", 
    "http://localhost:8080/v1/webhooks/simulation"
)

# Internal API Key for webhook authentication bypass
INTERNAL_API_KEY = os.getenv(
    "AGENTIX_INTERNAL_API_KEY", 
    settings.agentix_internal_api_key
)

logger.info(
    "attack_simulator.config_loaded",
    webhook_url=WEBHOOK_URL,
    db_host=DATABASE_URL.split("@")[-1] if "@" in DATABASE_URL else "localhost",
    has_api_key=bool(INTERNAL_API_KEY)
)
