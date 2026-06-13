"""
Wrapper module to transform correlated events to Wazuh alert payloads.
"""

from typing import Any
from attack_simulator.mapper.wazuh_template import generate_wazuh_alert


def transform_to_wazuh_alert(technique_id: str, raw_event: dict[str, Any]) -> dict[str, Any]:
    """
    Transforms a matched technique event into a structured Wazuh alert JSON payload.
    """
    return generate_wazuh_alert(technique_id, raw_event)
