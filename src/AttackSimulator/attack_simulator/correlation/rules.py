"""
Parses and loads YAML correlation rules for AttackSimulator.
"""

import glob
import os
import re
from typing import Any

import structlog
import yaml

logger = structlog.get_logger(__name__)


class CorrelationRule:
    """
    Representation of a single local correlation rule.
    """

    def __init__(self, data: dict[str, Any]) -> None:
        self.technique_id: str = data["technique_id"]
        self.technique_name: str = data.get("technique_name", "Unnamed Technique")
        self.correlation_type: str = data.get("correlation_type", "direct")  # "direct" or "aggregation"
        self.match_events: list[dict[str, Any]] = data.get("match_events", [])
        self.aggregation: dict[str, Any] = data.get("aggregation", {})
        self.output_alert: dict[str, Any] = data.get("output_alert", {})

    def matches_event(self, event: dict[str, Any]) -> bool:
        """
        Evaluates whether a raw event matches this rule's criteria.
        """
        for criteria in self.match_events:
            # Check Event ID
            expected_id = criteria.get("event_id")
            actual_id = event.get("EventID") or event.get("event_id") or event.get("eventID")
            if expected_id is not None:
                if actual_id is None:
                    continue  # Required field is missing in event
                if str(expected_id) != str(actual_id):
                    continue

            # Check Channel/Source
            expected_channel = criteria.get("channel")
            actual_channel = event.get("Channel") or event.get("channel")
            if expected_channel:
                if actual_channel is None:
                    continue  # Required field is missing in event
                if str(expected_channel).lower() != str(actual_channel).lower():
                    continue

            # Check filters (wildcard/substring checks)
            filters = criteria.get("filter", {})
            if not filters:
                # If there are filters in the criteria itself (older schema style)
                filters = {k: v for k, v in criteria.items() if k not in ("event_id", "channel")}

            match_failed = False
            for field, val in filters.items():
                actual_val = event.get(field)
                if actual_val is None:
                    match_failed = True
                    break

                # Check wildcard string
                pattern = str(val).lower().replace("*", ".*")
                if not re.search(f"^{pattern}$", str(actual_val).lower()):
                    match_failed = True
                    break

            if not match_failed:
                return True

        return False


def load_rules(rules_dir: str | None = None) -> list[CorrelationRule]:
    """
    Loads all correlation rules from the rules directory.
    """
    if rules_dir is None:
        # Resolve path relative to this file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        rules_dir = os.path.join(current_dir, "../correlation_rules")
        rules_dir = os.path.abspath(rules_dir)

    rules: list[CorrelationRule] = []
    if not os.path.exists(rules_dir):
        logger.warning("correlation.rules_directory_missing", path=rules_dir)
        return rules

    yaml_files = glob.glob(os.path.join(rules_dir, "*.yaml")) + glob.glob(os.path.join(rules_dir, "*.yml"))
    for path in yaml_files:
        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if data and "technique_id" in data:
                    rules.append(CorrelationRule(data))
        except Exception as e:
            logger.error("correlation.failed_to_load_rule", path=path, error=str(e))

    logger.info("correlation.rules_loaded", count=len(rules), path=rules_dir)
    return rules
