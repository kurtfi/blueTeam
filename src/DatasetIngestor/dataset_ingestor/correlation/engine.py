"""
Orchestrates correlation rules and aggregation logic over raw security events.
"""

from datetime import UTC, datetime
from typing import Any

import structlog
from attack_simulator.mapper.wazuh_template import generate_wazuh_alert
from dataset_ingestor.correlation.aggregator import EventAggregator
from dataset_ingestor.correlation.rules import CorrelationRule, load_rules

logger = structlog.get_logger(__name__)


class CorrelationEngine:
    """
    Main engine that consumes raw event telemetry and outputs correlated SIEM alerts.
    """

    def __init__(self, rules: list[CorrelationRule] | None = None) -> None:
        self.rules = rules if rules is not None else load_rules()
        self.aggregators: dict[str, EventAggregator] = {}

        # Instantiate aggregators for rules requiring them
        for rule in self.rules:
            if rule.correlation_type == "aggregation":
                agg_config = rule.aggregation
                self.aggregators[rule.technique_id] = EventAggregator(
                    group_by_fields=agg_config.get("group_by", ["IpAddress"]),
                    threshold=agg_config.get("threshold", 8),
                    timeframe_seconds=agg_config.get("timeframe_seconds", 120),
                )
        logger.info("correlation.engine_ready", rule_count=len(self.rules), aggregator_count=len(self.aggregators))

    def _parse_event_time(self, event: dict[str, Any]) -> datetime:
        """
        Extract timestamp from raw event or fallback to UTC now.
        """
        time_str = event.get("TimeCreated") or event.get("@timestamp")
        if time_str:
            try:
                # Common ISO formats (e.g. 2019-05-18T20:03:36.000Z or similar)
                # We strip trailing Z to avoid issues in older python versions
                clean_time = str(time_str).replace("Z", "+00:00")
                return datetime.fromisoformat(clean_time)
            except Exception:
                pass
        return datetime.now(UTC)

    def process_event(self, raw_event: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Processes a single raw event. Returns a list of generated Wazuh alerts (if matched).
        """
        alerts = []
        event_time = self._parse_event_time(raw_event)

        for rule in self.rules:
            if not rule.matches_event(raw_event):
                continue

            if rule.correlation_type == "direct":
                # 1:1 match -> directly generate alert
                alert = generate_wazuh_alert(rule.technique_id, raw_event)
                # Override rule details if specified in rule's output_alert
                if rule.output_alert:
                    alert["rule"].update(rule.output_alert)
                alerts.append(alert)
                logger.debug(
                    "correlation.direct_match_triggered", technique_id=rule.technique_id, rule_id=alert["rule"]["id"]
                )

            elif rule.correlation_type == "aggregation":
                # Aggregate match -> track window
                aggregator = self.aggregators.get(rule.technique_id)
                if aggregator:
                    triggered = aggregator.add_and_check(raw_event, event_time)
                    if triggered:
                        alert = generate_wazuh_alert(rule.technique_id, raw_event)
                        if rule.output_alert:
                            alert["rule"].update(rule.output_alert)
                        # Enrich full_log to summarize aggregation
                        alert["full_log"] = (
                            f"Correlation Aggregator [{rule.technique_name}] triggered. "
                            f"Matched {aggregator.threshold} events in {aggregator.timeframe_seconds}s window."
                        )
                        alerts.append(alert)
                        logger.info(
                            "correlation.aggregation_triggered",
                            technique_id=rule.technique_id,
                            rule_id=alert["rule"]["id"],
                        )

        return list(alerts)
