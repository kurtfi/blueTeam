"""
Service layer for simulation run lifecycle and telemetry replay.
"""

import asyncio
import copy
from typing import Any

import structlog

from attack_simulator.evaluator.gateway import PlaybookRegistryGateway
from attack_simulator.evaluator.playbook_match import evaluate_run
from attack_simulator.exceptions import ScenarioNotFoundError, SimulatorException
from attack_simulator.models import db_repo
from attack_simulator.sender.base import AlertSender
from attack_simulator.sender.webhook import WebhookAlertSender

logger = structlog.get_logger(__name__)


class SimulationService:
    """
    Handles creating simulation runs, executing alert replays with config adjustments,
    and invoking matching evaluations.
    """

    def __init__(
        self, alert_sender: AlertSender | None = None, playbook_gateway: PlaybookRegistryGateway | None = None
    ) -> None:
        self.alert_sender = alert_sender or WebhookAlertSender()
        self.playbook_gateway = playbook_gateway or PlaybookRegistryGateway()

    async def run_simulation(
        self,
        scenario_name: str,
        delay_between_events: float = 1.0,
        strip_labels: bool = False,
        bulk_run_id: str | None = None,
        sender_type: str = "webhook",
        timing_mode: str = "constant",
        max_original_delay: float = 30.0,
        **kwargs: Any,
    ) -> str:
        """
        Creates a simulation run and spawns execution in a background task.
        Returns the created run_id.
        """
        if not scenario_name or len(scenario_name) > 255:
            raise ValueError("Scenario name exceeds 255 characters limit.")

        sc = await db_repo.get_scenario_by_name(scenario_name)
        if not sc:
            raise ScenarioNotFoundError(f"Scenario '{scenario_name}' not found.")

        scenario_id = sc["id"]
        events = await db_repo.get_scenario_events(scenario_id)
        if not events:
            raise SimulatorException(f"Scenario '{scenario_name}' has no events in the database.")

        rate = 1.0 / delay_between_events if delay_between_events > 0 else 1.0
        run_id = await db_repo.create_run(scenario_id, len(events), rate, bulk_run_id=bulk_run_id)

        # Resolve sender and timing strategy
        from attack_simulator.sender.factory import get_sender
        from attack_simulator.services.timing import get_timing_strategy

        sender = get_sender(sender_type, **kwargs)
        timing_strategy = get_timing_strategy(
            mode=timing_mode,
            base_delay=delay_between_events,
            max_delay=max_original_delay,
        )

        # Spawn execution in the background
        asyncio.create_task(
            self.execute_simulation(
                run_id=run_id,
                scenario_id=scenario_id,
                events=events,
                delay_between_events=delay_between_events,
                strip_labels=strip_labels,
                timing_strategy=timing_strategy,
                sender=sender,
            )
        )
        return run_id

    async def execute_simulation(
        self,
        run_id: str,
        scenario_id: str,
        events: list[dict[str, Any]],
        delay_between_events: float = 1.0,
        strip_labels: bool = False,
        timing_strategy: Any = None,
        sender: Any = None,
    ) -> None:
        """
        Replays scenario events one by one, dispatches alerts, and updates run stats.
        Evaluates run outcomes upon completion.
        """
        # Backwards compatibility fallbacks
        if timing_strategy is None:
            from attack_simulator.services.timing import ConstantDelayStrategy

            timing_strategy = ConstantDelayStrategy(delay_seconds=delay_between_events)
        if sender is None:
            sender = self.alert_sender

        sent_events = 0
        try:
            for idx, ev in enumerate(events):
                alert_payload = copy.deepcopy(ev["wazuh_alert"])

                # Perform label stripping if requested
                if strip_labels:
                    if "rule" in alert_payload and isinstance(alert_payload["rule"], dict):
                        alert_payload["rule"].pop("mitre", None)
                        alert_payload["rule"].pop("rule_id", None)
                        if "groups" in alert_payload["rule"] and isinstance(alert_payload["rule"]["groups"], list):
                            import re

                            alert_payload["rule"]["groups"] = [
                                g
                                for g in alert_payload["rule"]["groups"]
                                if not (str(g).lower().startswith("mitre_") or re.match(r"^t\d{4}", str(g).lower()))
                            ]
                        alert_payload["rule"]["id"] = "999999"
                    alert_payload.pop("mitre_ids", None)
                    alert_payload.pop("rule_id", None)

                alert_payload["simulation_run_id"] = str(run_id)
                session_id = await sender.send(alert_payload, ev["mitre_technique"])

                # Resolve expected playbook
                expected_mitre = [ev["mitre_technique"]]
                expected_list = []
                try:
                    candidates = self.playbook_gateway.find_playbooks_for_mitre(expected_mitre)
                    expected_list = [c.id for c in candidates]
                except Exception:
                    pass

                expected_pb = expected_list[0] if expected_list else None

                await db_repo.insert_simulation_result(
                    run_id=run_id,
                    event_id=ev["id"],
                    session_id=session_id,
                    expected_mitre=expected_mitre,
                    expected_playbook=expected_pb,
                    match_result="PENDING",
                )

                sent_events += 1
                await db_repo.update_run_stats(run_id=run_id, status="RUNNING", sent_events=sent_events)

                if idx < len(events) - 1:
                    next_ev = events[idx + 1]
                    await timing_strategy.wait_before_next(ev, next_ev)

            # Wait 8s for the async agent triage workflow to finish matching playbooks
            logger.info("simulation.sleeping_for_eval", run_id=run_id)
            await asyncio.sleep(8)

            # Run evaluation
            await evaluate_run(run_id)
            logger.info("simulation.run_completed", run_id=run_id)

        except Exception as e:
            logger.exception("simulation.worker_error", run_id=run_id, error=str(e))
            await db_repo.update_run_stats(run_id=run_id, status="FAILED", sent_events=sent_events)

    async def evaluate_run_if_needed(self, run_id: str) -> None:
        """
        Evaluate run results against playbooks in real-time.
        """
        try:
            await evaluate_run(run_id)
        except Exception as e:
            logger.warning("SimulationService.evaluation_failed", run_id=run_id, error=str(e))

    async def trigger_bulk_simulations(
        self,
        name: str,
        scenario_ids: list[str],
        send_rate_per_sec: float,
        strip_labels: bool,
        llm_provider: str,
        llm_model: str,
        sender_type: str = "webhook",
        timing_mode: str = "constant",
        max_original_delay: float = 30.0,
        **kwargs: Any,
    ) -> str:
        """
        Create the bulk run record and spawn background sequential execution task.
        """
        bulk_run_id = await db_repo.create_bulk_run(
            name=name,
            llm_provider=llm_provider,
            llm_model=llm_model,
            strip_labels=strip_labels,
            send_rate_per_sec=send_rate_per_sec,
            total_scenarios=len(scenario_ids),
        )

        asyncio.create_task(
            self.run_bulk_simulation_task(
                bulk_run_id=bulk_run_id,
                scenario_ids=scenario_ids,
                send_rate_per_sec=send_rate_per_sec,
                strip_labels=strip_labels,
                sender_type=sender_type,
                timing_mode=timing_mode,
                max_original_delay=max_original_delay,
                **kwargs,
            )
        )

        return bulk_run_id

    async def run_bulk_simulation_task(
        self,
        bulk_run_id: str,
        scenario_ids: list[str],
        send_rate_per_sec: float,
        strip_labels: bool,
        sender_type: str = "webhook",
        timing_mode: str = "constant",
        max_original_delay: float = 30.0,
        **kwargs: Any,
    ) -> None:
        """
        Background task running scenarios sequentially for a bulk simulation run.
        """
        import uuid

        delay = 1.0 / send_rate_per_sec
        bulk_uuid = uuid.UUID(bulk_run_id)

        for sc_id in scenario_ids:
            try:
                # Check bulk run status for cancellation
                status = await db_repo.get_bulk_run_status(bulk_uuid)
                if status in ("CANCELLED", "PARTIALLY_COMPLETED"):
                    logger.info("SimulationService.bulk_run_interrupted", bulk_run_id=bulk_run_id, status=status)
                    break

                total_events = await db_repo.get_scenario_total_events(uuid.UUID(sc_id))
                if total_events is None:
                    logger.warning("SimulationService.bulk_run.scenario_not_found", scenario_id=sc_id)
                    continue

                sc = await db_repo.get_scenario_by_id(uuid.UUID(sc_id))
                if not sc:
                    continue

                run_id = await db_repo.create_run(
                    scenario_id=sc_id,
                    total_events=total_events,
                    send_rate_per_sec=send_rate_per_sec,
                    bulk_run_id=bulk_run_id,
                )

                logger.info(
                    "SimulationService.bulk_run.starting_scenario",
                    bulk_run_id=bulk_run_id,
                    scenario_id=sc_id,
                    run_id=run_id,
                )

                # Resolve sender and timing strategy
                from attack_simulator.sender.factory import get_sender
                from attack_simulator.services.timing import get_timing_strategy

                sender = get_sender(sender_type, **kwargs)
                timing_strategy = get_timing_strategy(
                    mode=timing_mode,
                    base_delay=delay,
                    max_delay=max_original_delay,
                )

                # Execute sequentially
                events = await db_repo.get_scenario_events(sc_id)
                await self.execute_simulation(
                    run_id=run_id,
                    scenario_id=sc_id,
                    events=events,
                    delay_between_events=delay,
                    strip_labels=strip_labels,
                    timing_strategy=timing_strategy,
                    sender=sender,
                )

                logger.info(
                    "SimulationService.bulk_run.finished_scenario",
                    bulk_run_id=bulk_run_id,
                    scenario_id=sc_id,
                    run_id=run_id,
                )
                await asyncio.sleep(2)
            except Exception as e:
                logger.exception(
                    "SimulationService.bulk_run.scenario_failed",
                    bulk_run_id=bulk_run_id,
                    scenario_id=sc_id,
                    error=str(e),
                )

    async def bulk_run_status_poller(self) -> None:
        """
        Background task polling for active bulk runs to evaluate sub-runs and update stats.
        """
        while True:
            try:
                bulk_rows = await db_repo.get_active_bulk_runs()
                for row in bulk_rows:
                    bulk_run_id = str(row["id"])
                    runs = await db_repo.get_runs_for_bulk(bulk_run_id)

                    completed_scenarios = 0
                    matched_count = 0
                    mismatched_count = 0
                    nobook_count = 0
                    all_done = len(runs) >= row["total_scenarios"]

                    for r in runs:
                        r_id = r["id"]
                        if r["status"] == "RUNNING":
                            try:
                                await self.evaluate_run_if_needed(r_id)
                                updated_r = await db_repo.get_run(r_id)
                                if updated_r:
                                    r = updated_r
                            except Exception as eval_err:
                                logger.warning(
                                    "SimulationService.poller_eval_failed",
                                    run_id=r_id,
                                    error=str(eval_err),
                                )

                        if r["status"] in ("COMPLETED", "FAILED"):
                            completed_scenarios += 1
                            matched_count += r.get("matched_playbooks", 0)
                            mismatched_count += r.get("mismatched_playbooks", 0)
                            nobook_count += r.get("no_playbook", 0)
                        else:
                            all_done = False

                    bulk_status = "COMPLETED" if (all_done and len(runs) > 0) else "RUNNING"
                    await db_repo.update_bulk_run_stats(
                        bulk_run_id=bulk_run_id,
                        status=bulk_status,
                        completed_scenarios=completed_scenarios,
                        matched=matched_count,
                        mismatched=mismatched_count,
                        nobook=nobook_count,
                    )
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("SimulationService.poller_error", error=str(e))

            await asyncio.sleep(5)

    async def cancel_bulk_run(self, bulk_run_id: str) -> None:
        """
        Cancel bulk run status and compute stats up to the point of cancellation.
        """
        await db_repo.cancel_bulk_run(bulk_run_id)

