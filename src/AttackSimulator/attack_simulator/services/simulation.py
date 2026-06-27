"""
Service layer for simulation run lifecycle and telemetry replay.
"""

import asyncio
import copy
import re
import uuid
from typing import Any

import structlog

from attack_simulator.evaluator.gateway import PlaybookRegistryGateway
from attack_simulator.evaluator.playbook_match import evaluate_run
from attack_simulator.exceptions import ScenarioNotFoundError, SimulatorException
from attack_simulator.repository import SimulationRepository, db_repo
from attack_simulator.sender.base import AlertSender
from attack_simulator.sender.webhook import WebhookAlertSender

logger = structlog.get_logger(__name__)


def strip_alert_labels(alert_payload: dict[str, Any]) -> dict[str, Any]:
    """
    Safeguard to strip MITRE, rule_id, and tactic labels from alert payloads.
    """
    sanitized = copy.deepcopy(alert_payload)
    if "rule" in sanitized and isinstance(sanitized["rule"], dict):
        sanitized["rule"].pop("mitre", None)
        sanitized["rule"].pop("rule_id", None)
        if "groups" in sanitized["rule"] and isinstance(sanitized["rule"]["groups"], list):
            sanitized["rule"]["groups"] = [
                g
                for g in sanitized["rule"]["groups"]
                if not (str(g).lower().startswith("mitre_") or re.match(r"^t\d{4}", str(g).lower()))
            ]
        sanitized["rule"]["id"] = "999999"
    sanitized.pop("mitre_ids", None)
    sanitized.pop("rule_id", None)
    return sanitized


class DagSimulationExecutor:
    """
    Orchestrates state-machine transitions and playbook matching evaluation
    for a DAG-based attack simulation run.
    """

    def __init__(
        self,
        run_id: str,
        scenario_id: str,
        dag_structure: dict[str, Any],
        db: SimulationRepository,
        sender: AlertSender,
        timing_strategy: Any,
        strip_labels: bool = False,
    ) -> None:
        self.run_id = run_id
        self.scenario_id = scenario_id
        self.dag_structure = dag_structure
        self.db = db
        self.sender = sender
        self.timing_strategy = timing_strategy
        self.strip_labels = strip_labels

    async def execute(self) -> None:
        initial_step = self.dag_structure.get("initial_step")
        steps = self.dag_structure.get("steps", {})

        if not initial_step or not steps:
            logger.error("simulation.dag_invalid_structure", run_id=self.run_id)
            await self.db.update_run_stats(run_id=self.run_id, status="FAILED", sent_events=0)
            return

        current_step = initial_step
        traversed_path = []
        sent_events = 0
        matched_playbooks = 0
        mismatched_playbooks = 0
        no_playbook = 0

        try:
            while current_step:
                if current_step not in steps:
                    logger.warning("simulation.dag_step_not_found", step=current_step)
                    break

                step_info = steps[current_step]
                mitre_technique = step_info.get("mitre_technique")
                wazuh_alerts = step_info.get("wazuh_alerts", [])
                transitions = step_info.get("next", {})

                # Record step traversal
                traversed_path.append(current_step)
                await self.db.update_run_path(self.run_id, list(traversed_path))

                if not wazuh_alerts:
                    # Empty/terminal node
                    logger.info("simulation.dag_reached_terminal_step", step=current_step)
                    if not transitions:
                        break
                    next_step = None
                    if transitions and "COMPLETED" in transitions:
                        next_step = transitions["COMPLETED"]
                    elif transitions and isinstance(transitions, dict) and len(transitions) > 0:
                        next_step = list(transitions.values())[0]
                    current_step = next_step
                    continue

                logger.info("simulation.dag_executing_step", step=current_step, alerts_count=len(wazuh_alerts))

                # Play all alerts for this step
                last_session_id = None
                for idx, alert in enumerate(wazuh_alerts):
                    if self.strip_labels:
                        alert_payload = strip_alert_labels(alert)
                    else:
                        alert_payload = copy.deepcopy(alert)

                    alert_payload["simulation_run_id"] = str(self.run_id)
                    last_session_id = await self.sender.send(alert_payload, mitre_technique)
                    sent_events += 1
                    await self.db.update_run_stats(run_id=self.run_id, status="RUNNING", sent_events=sent_events)

                    if idx < len(wazuh_alerts) - 1:
                        await self.timing_strategy.wait_before_next(alert, wazuh_alerts[idx + 1])

                if not last_session_id:
                    logger.warning("simulation.dag_step_no_session", step=current_step)
                    mismatched_playbooks += 1
                    current_step = transitions.get("TIMEOUT") or transitions.get("NO_PLAYBOOK")
                    continue

                from attack_simulator.evaluator.playbook_match import get_expected_playbooks

                expected_list = await get_expected_playbooks([mitre_technique])
                expected_pb = expected_list[0] if expected_list else None

                result_id = await self.db.insert_simulation_result(
                    run_id=self.run_id,
                    event_id=None,
                    session_id=last_session_id,
                    expected_mitre=[mitre_technique],
                    expected_playbook=expected_pb,
                    match_result="PENDING",
                )

                # Poll and evaluate verdict
                verdict, actual_pb = await self._poll_step_verdict(last_session_id, expected_list)

                logger.info(
                    "simulation.dag_step_verdict", step=current_step, verdict=verdict, actual_playbook=actual_pb
                )

                if verdict == "TRUE_POSITIVE":
                    match_result = "CORRECT"
                    matched_playbooks += 1
                elif verdict == "FALSE_POSITIVE":
                    match_result = "WRONG"
                    mismatched_playbooks += 1
                elif verdict == "NO_PLAYBOOK":
                    match_result = "NO_PLAYBOOK"
                    no_playbook += 1
                else:
                    match_result = "TIMEOUT"
                    mismatched_playbooks += 1

                # Update the result record
                await self.db.update_simulation_result_actual(result_id, actual_pb, match_result)

                next_step = transitions.get(verdict)
                if not next_step:
                    next_step = transitions.get("TIMEOUT") or transitions.get("NO_PLAYBOOK")

                current_step = next_step

            # Finalize run
            logger.info("simulation.dag_run_completed", run_id=self.run_id, path=traversed_path)
            await self.db.update_run_stats(
                run_id=self.run_id,
                status="COMPLETED",
                sent_events=sent_events,
                matched_playbooks=matched_playbooks,
                mismatched_playbooks=mismatched_playbooks,
                no_playbook=no_playbook,
            )

        except Exception as e:
            logger.exception("simulation.dag_error", run_id=self.run_id, error=str(e))
            await self.db.update_run_stats(run_id=self.run_id, status="FAILED", sent_events=sent_events)

    async def _poll_step_verdict(self, last_session_id: str, expected_list: list[str]) -> tuple[str, str | None]:
        from attack_simulator.evaluator.agentix_gateway import AgentixSessionGateway
        from attack_simulator.evaluator.playbook_match import check_actual_playbook

        agentix_gateway = AgentixSessionGateway()

        verdict = "TIMEOUT"
        actual_pb = None
        timeout_limit = 25.0
        poll_interval = 2.0
        elapsed = 0.0

        while elapsed < timeout_limit:
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

            actual_pb = await check_actual_playbook(last_session_id)
            sess_status = await agentix_gateway.get_session_status(last_session_id)

            if not sess_status:
                sess_status = "FAILED"

            if actual_pb:
                if actual_pb in expected_list:
                    verdict = "TRUE_POSITIVE"
                else:
                    verdict = "FALSE_POSITIVE"
                break
            elif sess_status not in ("ACTIVE", "WAITING_APPROVAL"):
                verdict = "NO_PLAYBOOK"
                break

        return verdict, actual_pb


class SimulationService:
    """
    Handles creating simulation runs, executing alert replays with config adjustments,
    and invoking matching evaluations.
    """

    def __init__(
        self,
        alert_sender: AlertSender | None = None,
        playbook_gateway: PlaybookRegistryGateway | None = None,
        db_repository: SimulationRepository | None = None,
    ) -> None:
        self.alert_sender = alert_sender or WebhookAlertSender()
        self.playbook_gateway = playbook_gateway or PlaybookRegistryGateway()
        self.db = db_repository or db_repo

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

        sc = await self.db.get_scenario_by_name(scenario_name)
        if not sc:
            raise ScenarioNotFoundError(f"Scenario '{scenario_name}' not found.")

        scenario_id = sc["id"]
        is_dag = sc.get("type") == "dag"

        if is_dag:
            total_events = sc.get("total_events") or 0
            events = []
        else:
            events = await self.db.get_scenario_events(scenario_id)
            if not events:
                raise SimulatorException(f"Scenario '{scenario_name}' has no events in the database.")
            total_events = len(events)

        rate = 1.0 / delay_between_events if delay_between_events > 0 else 1.0
        run_id = await self.db.create_run(scenario_id, total_events, rate, bulk_run_id=bulk_run_id)

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
        if is_dag:
            asyncio.create_task(
                self.execute_dag_simulation(
                    run_id=run_id,
                    scenario_id=scenario_id,
                    dag_structure=sc.get("dag_structure") or {},
                    delay_between_events=delay_between_events,
                    strip_labels=strip_labels,
                    timing_strategy=timing_strategy,
                    sender=sender,
                )
            )
        else:
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
                if strip_labels:
                    alert_payload = strip_alert_labels(ev["wazuh_alert"])
                else:
                    alert_payload = copy.deepcopy(ev["wazuh_alert"])

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

                await self.db.insert_simulation_result(
                    run_id=run_id,
                    event_id=ev["id"],
                    session_id=session_id,
                    expected_mitre=expected_mitre,
                    expected_playbook=expected_pb,
                    match_result="PENDING",
                )

                sent_events += 1
                await self.db.update_run_stats(run_id=run_id, status="RUNNING", sent_events=sent_events)

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
            await self.db.update_run_stats(run_id=run_id, status="FAILED", sent_events=sent_events)

    async def execute_dag_simulation(
        self,
        run_id: str,
        scenario_id: str,
        dag_structure: dict[str, Any],
        delay_between_events: float = 1.0,
        strip_labels: bool = False,
        timing_strategy: Any = None,
        sender: Any = None,
    ) -> None:
        """
        Executes a DAG-based attack scenario using a state machine.
        """
        if timing_strategy is None:
            from attack_simulator.services.timing import ConstantDelayStrategy

            timing_strategy = ConstantDelayStrategy(delay_seconds=delay_between_events)
        if sender is None:
            sender = self.alert_sender

        executor = DagSimulationExecutor(
            run_id=run_id,
            scenario_id=scenario_id,
            dag_structure=dag_structure,
            db=self.db,
            sender=sender,
            timing_strategy=timing_strategy,
            strip_labels=strip_labels,
        )
        await executor.execute()

    async def evaluate_run_if_needed(self, run_id: str) -> None:
        """
        Evaluate run results against playbooks in real-time.
        """
        try:
            run = await self.db.get_run(run_id)
            if run and run.get("scenario_id"):
                sc = await self.db.get_scenario_by_id(uuid.UUID(run["scenario_id"]))
                if sc and sc.get("type") == "dag":
                    return
            await evaluate_run(run_id)
        except Exception as e:
            logger.warning("SimulationService.poller_eval_failed", run_id=run_id, error=str(e))

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
        bulk_run_id = await self.db.create_bulk_run(
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
        delay = 1.0 / send_rate_per_sec
        bulk_uuid = uuid.UUID(bulk_run_id)

        for sc_id in scenario_ids:
            try:
                # Check bulk run status for cancellation
                status = await self.db.get_bulk_run_status(bulk_uuid)
                if status in ("CANCELLED", "PARTIALLY_COMPLETED"):
                    logger.info("SimulationService.bulk_run_interrupted", bulk_run_id=bulk_run_id, status=status)
                    break

                total_events = await self.db.get_scenario_total_events(uuid.UUID(sc_id))
                if total_events is None:
                    logger.warning("SimulationService.bulk_run.scenario_not_found", scenario_id=sc_id)
                    continue

                sc = await self.db.get_scenario_by_id(uuid.UUID(sc_id))
                if not sc:
                    continue

                run_id = await self.db.create_run(
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

                if sc.get("type") == "dag":
                    await self.execute_dag_simulation(
                        run_id=run_id,
                        scenario_id=sc_id,
                        dag_structure=sc.get("dag_structure") or {},
                        delay_between_events=delay,
                        strip_labels=strip_labels,
                        timing_strategy=timing_strategy,
                        sender=sender,
                    )
                else:
                    # Execute sequentially
                    events = await self.db.get_scenario_events(sc_id)
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
                bulk_rows = await self.db.get_active_bulk_runs()
                for row in bulk_rows:
                    bulk_run_id = str(row["id"])
                    runs = await self.db.get_runs_for_bulk(bulk_run_id)

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
                                updated_r = await self.db.get_run(r_id)
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
                    await self.db.update_bulk_run_stats(
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
        await self.db.cancel_bulk_run(bulk_run_id)
