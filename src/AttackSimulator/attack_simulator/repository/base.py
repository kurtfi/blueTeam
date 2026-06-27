"""
Abstract boundary representing database access for Simulation Service.
"""

import uuid
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class SimulationRepository(Protocol):
    """
    Interface/boundary for database operations required by SimulationService.
    """

    async def get_scenario_by_name(self, name: str) -> dict[str, Any] | None:
        """Retrieve a scenario by its unique name."""
        ...

    async def get_scenario_events(self, scenario_id: str) -> list[dict[str, Any]]:
        """Retrieve all events associated with a scenario, ordered by sequence."""
        ...

    async def create_run(
        self, scenario_id: str, total_events: int, send_rate_per_sec: float, bulk_run_id: str | None = None
    ) -> str:
        """Create a new simulation run record."""
        ...

    async def insert_simulation_result(
        self,
        run_id: str,
        event_id: str | None,
        session_id: str | None,
        expected_mitre: list[str],
        expected_playbook: str | None,
        actual_playbook: str | None = None,
        match_result: str = "PENDING",
        response_time_ms: int | None = None,
    ) -> str:
        """Insert a result record for an individual alert playback."""
        ...

    async def update_run_stats(
        self,
        run_id: str,
        status: str,
        sent_events: int,
        matched_playbooks: int = 0,
        mismatched_playbooks: int = 0,
        no_playbook: int = 0,
    ) -> None:
        """Update telemetry stats for a simulation run."""
        ...

    async def update_run_path(self, run_id: str, traversed_path: list[str]) -> None:
        """Update the traversed path list in a DAG simulation run."""
        ...

    async def get_run(self, run_id: str) -> dict[str, Any] | None:
        """Retrieve a simulation run record by ID."""
        ...

    async def get_scenario_by_id(self, scenario_id: uuid.UUID) -> dict[str, Any] | None:
        """Retrieve a scenario record by ID."""
        ...

    async def create_bulk_run(
        self,
        name: str,
        llm_provider: str | None,
        llm_model: str | None,
        strip_labels: bool,
        send_rate_per_sec: float,
        total_scenarios: int,
    ) -> str:
        """Create a bulk simulation run record."""
        ...

    async def get_bulk_run_status(self, bulk_run_id: uuid.UUID) -> str | None:
        """Retrieve the status of a bulk run by ID."""
        ...

    async def get_scenario_total_events(self, scenario_id: uuid.UUID) -> int | None:
        """Retrieve the total event count for a scenario by ID."""
        ...

    async def get_active_bulk_runs(self) -> list[dict[str, Any]]:
        """Retrieve all currently active/running bulk runs."""
        ...

    async def get_runs_for_bulk(self, bulk_run_id: str) -> list[dict[str, Any]]:
        """Retrieve all simulation runs associated with a bulk run."""
        ...

    async def update_bulk_run_stats(
        self,
        bulk_run_id: str,
        status: str,
        completed_scenarios: int,
        matched: int,
        mismatched: int,
        nobook: int,
    ) -> None:
        """Update stats and status for a bulk run."""
        ...

    async def cancel_bulk_run(self, bulk_run_id: str) -> None:
        """Cancel an active bulk run and finalize its stats."""
        ...

    async def update_simulation_result_actual(
        self, result_id: str, actual_playbook: str | None, match_result: str
    ) -> None:
        """Update the actual playbook matched and verdict status for a simulation result."""
        ...
