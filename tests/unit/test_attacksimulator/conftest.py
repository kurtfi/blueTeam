import uuid
from datetime import datetime, UTC
from typing import Any

from attack_simulator.repository.postgres import DatabaseRepository
from agentic_common.memory.postgres_session import PostgresSessionRepository


class MockConnection:
    def __init__(self, repo):
        self.repo = repo

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

    async def execute(self, query, *args):
        # We know the query here is the UPDATE query:
        # UPDATE simulator.simulation_results
        # SET expected_playbook = $2, actual_playbook = $3, match_result = $4
        # WHERE id = $1
        # args = (res_uuid, expected_pb, actual_pb, match_result)
        if len(args) == 4:
            res_id, expected_pb, actual_pb, match_result = args
            res = self.repo.results.get(str(res_id))
            if res:
                res["expected_playbook"] = expected_pb
                res["actual_playbook"] = actual_pb
                res["match_result"] = match_result

    def transaction(self):
        return self


class InMemoryDatabaseRepository(DatabaseRepository):
    def __init__(self):
        self.scenarios = {}
        self.events = {}
        self.runs = {}
        self.results = {}
        self.bulk_runs = {}
        self._pool = None

    async def get_pool(self):
        return self

    def acquire(self):
        return MockConnection(self)

    async def create_scenario(
        self,
        name,
        description,
        mitre_ids,
        source_dataset,
        source_path,
        total_events=0,
        status="passive",
        type="linear",
        dag_structure=None,
    ):
        scenario_id = str(uuid.uuid4())
        self.scenarios[scenario_id] = {
            "id": scenario_id,
            "name": name,
            "description": description,
            "mitre_ids": mitre_ids,
            "source_dataset": source_dataset,
            "source_path": source_path,
            "total_events": total_events,
            "status": status,
            "type": type,
            "dag_structure": dag_structure,
            "created_at": datetime.now(),
        }
        self.events[scenario_id] = []
        return scenario_id

    async def get_scenario_by_name(self, name):
        for s in self.scenarios.values():
            if s["name"] == name:
                return s
        return None

    async def get_scenario_by_path(self, source_path):
        for s in self.scenarios.values():
            if s["source_path"] == source_path:
                return s
        return None

    async def get_scenario_by_id(self, scenario_id):
        return self.scenarios.get(str(scenario_id))

    async def get_scenario_events(self, scenario_id):
        return self.events.get(str(scenario_id), [])

    async def insert_attack_events(self, events_list, status="passive"):
        for ev in events_list:
            sc_id = str(ev["scenario_id"])
            ev_copy = dict(ev)
            ev_copy["id"] = str(uuid.uuid4())
            ev_copy["status"] = status
            if sc_id not in self.events:
                self.events[sc_id] = []
            self.events[sc_id].append(ev_copy)

    async def activate_scenario(self, scenario_id):
        for sid, s in self.scenarios.items():
            if sid == str(scenario_id):
                s["status"] = "active"
                for ev in self.events.get(sid, []):
                    ev["status"] = "active"
            else:
                s["status"] = "passive"
                for ev in self.events.get(sid, []):
                    ev["status"] = "passive"

    async def list_scenarios(self):
        return list(self.scenarios.values())

    async def delete_scenario(self, scenario_id):
        self.scenarios.pop(str(scenario_id), None)
        self.events.pop(str(scenario_id), None)

    async def create_run(self, scenario_id, total_events, send_rate_per_sec, bulk_run_id=None):
        run_id = str(uuid.uuid4())
        self.runs[run_id] = {
            "id": run_id,
            "scenario_id": str(scenario_id),
            "status": "PENDING",
            "total_events": total_events,
            "sent_events": 0,
            "matched_playbooks": 0,
            "mismatched_playbooks": 0,
            "no_playbook": 0,
            "send_rate_per_sec": send_rate_per_sec,
            "bulk_run_id": bulk_run_id,
            "started_at": datetime.now(),
            "completed_at": None,
            "traversed_path": None,
        }
        return run_id

    async def get_run(self, run_id):
        return self.runs.get(str(run_id))

    async def update_run_stats(
        self, run_id, status, sent_events, matched_playbooks=0, mismatched_playbooks=0, no_playbook=0
    ):
        run = self.runs.get(str(run_id))
        if run:
            run["status"] = status
            run["sent_events"] = sent_events
            run["matched_playbooks"] = matched_playbooks
            run["mismatched_playbooks"] = mismatched_playbooks
            run["no_playbook"] = no_playbook
            if status in ("COMPLETED", "FAILED"):
                run["completed_at"] = datetime.now()

    async def update_run_path(self, run_id, traversed_path):
        run = self.runs.get(str(run_id))
        if run:
            run["traversed_path"] = traversed_path

    async def create_bulk_run(self, name, llm_provider, llm_model, strip_labels, send_rate_per_sec, total_scenarios):
        bulk_run_id = str(uuid.uuid4())
        self.bulk_runs[bulk_run_id] = {
            "id": bulk_run_id,
            "name": name,
            "llm_provider": llm_provider,
            "llm_model": llm_model,
            "strip_labels": strip_labels,
            "send_rate_per_sec": send_rate_per_sec,
            "total_scenarios": total_scenarios,
            "completed_scenarios": 0,
            "status": "RUNNING",
            "matched_playbooks": 0,
            "mismatched_playbooks": 0,
            "no_playbook": 0,
            "started_at": datetime.now(),
            "completed_at": None,
        }
        return bulk_run_id

    async def get_bulk_run(self, bulk_run_id):
        return self.bulk_runs.get(str(bulk_run_id))

    async def get_bulk_run_status(self, bulk_run_id):
        br = self.bulk_runs.get(str(bulk_run_id))
        return br["status"] if br else None

    async def cancel_bulk_run(self, bulk_run_id):
        br = self.bulk_runs.get(str(bulk_run_id))
        if br:
            runs = await self.get_runs_for_bulk(bulk_run_id)
            completed_scenarios = 0
            matched = 0
            mismatched = 0
            nobook = 0
            for r in runs:
                if r["status"] in ("COMPLETED", "FAILED"):
                    completed_scenarios += 1
                    matched += r.get("matched_playbooks", 0)
                    mismatched += r.get("mismatched_playbooks", 0)
                    nobook += r.get("no_playbook", 0)

            final_status = "PARTIALLY_COMPLETED" if completed_scenarios > 0 else "CANCELLED"
            br["status"] = final_status
            br["completed_scenarios"] = completed_scenarios
            br["matched_playbooks"] = matched
            br["mismatched_playbooks"] = mismatched
            br["no_playbook"] = nobook
            br["completed_at"] = datetime.now()

    async def get_runs_for_bulk(self, bulk_run_id):
        return [r for r in self.runs.values() if r.get("bulk_run_id") == str(bulk_run_id)]

    async def update_bulk_run_stats(self, bulk_run_id, status, completed_scenarios, matched, mismatched, no_playbook):
        br = self.bulk_runs.get(str(bulk_run_id))
        if br:
            br["status"] = status
            br["completed_scenarios"] = completed_scenarios
            br["matched_playbooks"] = matched
            br["mismatched_playbooks"] = mismatched
            br["no_playbook"] = no_playbook
            if status in ("COMPLETED", "FAILED", "CANCELLED", "PARTIALLY_COMPLETED"):
                br["completed_at"] = datetime.now()

    async def get_active_bulk_runs(self):
        return [br for br in self.bulk_runs.values() if br["status"] == "RUNNING"]

    async def insert_simulation_result(
        self,
        run_id,
        event_id,
        session_id,
        expected_mitre,
        expected_playbook,
        actual_playbook=None,
        match_result="PENDING",
        response_time_ms=None,
    ):
        res_id = str(uuid.uuid4())
        self.results[res_id] = {
            "id": res_id,
            "run_id": str(run_id),
            "event_id": str(event_id) if event_id else None,
            "session_id": session_id,
            "expected_mitre": expected_mitre,
            "expected_playbook": expected_playbook,
            "actual_playbook": actual_playbook,
            "match_result": match_result,
            "response_time_ms": response_time_ms,
        }
        return res_id

    async def get_scenario_total_events(self, scenario_id):
        sc = self.scenarios.get(str(scenario_id))
        return sc["total_events"] if sc else None

    async def get_run_results(self, run_id: str) -> list[dict[str, Any]]:
        run_id_str = str(run_id)
        out = []
        for res in self.results.values():
            if res["run_id"] == run_id_str:
                res_copy = dict(res)
                expected = res.get("expected_mitre")
                res_copy["mitre_technique"] = expected[0] if expected else None
                res_copy["sequence_order"] = 0
                out.append(res_copy)
        return out

    async def get_active_simulation_runs(self) -> list[str]:
        return [r["id"] for r in self.runs.values() if r["status"] in ("PENDING", "RUNNING")]

    async def get_latest_runs(self, limit: int = 10) -> list[dict[str, Any]]:
        runs = list(self.runs.values())
        runs.sort(key=lambda x: x.get("started_at", datetime.min), reverse=True)
        return runs[:limit]

    async def get_bulk_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        brs = list(self.bulk_runs.values())
        brs.sort(key=lambda x: x.get("started_at", datetime.min), reverse=True)
        return brs[:limit]

    async def update_simulation_result_actual(
        self, result_id: str, actual_playbook: str | None, match_result: str, response_time_ms: int | None = None
    ) -> None:
        res = self.results.get(str(result_id))
        if res:
            res["actual_playbook"] = actual_playbook
            res["match_result"] = match_result
            res["response_time_ms"] = response_time_ms

    async def close(self):
        pass


class InMemoryPostgresSessionRepository(PostgresSessionRepository):
    def __init__(self):
        self.sessions = {}
        self.events = {}
        self._pool = None

    async def get_pool(self):
        return self

    async def run_migrations(self):
        pass

    async def create_session(
        self,
        *,
        display_name,
        source,
        owner_id="anonymous",
        agent_name=None,
        siem_rule_id=None,
        siem_rule_desc=None,
        siem_severity=None,
        source_ip=None,
        mitre_ids=None,
        alert_payload=None,
        session_id=None,
    ):
        sess_id = session_id or str(uuid.uuid4())
        self.sessions[sess_id] = {
            "id": uuid.UUID(sess_id),
            "display_name": display_name,
            "source": source,
            "owner_id": owner_id,
            "agent_name": agent_name,
            "siem_rule_id": siem_rule_id,
            "siem_rule_desc": siem_rule_desc,
            "siem_severity": siem_severity,
            "source_ip": source_ip,
            "mitre_ids": mitre_ids,
            "alert_payload": alert_payload,
            "status": "ACTIVE",
            "created_at": datetime.now(UTC),
            "updated_at": datetime.now(UTC),
            "completed_at": None,
            "verdict": None,
        }
        self.events[sess_id] = []
        return sess_id

    async def get_session(self, session_id):
        return self.sessions.get(session_id)

    async def get_events(self, session_id):
        return self.events.get(session_id, [])

    async def add_event(self, session_id, event_type, actor, content=None, metadata=None):
        event = {
            "session_id": session_id,
            "event_type": event_type,
            "actor": actor,
            "content": content,
            "metadata": metadata,
            "created_at": datetime.now(UTC),
        }
        if session_id not in self.events:
            self.events[session_id] = []
        self.events[session_id].append(event)

    async def update_status(self, session_id, status, verdict=None):
        if session_id in self.sessions:
            self.sessions[session_id]["status"] = status
            if verdict:
                self.sessions[session_id]["verdict"] = verdict
            if status in ("COMPLETED", "FAILED", "ARCHIVED"):
                self.sessions[session_id]["completed_at"] = datetime.now(UTC)

    async def update_stats(self, session_id, **kwargs):
        pass

    async def increment_stats(self, session_id, **kwargs):
        pass

    async def close(self):
        pass


from attack_simulator.repository import db_repo
from agentic_common.memory import postgres_session_repo

# Class swapping singletons to in-memory mocks
db_repo.__class__ = InMemoryDatabaseRepository
InMemoryDatabaseRepository.__init__(db_repo)

postgres_session_repo.__class__ = InMemoryPostgresSessionRepository
InMemoryPostgresSessionRepository.__init__(postgres_session_repo)
