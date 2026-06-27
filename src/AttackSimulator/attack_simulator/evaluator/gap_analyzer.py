"""
Computes and reports playbook coverage gaps for simulated MITRE techniques.
"""

from typing import Any

import structlog
from attack_simulator.repository import db_repo

from agentic_common.mapper.mitre_catalog import MITRE_CATALOG, get_mitre_info

logger = structlog.get_logger(__name__)


async def get_registered_playbooks_coverage() -> dict[str, list[dict[str, Any]]]:
    """
    Fetches all registered playbooks and groups them by covered MITRE techniques.
    """
    coverage: dict[str, list[dict[str, Any]]] = {}
    try:
        from triage_core.playbooks import registry as pb_registry

        playbooks = pb_registry.list_all()
        for pb in playbooks:
            for mitre_id in pb.get("mitre_ids", []):
                mid = mitre_id.upper().strip()
                coverage.setdefault(mid, []).append(pb)
    except Exception as e:
        logger.error("evaluator.gap_analyzer.registry_error", error=str(e))
    return coverage


async def generate_coverage_report() -> dict[str, Any]:
    """
    Compares simulated techniques in PostgreSQL against registered playbooks to identify gaps.
    """
    # 1. Get playbook coverage
    playbook_coverage = await get_registered_playbooks_coverage()

    # 2. Get all techniques used in ingested simulation events
    pool = await db_repo.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT DISTINCT mitre_technique FROM attack_events")
        simulated_techniques = [row["mitre_technique"].upper().strip() for row in rows]

    # 3. Categorize simulated techniques
    covered_simulated = []
    uncovered_simulated = []

    for tech in simulated_techniques:
        # Check direct or parent matching (e.g. T1003.001 -> T1003)
        matching_pbs = playbook_coverage.get(tech, [])
        if not matching_pbs and "." in tech:
            parent_id = tech.split(".")[0]
            matching_pbs = playbook_coverage.get(parent_id, [])

        if matching_pbs:
            covered_simulated.append(
                {"technique_id": tech, "info": get_mitre_info(tech), "playbooks": [pb["id"] for pb in matching_pbs]}
            )
        else:
            uncovered_simulated.append({"technique_id": tech, "info": get_mitre_info(tech)})

    # 4. Check general catalog coverage gaps
    all_catalog_gaps = []
    for tech_id in MITRE_CATALOG.keys():
        if tech_id not in playbook_coverage:
            # Check parent matching
            if "." in tech_id:
                parent_id = tech_id.split(".")[0]
                if parent_id in playbook_coverage:
                    continue
            all_catalog_gaps.append({"technique_id": tech_id, "info": MITRE_CATALOG[tech_id]})

    report = {
        "total_playbooks": len(set(pb["id"] for pbs in playbook_coverage.values() for pb in pbs)),
        "simulated_count": len(simulated_techniques),
        "covered_simulated": covered_simulated,
        "uncovered_simulated": uncovered_simulated,
        "catalog_gaps": all_catalog_gaps,
    }

    return report


def print_ascii_gap_report(report: dict[str, Any]) -> None:
    """
    Prints a beautiful ASCII table format of the gap report to stdout.
    """
    print("\n" + "=" * 80)
    print("                    AGENTIX PLAYBOOK COVERAGE GAP REPORT")
    print("=" * 80)
    print(f"Total Registered Playbooks: {report['total_playbooks']}")
    print(f"Simulated MITRE Techniques: {report['simulated_count']}")
    print("-" * 80)

    print(f"\n[+] COVERED SIMULATED TECHNIQUES ({len(report['covered_simulated'])}):")
    if not report["covered_simulated"]:
        print("  None")
    else:
        print(f"  {'Technique ID':<15} | {'Technique Name':<35} | {'Playbooks':<20}")
        print("  " + "-" * 76)
        for item in report["covered_simulated"]:
            pbs = ", ".join(item["playbooks"])
            print(f"  {item['technique_id']:<15} | {item['info']['name'][:35]:<35} | {pbs:<20}")

    print(f"\n[-] UNCOVERED SIMULATED TECHNIQUES (GAPS) ({len(report['uncovered_simulated'])}):")
    if not report["uncovered_simulated"]:
        print("  None (100% Coverage of simulated techniques!)")
    else:
        print(f"  {'Technique ID':<15} | {'Technique Name':<35} | {'Tactic':<20}")
        print("  " + "-" * 76)
        for item in report["uncovered_simulated"]:
            print(f"  {item['technique_id']:<15} | {item['info']['name'][:35]:<35} | {item['info']['tactic']:<20}")

    print("\n" + "=" * 80)
