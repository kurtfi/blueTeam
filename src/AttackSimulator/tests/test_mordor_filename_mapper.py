"""
Unit tests for mordor_filename mapper.
"""

from attack_simulator.mapper.mordor_filename import extract_technique_from_path


def test_static_mappings() -> None:
    assert extract_technique_from_path("cmd_lsass_memory_dumpert.zip") == "T1003.001"
    assert extract_technique_from_path("/some/path/cmd_sam_copy_esentutl.zip") == "T1003.002"
    assert extract_technique_from_path("covenant_wmi_wbemcomn_dll_hijack.zip") == "T1047"



def test_regex_matching() -> None:
    # Explicit T-ID in file name
    assert extract_technique_from_path("attack_T1110_simulation.zip") == "T1110"
    assert extract_technique_from_path("some_t1003.001_logs.json") == "T1003.001"


def test_tactic_fallback() -> None:
    # Folders inside path
    assert extract_technique_from_path("datasets/small/windows/credential_access/host/unknown.zip") == "T1003"
    assert extract_technique_from_path("datasets/small/windows/lateral_movement/network/pcap.zip") == "T1021"
