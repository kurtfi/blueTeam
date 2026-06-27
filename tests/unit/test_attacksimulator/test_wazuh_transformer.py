"""
Unit tests for alert transformer and wazuh alert payload generator.
"""

from agentic_common.mapper.wazuh_template import generate_wazuh_alert


def test_alert_generation_default() -> None:
    raw_event = {
        "EventID": 10,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "IpAddress": "192.168.1.100",
        "User": "Administrator",
        "CommandLine": "rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 1234 C:\\lsass.dmp",
        "Image": "C:\\windows\\System32\\rundll32.exe",
    }

    alert = generate_wazuh_alert("T1003.001", raw_event)

    # Assert top-level fields
    assert "@timestamp" in alert
    assert alert["agent"]["name"] == "client-workstation-01"

    # Assert rule matching details
    assert alert["rule"]["id"] == "100002"
    assert alert["rule"]["level"] == 12
    assert "T1003.001" in alert["rule"]["mitre"]["id"]

    # Assert structured data fields
    assert alert["data"]["srcip"] == "192.168.1.100"
    assert alert["data"]["dstuser"] == "Administrator"
    assert alert["data"]["command"] == raw_event["CommandLine"]
    assert alert["data"]["process"] == raw_event["Image"]
