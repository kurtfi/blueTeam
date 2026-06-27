import os
import tempfile
import argparse
from unittest.mock import MagicMock, AsyncMock, patch
import pytest

from dataset_ingestor.loader.dag_loader import resolve_log_path
from dataset_ingestor.ingestion import IngestionService
from dataset_ingestor.cli import ingest_command, confirm_prompt


def test_resolve_log_path_with_scenario_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a scenario directory
        scenario_dir = os.path.join(tmpdir, "scenarios")
        os.makedirs(scenario_dir, exist_ok=True)
        
        # Create a dummy log file in the scenario directory
        log_file = os.path.join(scenario_dir, "attack_logs.zip")
        with open(log_file, "w") as f:
            f.write("dummy log data")
            
        # Resolve path relative to scenario_dir
        resolved = resolve_log_path("attack_logs.zip", data_dir=tmpdir, scenario_dir=scenario_dir)
        assert resolved == os.path.abspath(log_file)


@patch("dataset_ingestor.loader.metadata.ScenarioMetadataReader.read_metadata")
@patch("dataset_ingestor.loader.factory.DatasetLoaderFactory.get_loader")
def test_prepare_scenario_payload_mitre_ids_override(mock_get_loader, mock_read_metadata):
    # Mock metadata
    mock_read_metadata.return_value = {
        "name": "Test Scenario",
        "description": "Test description",
        "mitre_ids": ["T1059"],
    }
    
    # Mock loader
    mock_loader = MagicMock()
    mock_loader.load.return_value = iter([
        {
            "EventID": 1,
            "CommandLine": "cmd.exe /c whoami",
        }
    ])
    mock_get_loader.return_value = mock_loader
    
    service = IngestionService()
    
    # Ingest with overridden mitre_ids
    with tempfile.NamedTemporaryFile(suffix=".zip") as tmp:
        payload = service.prepare_scenario_payload(
            path=tmp.name,
            source_type="mordor",
            mitre_ids=["T1003.001"],
        )
        
        assert "T1003.001" in payload["mitre_ids"]


def test_confirm_prompt_yes():
    with patch("sys.stdin.readline", return_value="yes\n"):
        assert confirm_prompt("Prompt: ") is True
        
    with patch("sys.stdin.readline", return_value="y\n"):
        assert confirm_prompt("Prompt: ") is True


def test_confirm_prompt_no():
    with patch("sys.stdin.readline", return_value="no\n"):
        assert confirm_prompt("Prompt: ") is False
        
    with patch("sys.stdin.readline", return_value="\n"):
        assert confirm_prompt("Prompt: ", default=False) is False
