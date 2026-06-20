"""
Domain-specific exceptions for AttackSimulator.
"""


class SimulatorException(Exception):
    """Base exception for all AttackSimulator errors."""

    pass


class ScenarioNotFoundError(SimulatorException):
    """Raised when a requested attack scenario cannot be found in the database."""

    pass


class DuplicateScenarioError(SimulatorException):
    """Raised when trying to ingest a scenario that already exists in the database."""

    pass


class IngestionError(SimulatorException):
    """Raised when the scenario ingestion process fails."""

    pass


class DatasetDownloadError(SimulatorException):
    """Raised when downloading a dataset from a remote URL fails."""

    pass
