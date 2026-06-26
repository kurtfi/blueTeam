"""
Domain-specific exceptions for AttackSimulator.
"""


class SimulatorException(Exception):
    """Base exception for all AttackSimulator errors."""

    pass


class ScenarioNotFoundError(SimulatorException):
    """Raised when a requested attack scenario cannot be found in the database."""

    pass

