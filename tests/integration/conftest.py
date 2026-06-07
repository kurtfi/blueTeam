"""
conftest.py — shared pytest fixtures for the Agentix test suite.

Cache isolation
---------------
Connector modules cache client/engine instances in module-level dicts to avoid
reconnecting on every call.  Without cleanup, a connection mock from one test
can leak into the next.

The ``clear_connector_caches`` fixture resets all caches after every test,
ensuring complete isolation between test cases.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
async def clear_connector_caches():
    """
    Reset all module-level connector caches after each test.

    This fixture runs for *every* test automatically (autouse=True).
    It yields first (allowing the test to execute), then clears the caches.
    """
    yield  # --- test runs here ---

    # Data connector caches
    try:
        from general_mcp.tools.data.connectors.data_server import _sql_engines

        _sql_engines.clear()
    except (ImportError, AttributeError):
        pass

    try:
        from general_mcp.tools.data.connectors import mongodb_connector

        mongodb_connector._clients.clear()
    except (ImportError, AttributeError):
        pass

    try:
        from general_mcp.tools.data.connectors import redis_connector

        redis_connector._clients.clear()
    except (ImportError, AttributeError):
        pass

    try:
        from general_mcp.tools.data.connectors import elasticsearch_connector

        elasticsearch_connector._clients.clear()
    except (ImportError, AttributeError):
        pass

    try:
        from general_mcp.tools.data.connectors import neo4j_connector

        neo4j_connector._drivers.clear()
    except (ImportError, AttributeError):
        pass
