"""
Entry point for the Agentix platform.

Runs the Agentix FastAPI streaming app via Uvicorn.
"""

from __future__ import annotations

import sys

import uvicorn

if __name__ == "__main__":
    print("Starting Agentix API Server...")
    print("Access the API docs at http://127.0.0.1:8000/docs")

    # Run the Uvicorn server referencing the FastAPI app object
    uvicorn.run(
        "agentix.api.server:app",
        host="0.0.0.0",
        port=8000,
        reload="--reload" in sys.argv,
    )
