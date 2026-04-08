#!/usr/bin/env python3
"""
run_all.py
Starts the FastAPI orchestrator API (port 8000).

MCP servers are no longer long-running HTTP processes.
They are spawned on-demand as stdio subprocesses by the MCP client
when the pipeline runs, then terminated automatically.

Usage:
  python run_all.py
"""
import subprocess
import sys
import signal
import os

proc = None


def shutdown(sig, frame):
    print("\nShutting down...")
    if proc:
        proc.terminate()
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    print("Starting MCP PDF Attack Chain Intelligence System")
    print("=" * 55)
    print("MCP servers: spawned on-demand via stdio (no ports needed)")
    print("Starting orchestrator API on port 8000...")

    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "api.main:app",
         "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"],
        cwd=os.path.dirname(os.path.abspath(__file__)),
    )

    print("=" * 55)
    print("Orchestrator API: http://localhost:8000")
    print("API Docs:         http://localhost:8000/docs")
    print("Health check:     http://localhost:8000/health")
    print("Press Ctrl+C to stop")
    print("=" * 55)

    proc.wait()
