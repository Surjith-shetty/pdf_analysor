#!/usr/bin/env python3
"""
run_all.py
Launches all MCP servers + the orchestrator API in separate processes.
Use this for local development and demo.

Usage:
  python run_all.py

Each server runs on its configured port (see .env).
Press Ctrl+C to stop all servers.
"""
import subprocess
import sys
import time
import signal
import os

SERVERS = [
    # (module_path, port, name)
    ("mcp_servers.email_server.server:app", 8001, "email_server"),
    ("mcp_servers.pdf_server.server:app", 8002, "pdf_server"),
    ("mcp_servers.endpoint_server.server:app", 8003, "endpoint_server"),
    ("mcp_servers.filesystem_server.server:app", 8004, "filesystem_server"),
    ("mcp_servers.network_server.server:app", 8005, "network_server"),
    ("mcp_servers.threatintel_server.server:app", 8006, "threatintel_server"),
    ("mcp_servers.response_server.server:app", 8007, "response_server"),
    ("mcp_servers.memory_server.server:app", 8008, "memory_server"),
    ("api.main:app", 8000, "orchestrator"),
]

processes = []


def start_server(module: str, port: int, name: str) -> subprocess.Popen:
    cmd = [
        sys.executable, "-m", "uvicorn",
        module,
        "--host", "0.0.0.0",
        "--port", str(port),
        "--log-level", "warning",
    ]
    proc = subprocess.Popen(cmd, cwd=os.path.dirname(os.path.abspath(__file__)))
    print(f"  ✓ {name} started on port {port} (pid={proc.pid})")
    return proc


def shutdown(sig, frame):
    print("\nShutting down all servers...")
    for p in processes:
        p.terminate()
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    print("Starting MCP PDF Attack Chain Intelligence System")
    print("=" * 55)

    for module, port, name in SERVERS:
        proc = start_server(module, port, name)
        processes.append(proc)
        time.sleep(0.3)  # stagger startup

    print("=" * 55)
    print(f"Orchestrator API: http://localhost:8000")
    print(f"API Docs:         http://localhost:8000/docs")
    print(f"Health check:     http://localhost:8000/health")
    print("Press Ctrl+C to stop all servers")
    print("=" * 55)

    # Keep alive
    while True:
        time.sleep(1)
        # Restart any crashed servers
        for i, (module, port, name) in enumerate(SERVERS):
            if processes[i].poll() is not None:
                print(f"  ⚠ {name} crashed, restarting...")
                processes[i] = start_server(module, port, name)
