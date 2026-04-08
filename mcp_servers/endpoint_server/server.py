"""
mcp_servers/endpoint_server/server.py

MCP Server 3: Endpoint Process Telemetry
Role: Ingests process creation/termination events and answers queries like:
      "What child processes did AcroRd32.exe spawn in the last 5 minutes?"

In production: connects to Sysmon Event ID 1 logs, EDR API, or osquery.
In prototype:  accepts POST events + stores in-memory, queryable by parent PID/name.

Input (ingest):  ProcessEvent
Input (query):   { "parent_name": "AcroRd32.exe", "window_seconds": 300 }
Output (query):  list[ProcessEvent]
"""
from datetime import datetime, timedelta
from fastapi import FastAPI
from pydantic import BaseModel
from models.schemas import ProcessEvent
from utils.helpers import is_suspicious_child
from utils.logger import get_logger

log = get_logger("endpoint_server")
app = FastAPI(title="Endpoint Telemetry MCP Server")

# In-memory event store (replace with DB or Kafka consumer in production)
_process_events: list[ProcessEvent] = []


@app.post("/ingest/process")
async def ingest_process_event(event: ProcessEvent):
    """Receive a process event from an agent/sensor."""
    _process_events.append(event)
    log.info(f"Process event: {event.parent_name} -> {event.name} (pid={event.pid})")
    return {"status": "ingested"}


class ProcessQuery(BaseModel):
    parent_name: str = ""
    parent_pid: int = 0
    user: str = ""
    host: str = ""
    window_seconds: int = 300


@app.post("/query/children", response_model=list[ProcessEvent])
async def query_child_processes(q: ProcessQuery) -> list[ProcessEvent]:
    """
    Return child processes matching the query within the time window.
    Used by the MCP client to find what a PDF reader spawned.
    """
    cutoff = datetime.utcnow() - timedelta(seconds=q.window_seconds)
    results = []
    for ev in _process_events:
        if ev.timestamp < cutoff:
            continue
        if q.parent_name and q.parent_name.lower() not in ev.parent_name.lower():
            continue
        if q.parent_pid and ev.parent_pid != q.parent_pid:
            continue
        if q.user and ev.user != q.user:
            continue
        if q.host and ev.host != q.host:
            continue
        results.append(ev)

    log.info(f"Process query for parent={q.parent_name}: {len(results)} results")
    return results


@app.post("/query/suspicious", response_model=list[ProcessEvent])
async def query_suspicious_processes(q: ProcessQuery) -> list[ProcessEvent]:
    """Return only suspicious child processes (powershell, cmd, etc.)."""
    all_children = await query_child_processes(q)
    return [ev for ev in all_children if is_suspicious_child(ev.name)]


@app.post("/seed/mock")
async def seed_mock_events():
    """Seed mock process events for demo/testing."""
    now = datetime.utcnow()
    mock = [
        ProcessEvent(
            pid=1234, name="AcroRd32.exe", cmdline="AcroRd32.exe invoice_q2.pdf",
            parent_pid=999, parent_name="explorer.exe",
            user="jdoe", host="WORKSTATION-01", timestamp=now,
        ),
        ProcessEvent(
            pid=1235, name="powershell.exe",
            cmdline="powershell -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdA==",
            parent_pid=1234, parent_name="AcroRd32.exe",
            user="jdoe", host="WORKSTATION-01", timestamp=now,
        ),
        ProcessEvent(
            pid=1236, name="cmd.exe", cmdline="cmd.exe /c copy temp.exe %APPDATA%",
            parent_pid=1235, parent_name="powershell.exe",
            user="jdoe", host="WORKSTATION-01", timestamp=now,
        ),
    ]
    _process_events.extend(mock)
    return {"status": "seeded", "count": len(mock)}


@app.get("/health")
async def health():
    return {"status": "ok", "server": "endpoint_telemetry", "events_stored": len(_process_events)}
