"""
mcp_servers/filesystem_server/server.py

MCP Server 4: File System Telemetry
Role: Tracks file create/write/execute events.
      Answers: "What files did powershell.exe drop in the last 5 minutes?"

In production: Sysmon Event ID 11 (FileCreate), EDR file events, auditd.
In prototype:  in-memory store + mock seeding.

Key detection signals:
  - Executable dropped in Temp/AppData by a script process
  - File written then immediately executed
  - Renamed files (extension mismatch)
"""
from datetime import datetime, timedelta
from fastapi import FastAPI
from pydantic import BaseModel
from models.schemas import FileEvent
from utils.helpers import is_suspicious_path, classify_file_extension
from utils.logger import get_logger

log = get_logger("filesystem_server")
app = FastAPI(title="File System Telemetry MCP Server")

_file_events: list[FileEvent] = []


@app.post("/ingest/file")
async def ingest_file_event(event: FileEvent):
    _file_events.append(event)
    log.info(f"File event: {event.operation} {event.path} by {event.process_name}")
    return {"status": "ingested"}


class FileQuery(BaseModel):
    process_name: str = ""
    process_pid: int = 0
    operation: str = ""         # create | write | execute | ""
    user: str = ""
    host: str = ""
    window_seconds: int = 300
    suspicious_only: bool = False


@app.post("/query/drops", response_model=list[FileEvent])
async def query_file_drops(q: FileQuery) -> list[FileEvent]:
    """
    Return file events matching the query.
    With suspicious_only=True, filters to executables dropped in suspicious paths.
    """
    cutoff = datetime.utcnow() - timedelta(seconds=q.window_seconds)
    results = []
    for ev in _file_events:
        if ev.timestamp < cutoff:
            continue
        if q.process_name and q.process_name.lower() not in ev.process_name.lower():
            continue
        if q.process_pid and ev.process_pid != q.process_pid:
            continue
        if q.operation and ev.operation != q.operation:
            continue
        if q.user and ev.user != q.user:
            continue
        if q.host and ev.host != q.host:
            continue
        if q.suspicious_only:
            if not (is_suspicious_path(ev.path) and classify_file_extension(ev.path) == "executable"):
                continue
        results.append(ev)
    return results


@app.post("/seed/mock")
async def seed_mock_events():
    now = datetime.utcnow()
    mock = [
        FileEvent(
            path="C:\\Users\\jdoe\\AppData\\Local\\Temp\\temp.exe",
            operation="create",
            process_name="powershell.exe", process_pid=1235,
            user="jdoe", host="WORKSTATION-01",
            timestamp=now, file_hash="cafebabe1234",
        ),
        FileEvent(
            path="C:\\Users\\jdoe\\AppData\\Local\\Temp\\temp.exe",
            operation="execute",
            process_name="cmd.exe", process_pid=1236,
            user="jdoe", host="WORKSTATION-01",
            timestamp=now, file_hash="cafebabe1234",
        ),
    ]
    _file_events.extend(mock)
    return {"status": "seeded", "count": len(mock)}


@app.get("/health")
async def health():
    return {"status": "ok", "server": "filesystem_telemetry", "events_stored": len(_file_events)}
