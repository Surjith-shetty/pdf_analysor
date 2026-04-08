"""
mcp_servers/network_server/server.py

MCP Server 5: Network Telemetry
Role: Tracks outbound connections made by processes.
      Answers: "What IPs did temp.exe connect to?"

In production: Sysmon Event ID 3 (NetworkConnect), Zeek/Suricata logs, EDR.
In prototype:  in-memory store + mock seeding.

Key detection signals:
  - Executable in Temp connecting to external IP
  - Beaconing patterns (regular intervals)
  - Connections to known-bad IPs/domains
  - Unusual ports (4444, 1337, 8080 from non-browser)
"""
from datetime import datetime, timedelta
from fastapi import FastAPI
from pydantic import BaseModel
from models.schemas import NetworkEvent
from utils.logger import get_logger

log = get_logger("network_server")
app = FastAPI(title="Network Telemetry MCP Server")

_network_events: list[NetworkEvent] = []

# Ports commonly used by C2 frameworks
SUSPICIOUS_PORTS = {4444, 1337, 8080, 8443, 9001, 31337}


@app.post("/ingest/network")
async def ingest_network_event(event: NetworkEvent):
    _network_events.append(event)
    log.info(f"Network event: {event.process_name} -> {event.dst_ip}:{event.dst_port}")
    return {"status": "ingested"}


class NetworkQuery(BaseModel):
    process_name: str = ""
    process_pid: int = 0
    user: str = ""
    host: str = ""
    window_seconds: int = 300


@app.post("/query/connections", response_model=list[NetworkEvent])
async def query_connections(q: NetworkQuery) -> list[NetworkEvent]:
    cutoff = datetime.utcnow() - timedelta(seconds=q.window_seconds)
    results = []
    for ev in _network_events:
        if ev.timestamp < cutoff:
            continue
        if q.process_name and q.process_name.lower() not in ev.process_name.lower():
            continue
        if q.process_pid and ev.process_pid != q.process_pid:
            continue
        if q.user and ev.user != q.user:
            continue
        if q.host and ev.host != q.host:
            continue
        results.append(ev)
    return results


@app.post("/query/suspicious_connections", response_model=list[NetworkEvent])
async def query_suspicious_connections(q: NetworkQuery) -> list[NetworkEvent]:
    """Return connections on suspicious ports or from temp-path processes."""
    all_conns = await query_connections(q)
    return [
        ev for ev in all_conns
        if ev.dst_port in SUSPICIOUS_PORTS or not ev.dst_ip.startswith("10.")
    ]


@app.post("/seed/mock")
async def seed_mock_events():
    now = datetime.utcnow()
    mock = [
        NetworkEvent(
            src_ip="192.168.1.50", dst_ip="185.220.101.45", dst_port=4444,
            protocol="TCP", process_name="temp.exe", process_pid=1237,
            user="jdoe", host="WORKSTATION-01", timestamp=now,
            bytes_sent=1024, dns_query=None,
        ),
        NetworkEvent(
            src_ip="192.168.1.50", dst_ip="185.220.101.45", dst_port=443,
            protocol="TCP", process_name="temp.exe", process_pid=1237,
            user="jdoe", host="WORKSTATION-01", timestamp=now,
            bytes_sent=512, dns_query="c2.evil-domain.ru",
        ),
    ]
    _network_events.extend(mock)
    return {"status": "seeded", "count": len(mock)}


@app.get("/health")
async def health():
    return {"status": "ok", "server": "network_telemetry", "events_stored": len(_network_events)}
