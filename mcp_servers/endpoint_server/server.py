"""
mcp_servers/endpoint_server/server.py
MCP Server 3: Endpoint Process Telemetry — real MCP SDK (stdio transport)
Tools: ingest_process_event, query_child_processes, seed_mock_processes
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import json
from datetime import datetime, timedelta
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
from models.schemas import ProcessEvent
from utils.helpers import is_suspicious_child
from utils.logger import get_logger

log = get_logger("endpoint_server")
server = Server("endpoint-server")

_process_events: list[ProcessEvent] = []


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="ingest_process_event",
            description="Ingest a process creation event",
            inputSchema={"type": "object", "properties": {"event": {"type": "object"}}, "required": ["event"]},
        ),
        Tool(
            name="query_child_processes",
            description="Query child processes spawned by a parent within a time window",
            inputSchema={
                "type": "object",
                "properties": {
                    "parent_name": {"type": "string", "default": ""},
                    "user": {"type": "string", "default": ""},
                    "host": {"type": "string", "default": ""},
                    "window_seconds": {"type": "integer", "default": 300},
                },
            },
        ),
        Tool(
            name="seed_mock_processes",
            description="Seed mock process events for demo/testing",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "ingest_process_event":
        ev = ProcessEvent(**arguments["event"])
        _process_events.append(ev)
        return [TextContent(type="text", text=json.dumps({"status": "ingested"}))]

    elif name == "query_child_processes":
        cutoff = datetime.utcnow() - timedelta(seconds=arguments.get("window_seconds", 300))
        parent = arguments.get("parent_name", "").lower()
        user = arguments.get("user", "")
        host = arguments.get("host", "")
        results = [
            ev for ev in _process_events
            if ev.timestamp >= cutoff
            and (not parent or parent in ev.parent_name.lower())
            and (not user or ev.user == user)
            and (not host or ev.host == host)
        ]
        return [TextContent(type="text", text=json.dumps([e.model_dump(mode="json") for e in results]))]

    elif name == "seed_mock_processes":
        now = datetime.utcnow()
        mock = [
            ProcessEvent(pid=1234, name="AcroRd32.exe", cmdline="AcroRd32.exe invoice_q2.pdf",
                         parent_pid=999, parent_name="explorer.exe",
                         user="jdoe", host="WORKSTATION-01", timestamp=now),
            ProcessEvent(pid=1235, name="powershell.exe",
                         cmdline="powershell -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdA==",
                         parent_pid=1234, parent_name="AcroRd32.exe",
                         user="jdoe", host="WORKSTATION-01", timestamp=now),
            ProcessEvent(pid=1236, name="cmd.exe", cmdline="cmd.exe /c copy temp.exe %APPDATA%",
                         parent_pid=1235, parent_name="powershell.exe",
                         user="jdoe", host="WORKSTATION-01", timestamp=now),
        ]
        _process_events.extend(mock)
        return [TextContent(type="text", text=json.dumps({"status": "seeded", "count": len(mock)}))]

    raise ValueError(f"Unknown tool: {name}")


async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
