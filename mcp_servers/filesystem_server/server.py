"""
mcp_servers/filesystem_server/server.py
MCP Server 4: File System Telemetry — real MCP SDK (stdio transport)
Tools: ingest_file_event, query_file_drops, seed_mock_files
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import json
from datetime import datetime, timedelta
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
from models.schemas import FileEvent
from utils.helpers import is_suspicious_path, classify_file_extension
from utils.logger import get_logger

log = get_logger("filesystem_server")
server = Server("filesystem-server")

_file_events: list[FileEvent] = []


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="ingest_file_event",
            description="Ingest a file system event",
            inputSchema={"type": "object", "properties": {"event": {"type": "object"}}, "required": ["event"]},
        ),
        Tool(
            name="query_file_drops",
            description="Query file drop/execute events within a time window",
            inputSchema={
                "type": "object",
                "properties": {
                    "user": {"type": "string", "default": ""},
                    "host": {"type": "string", "default": ""},
                    "window_seconds": {"type": "integer", "default": 300},
                    "suspicious_only": {"type": "boolean", "default": False},
                },
            },
        ),
        Tool(
            name="seed_mock_files",
            description="Seed mock file events for demo/testing",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "ingest_file_event":
        ev = FileEvent(**arguments["event"])
        _file_events.append(ev)
        return [TextContent(type="text", text=json.dumps({"status": "ingested"}))]

    elif name == "query_file_drops":
        cutoff = datetime.utcnow() - timedelta(seconds=arguments.get("window_seconds", 300))
        user = arguments.get("user", "")
        host = arguments.get("host", "")
        suspicious_only = arguments.get("suspicious_only", False)
        results = []
        for ev in _file_events:
            if ev.timestamp < cutoff: continue
            if user and ev.user != user: continue
            if host and ev.host != host: continue
            if suspicious_only and not (is_suspicious_path(ev.path) and classify_file_extension(ev.path) == "executable"):
                continue
            results.append(ev)
        return [TextContent(type="text", text=json.dumps([e.model_dump(mode="json") for e in results]))]

    elif name == "seed_mock_files":
        now = datetime.utcnow()
        mock = [
            FileEvent(path="C:\\Users\\jdoe\\AppData\\Local\\Temp\\temp.exe", operation="create",
                      process_name="powershell.exe", process_pid=1235,
                      user="jdoe", host="WORKSTATION-01", timestamp=now, file_hash="cafebabe1234"),
            FileEvent(path="C:\\Users\\jdoe\\AppData\\Local\\Temp\\temp.exe", operation="execute",
                      process_name="cmd.exe", process_pid=1236,
                      user="jdoe", host="WORKSTATION-01", timestamp=now, file_hash="cafebabe1234"),
        ]
        _file_events.extend(mock)
        return [TextContent(type="text", text=json.dumps({"status": "seeded", "count": len(mock)}))]

    raise ValueError(f"Unknown tool: {name}")


async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
