"""
mcp_servers/network_server/server.py
MCP Server 5: Network Telemetry — real MCP SDK (stdio transport)
Tools: ingest_network_event, query_connections, seed_mock_network
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import json
from datetime import datetime, timedelta
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
from models.schemas import NetworkEvent
from utils.logger import get_logger

log = get_logger("network_server")
server = Server("network-server")

_network_events: list[NetworkEvent] = []
SUSPICIOUS_PORTS = {4444, 1337, 8080, 8443, 9001, 31337}


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="ingest_network_event",
            description="Ingest a network connection event",
            inputSchema={"type": "object", "properties": {"event": {"type": "object"}}, "required": ["event"]},
        ),
        Tool(
            name="query_connections",
            description="Query outbound network connections within a time window",
            inputSchema={
                "type": "object",
                "properties": {
                    "user": {"type": "string", "default": ""},
                    "host": {"type": "string", "default": ""},
                    "window_seconds": {"type": "integer", "default": 300},
                },
            },
        ),
        Tool(
            name="seed_mock_network",
            description="Seed mock network events for demo/testing",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "ingest_network_event":
        ev = NetworkEvent(**arguments["event"])
        _network_events.append(ev)
        return [TextContent(type="text", text=json.dumps({"status": "ingested"}))]

    elif name == "query_connections":
        cutoff = datetime.utcnow() - timedelta(seconds=arguments.get("window_seconds", 300))
        user = arguments.get("user", "")
        host = arguments.get("host", "")
        results = [
            ev for ev in _network_events
            if ev.timestamp >= cutoff
            and (not user or ev.user == user)
            and (not host or ev.host == host)
        ]
        return [TextContent(type="text", text=json.dumps([e.model_dump(mode="json") for e in results]))]

    elif name == "seed_mock_network":
        now = datetime.utcnow()
        mock = [
            NetworkEvent(src_ip="192.168.1.50", dst_ip="185.220.101.45", dst_port=4444,
                         protocol="TCP", process_name="temp.exe", process_pid=1237,
                         user="jdoe", host="WORKSTATION-01", timestamp=now,
                         bytes_sent=1024, dns_query=None),
            NetworkEvent(src_ip="192.168.1.50", dst_ip="185.220.101.45", dst_port=443,
                         protocol="TCP", process_name="temp.exe", process_pid=1237,
                         user="jdoe", host="WORKSTATION-01", timestamp=now,
                         bytes_sent=512, dns_query="c2.evil-domain.ru"),
        ]
        _network_events.extend(mock)
        return [TextContent(type="text", text=json.dumps({"status": "seeded", "count": len(mock)}))]

    raise ValueError(f"Unknown tool: {name}")


async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
