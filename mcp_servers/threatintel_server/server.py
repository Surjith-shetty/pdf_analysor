"""
mcp_servers/threatintel_server/server.py
MCP Server 6: Threat Intelligence — real MCP SDK (stdio transport)
Tool: enrich_indicators(hashes, ips, domains) -> ThreatIntelResult JSON
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
from models.schemas import ThreatIntelResult
from config.settings import settings
from utils.logger import get_logger
import httpx

log = get_logger("threatintel_server")
server = Server("threatintel-server")

MOCK_HASH_DB = {"deadbeef1234": "malicious", "cafebabe1234": "suspicious", "aabbcc9900": "clean"}
MOCK_IP_DB = {
    "185.220.101.45": ("malicious", ["tor_exit_node", "c2_server"]),
    "1.2.3.4": ("suspicious", ["scanner"]),
    "8.8.8.8": ("clean", []),
}
MOCK_DOMAIN_DB = {
    "evil-domain.ru": ("malicious", ["phishing", "malware_distribution"]),
    "c2.evil-domain.ru": ("malicious", ["c2"]),
    "company.com": ("clean", []),
}
SEVERITY = {"malicious": 3, "suspicious": 2, "unknown": 1, "clean": 0}


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [Tool(
        name="enrich_indicators",
        description="Enrich file hashes, IPs, and domains with threat intelligence",
        inputSchema={
            "type": "object",
            "properties": {
                "hashes": {"type": "array", "items": {"type": "string"}, "default": []},
                "ips": {"type": "array", "items": {"type": "string"}, "default": []},
                "domains": {"type": "array", "items": {"type": "string"}, "default": []},
            },
        },
    )]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name != "enrich_indicators":
        raise ValueError(f"Unknown tool: {name}")

    hash_rep, hash_det = "unknown", 0
    for h in arguments.get("hashes", []):
        rep = MOCK_HASH_DB.get(h, "unknown")
        if SEVERITY.get(rep, 0) > SEVERITY.get(hash_rep, 0):
            hash_rep, hash_det = rep, (5 if rep == "malicious" else 0)

    ip_rep, ip_tags = "unknown", []
    for ip in arguments.get("ips", []):
        rep, tags = MOCK_IP_DB.get(ip, ("unknown", []))
        if SEVERITY.get(rep, 0) > SEVERITY.get(ip_rep, 0):
            ip_rep = rep
        ip_tags.extend(tags)

    domain_rep, domain_tags = "unknown", []
    for domain in arguments.get("domains", []):
        rep, tags = MOCK_DOMAIN_DB.get(domain, ("unknown", []))
        if SEVERITY.get(rep, 0) > SEVERITY.get(domain_rep, 0):
            domain_rep = rep
        domain_tags.extend(tags)

    result = ThreatIntelResult(
        hash_reputation=hash_rep, ip_reputation=ip_rep, domain_reputation=domain_rep,
        hash_detections=hash_det, ip_tags=list(set(ip_tags)),
        domain_tags=list(set(domain_tags)), source="mock+vt",
    )
    return [TextContent(type="text", text=result.model_dump_json())]


async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
