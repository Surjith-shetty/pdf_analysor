"""
mcp_servers/email_server/server.py
MCP Server 1: Email / Source Metadata — real MCP SDK (stdio transport)
Tool: query_email_metadata(attachment_hash, sender) -> EmailMetadata JSON
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import json
from datetime import datetime
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
from models.schemas import EmailMetadata
from utils.logger import get_logger

log = get_logger("email_server")

MOCK_EMAILS = {
    "deadbeef1234": {
        "sender": "attacker@evil-domain.ru", "sender_domain": "evil-domain.ru",
        "subject": "Invoice Q2 2024", "received_at": "2024-06-01T09:15:00",
        "attachment_name": "invoice_q2.pdf", "is_external": True,
        "spf_pass": False, "dkim_pass": False,
    },
    "aabbcc9900": {
        "sender": "hr@company.com", "sender_domain": "company.com",
        "subject": "Benefits Update", "received_at": "2024-06-01T10:00:00",
        "attachment_name": "benefits.pdf", "is_external": False,
        "spf_pass": True, "dkim_pass": True,
    },
}
SUSPICIOUS_DOMAINS = {"evil-domain.ru", "phish.xyz", "malware-drop.com"}

server = Server("email-server")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [Tool(
        name="query_email_metadata",
        description="Look up email metadata for a given attachment hash",
        inputSchema={
            "type": "object",
            "properties": {
                "attachment_hash": {"type": "string"},
                "sender": {"type": "string", "default": ""},
            },
            "required": ["attachment_hash"],
        },
    )]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name != "query_email_metadata":
        raise ValueError(f"Unknown tool: {name}")

    h = arguments["attachment_hash"]
    raw = MOCK_EMAILS.get(h)

    if raw:
        domain = raw["sender_domain"]
        reputation = "malicious" if domain in SUSPICIOUS_DOMAINS else (
            "suspicious" if not raw["spf_pass"] else "clean"
        )
        result = EmailMetadata(
            sender=raw["sender"], sender_domain=domain, subject=raw["subject"],
            received_at=datetime.fromisoformat(raw["received_at"]),
            attachment_name=raw["attachment_name"], attachment_hash=h,
            is_external=raw["is_external"], spf_pass=raw["spf_pass"],
            dkim_pass=raw["dkim_pass"], sender_reputation=reputation,
        )
    else:
        result = EmailMetadata(
            sender=arguments.get("sender", "unknown"), sender_domain="unknown",
            subject="", received_at=datetime.utcnow(), attachment_name="",
            attachment_hash=h, is_external=True, spf_pass=False,
            dkim_pass=False, sender_reputation="unknown",
        )

    return [TextContent(type="text", text=result.model_dump_json())]


async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
