"""
mcp_servers/whatsapp_server/server.py
MCP Server: WhatsApp PDF Source Detection — stdio transport
Tools:
  detect_whatsapp_source(pdf_path) -> WhatsAppMetadata JSON
  get_whatsapp_context(pdf_path)   -> WhatsAppMetadata JSON (DB-enriched)
"""
import sys, os, re, json, sqlite3, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
from utils.logger import get_logger

log = get_logger("whatsapp_server")

# Known WhatsApp cache paths (macOS)
WHATSAPP_CACHE_PATHS = [
    os.path.expanduser("~/Library/Containers/net.whatsapp.WhatsApp/Data/tmp/documents"),
    os.path.expanduser("~/Library/Containers/net.whatsapp.WhatsApp/Data/tmp"),
    os.path.expanduser("~/Library/Containers/net.whatsapp.WhatsApp/Data/Library/Caches"),
    os.path.expanduser("~/Library/Application Support/WhatsApp"),
]

# WhatsApp DB locations (macOS)
WA_DB_PATHS = [
    os.path.expanduser("~/Library/Containers/net.whatsapp.WhatsApp/Data/Library/Application Support/WhatsApp/ChatStorage.sqlite"),
    os.path.expanduser("~/Library/Application Support/WhatsApp/ChatStorage.sqlite"),
]

# WhatsApp filename patterns: e.g. "DOC-20240601-WA0003.pdf"
_WA_FILENAME_RE = re.compile(r"(DOC|IMG|VID|AUD|PTT)-\d{8}-WA\d+\.", re.IGNORECASE)


def _is_whatsapp_path(pdf_path: str) -> bool:
    return any(pdf_path.startswith(p) for p in WHATSAPP_CACHE_PATHS)


def _is_whatsapp_filename(pdf_path: str) -> bool:
    return bool(_WA_FILENAME_RE.search(os.path.basename(pdf_path)))


def _get_xattr_origins(pdf_path: str) -> list[str]:
    """Read com.apple.metadata:kMDItemWhereFroms extended attribute."""
    try:
        result = subprocess.run(
            ["xattr", "-p", "com.apple.metadata:kMDItemWhereFroms", pdf_path],
            capture_output=True, text=True, timeout=3,
        )
        if result.returncode == 0 and result.stdout.strip():
            return [result.stdout.strip()]
    except Exception:
        pass
    return []


def _get_quarantine_agent(pdf_path: str) -> str:
    """Read com.apple.quarantine to find which app wrote the file."""
    try:
        result = subprocess.run(
            ["xattr", "-p", "com.apple.quarantine", pdf_path],
            capture_output=True, text=True, timeout=3,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return ""


def _written_by_whatsapp(pdf_path: str) -> tuple[bool, float]:
    """
    Check if the file was written by WhatsApp process.
    Returns (is_whatsapp, confidence).
    """
    confidence = 0.0
    is_wa = False

    if _is_whatsapp_path(pdf_path):
        confidence += 0.6
        is_wa = True

    if _is_whatsapp_filename(pdf_path):
        confidence += 0.3
        is_wa = True

    quarantine = _get_quarantine_agent(pdf_path)
    if "whatsapp" in quarantine.lower():
        confidence += 0.1
        is_wa = True

    origins = _get_xattr_origins(pdf_path)
    for o in origins:
        if "whatsapp" in o.lower():
            confidence += 0.1
            is_wa = True

    return is_wa, min(confidence, 1.0)


def _query_wa_db(pdf_path: str) -> dict:
    """
    Try to read WhatsApp ChatStorage.sqlite for message context.
    Returns partial metadata dict or empty dict if inaccessible.
    """
    filename = os.path.basename(pdf_path)
    for db_path in WA_DB_PATHS:
        if not os.path.exists(db_path):
            continue
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2)
            cur = conn.cursor()
            # Try to find the message by filename match
            cur.execute(
                "SELECT ZFROMJID, ZTOJID, ZGROUPMEMBER, ZTEXT FROM ZWAMESSAGE "
                "WHERE ZMEDIAURL LIKE ? OR ZTEXT LIKE ? LIMIT 1",
                (f"%{filename}%", f"%{filename}%"),
            )
            row = cur.fetchone()
            conn.close()
            if row:
                from_jid, to_jid, group_member, _ = row
                return {
                    "sender_jid": from_jid or "unknown",
                    "group_name": group_member or None,
                    "chat_type": "group" if group_member else "individual",
                }
        except Exception:
            pass
    return {}


def _detect(pdf_path: str) -> dict:
    is_wa, confidence = _written_by_whatsapp(pdf_path)
    db_ctx = _query_wa_db(pdf_path) if is_wa else {}

    chat_type = db_ctx.get("chat_type", "unknown")
    # Heuristic: WhatsApp group filenames sometimes have "WA" + high index
    if chat_type == "unknown" and _is_whatsapp_filename(pdf_path):
        match = _WA_FILENAME_RE.search(os.path.basename(pdf_path))
        if match:
            chat_type = "individual"  # conservative default

    return {
        "app_name": "WhatsApp" if is_wa else "unknown",
        "sender_jid": db_ctx.get("sender_jid"),
        "group_name": db_ctx.get("group_name"),
        "chat_type": chat_type,
        "preview_only": True,   # by definition — file is in cache, not saved by user
        "confidence": round(confidence, 2),
    }


server = Server("whatsapp-server")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="detect_whatsapp_source",
            description="Detect if a PDF came from WhatsApp preview (cache path, filename pattern, xattr)",
            inputSchema={
                "type": "object",
                "properties": {"pdf_path": {"type": "string"}},
                "required": ["pdf_path"],
            },
        ),
        Tool(
            name="get_whatsapp_context",
            description="Enrich WhatsApp PDF detection with ChatStorage.sqlite context (sender JID, group)",
            inputSchema={
                "type": "object",
                "properties": {"pdf_path": {"type": "string"}},
                "required": ["pdf_path"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name not in ("detect_whatsapp_source", "get_whatsapp_context"):
        raise ValueError(f"Unknown tool: {name}")
    result = _detect(arguments["pdf_path"])
    return [TextContent(type="text", text=json.dumps(result))]


async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
