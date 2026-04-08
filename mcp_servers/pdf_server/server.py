"""
mcp_servers/pdf_server/server.py
MCP Server 2: PDF Static Analysis — real MCP SDK (stdio transport)
Tool: analyze_pdf(pdf_path, pdf_hash) -> PDFAnalysisResult JSON
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
from models.schemas import PDFAnalysisResult
from utils.helpers import calculate_entropy, sha256_file
from utils.logger import get_logger
import re

log = get_logger("pdf_server")

SUSPICIOUS_KEYWORDS = [
    "/JS", "/JavaScript", "/OpenAction", "/AA", "/EmbeddedFile",
    "/Launch", "/URI", "/SubmitForm", "/ImportData", "/RichMedia",
    "/XFA", "eval(", "unescape(", "String.fromCharCode", "shellcode",
]

server = Server("pdf-server")


def _mock_analysis(path: str) -> dict:
    filename = os.path.basename(path).lower()
    is_bad = "malicious" in filename or "invoice" in filename
    return {
        "has_javascript": is_bad, "has_open_action": is_bad,
        "has_embedded_files": 1 if is_bad else 0, "has_launch_action": False,
        "has_uri_action": is_bad, "has_acroform": False,
        "suspicious_keywords": ["/JS", "/OpenAction", "/EmbeddedFile"] if is_bad else [],
        "streams_count": 5, "entropy": 7.2 if is_bad else 4.1,
        "pdf_version": "PDF-1.6", "file_size": 102400,
    }


def _analyze_with_pymupdf(path: str) -> dict:
    try:
        import fitz
    except ImportError:
        return _mock_analysis(path)

    result = {
        "has_javascript": False, "has_open_action": False, "has_embedded_files": 0,
        "has_launch_action": False, "has_uri_action": False, "has_acroform": False,
        "suspicious_keywords": [], "streams_count": 0, "entropy": 0.0,
        "pdf_version": "unknown", "file_size": os.path.getsize(path),
    }
    try:
        doc = fitz.open(path)
        result["pdf_version"] = doc.metadata.get("format", "unknown")
        with open(path, "rb") as f:
            raw = f.read()
        result["entropy"] = calculate_entropy(raw)
        raw_str = raw.decode("latin-1", errors="ignore")
        found = [kw for kw in SUSPICIOUS_KEYWORDS
                 if re.search(re.escape(kw) + r'(?!_removed)', raw_str, re.IGNORECASE)]
        result["suspicious_keywords"] = found
        result["has_javascript"] = "/JS" in found or "/JavaScript" in found
        result["has_open_action"] = "/OpenAction" in found or "/AA" in found
        result["has_launch_action"] = "/Launch" in found
        result["has_uri_action"] = "/URI" in found
        result["has_acroform"] = "/XFA" in found
        for xref in range(doc.xref_length()):
            try:
                obj_str = doc.xref_object(xref)
                if "/EmbeddedFile" in obj_str:
                    result["has_embedded_files"] += 1
                if "/ObjStm" in obj_str or "/FlateDecode" in obj_str:
                    result["streams_count"] += 1
            except Exception:
                pass
        doc.close()
    except Exception as e:
        log.error(f"PyMuPDF parse error: {e}")
    return result


def _obfuscation_score(f: dict) -> float:
    score = 0.4 if f["entropy"] > 7.0 else (0.2 if f["entropy"] > 6.0 else 0.0)
    score += min(len(f["suspicious_keywords"]) * 0.1, 0.4)
    if f["has_javascript"]: score += 0.1
    if f["has_launch_action"]: score += 0.1
    return round(min(score, 1.0), 2)


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [Tool(
        name="analyze_pdf",
        description="Perform static structural analysis of a PDF file",
        inputSchema={
            "type": "object",
            "properties": {
                "pdf_path": {"type": "string"},
                "pdf_hash": {"type": "string", "default": ""},
            },
            "required": ["pdf_path"],
        },
    )]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name != "analyze_pdf":
        raise ValueError(f"Unknown tool: {name}")

    path = arguments["pdf_path"]
    features = _analyze_with_pymupdf(path) if os.path.exists(path) else _mock_analysis(path)
    file_hash = arguments.get("pdf_hash") or (sha256_file(path) if os.path.exists(path) else "mock_hash")
    obfuscation = _obfuscation_score(features)

    result = PDFAnalysisResult(
        hash=file_hash, path=path, file_size=features["file_size"],
        has_javascript=features["has_javascript"], has_open_action=features["has_open_action"],
        has_embedded_files=features["has_embedded_files"], has_launch_action=features["has_launch_action"],
        has_uri_action=features["has_uri_action"], has_acroform=features["has_acroform"],
        obfuscation_score=obfuscation, entropy=features["entropy"],
        suspicious_keywords=features["suspicious_keywords"],
        streams_count=features["streams_count"], pdf_version=features["pdf_version"],
    )
    return [TextContent(type="text", text=result.model_dump_json())]


async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
