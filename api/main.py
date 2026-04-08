"""
api/main.py

Main FastAPI Application — Orchestrator API
Role: External HTTP interface to the MCP client orchestrator.
      Accepts trigger events, runs the pipeline, returns results.

Endpoints:
  POST /analyze          → run full pipeline for a PDF trigger
  GET  /cases            → list recent cases
  GET  /cases/{case_id}  → get case details
  POST /cases/verdict    → analyst feedback
  GET  /health           → system health check
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from models.schemas import TriggerEvent
from models.database import init_db
from mcp_client.orchestrator import run_pipeline
from utils.logger import get_logger
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
import sys, os, json
from datetime import datetime

log = get_logger("api")

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ALL_SERVERS = {
    **{
        k: v for k, v in {
            "email":       "mcp_servers.email_server.server",
            "pdf":         "mcp_servers.pdf_server.server",
            "endpoint":    "mcp_servers.endpoint_server.server",
            "filesystem":  "mcp_servers.filesystem_server.server",
            "network":     "mcp_servers.network_server.server",
            "threatintel": "mcp_servers.threatintel_server.server",
            "response":    "mcp_servers.response_server.server",
            "memory":      "mcp_servers.memory_server.server",
        }.items()
    }
}


async def _call(server_name: str, tool: str, args: dict) -> dict | list:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", _ALL_SERVERS[server_name]],
        env={**os.environ, "PYTHONPATH": _ROOT},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool, args)
            return json.loads(result.content[0].text)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    log.info("Database initialized")
    yield


app = FastAPI(
    title="MCP PDF Attack Chain Intelligence System",
    description="Context-aware PDF attack chain detection using MCP + LLM reasoning",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/analyze")
async def analyze(trigger: TriggerEvent):
    """
    Main analysis endpoint.
    Accepts a trigger event and runs the full 7-step pipeline.
    Returns the complete analysis result.
    """
    log.info(f"Analysis request: {trigger.pdf_path} | {trigger.user}@{trigger.host}")
    try:
        result = await run_pipeline(trigger)
        return result.summary()
    except Exception as e:
        log.error(f"Pipeline error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/cases")
async def list_cases(limit: int = 20):
    try:
        return await _call("memory", "list_cases", {"limit": limit})
    except Exception as e:
        return {"error": str(e)}


@app.get("/cases/{case_id}")
async def get_case(case_id: str):
    try:
        return await _call("memory", "get_case", {"case_id": case_id})
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@app.post("/cases/{case_id}/verdict")
async def update_verdict(case_id: str, verdict: str):
    try:
        return await _call("memory", "update_verdict", {"case_id": case_id, "verdict": verdict})
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@app.get("/health")
async def health():
    """Probe each MCP server by calling a lightweight tool."""
    status = {}
    for server_name, tool, args in [
        ("email",      "query_email_metadata", {"attachment_hash": "healthcheck"}),
        ("pdf",        "analyze_pdf",          {"pdf_path": "/nonexistent"}),
        ("endpoint",   "query_child_processes",{}),
        ("filesystem", "query_file_drops",     {}),
        ("network",    "query_connections",    {}),
        ("threatintel","enrich_indicators",    {}),
        ("response",   "execute_action",       {"case_id": "hc", "action": "log_only"}),
        ("memory",     "list_cases",           {"limit": 1}),
    ]:
        try:
            await _call(server_name, tool, args)
            status[server_name] = "ok"
        except Exception:
            status[server_name] = "unreachable"

    all_ok = all(v == "ok" for v in status.values())
    return {
        "orchestrator": "ok",
        "servers": status,
        "overall": "healthy" if all_ok else "degraded",
        "timestamp": datetime.utcnow().isoformat(),
    }
