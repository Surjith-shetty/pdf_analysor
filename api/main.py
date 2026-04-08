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
from models.schemas import TriggerEvent, EmailMetadata
from models.database import init_db
from mcp_client.orchestrator import run_pipeline
from utils.logger import get_logger
import httpx
from config.settings import settings
from datetime import datetime

log = get_logger("api")


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
    """Proxy to memory server case list."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"http://localhost:{settings.memory_server_port}/cases",
                params={"limit": limit}, timeout=5.0,
            )
            return resp.json()
    except Exception:
        return {"error": "Memory server unavailable"}


@app.get("/cases/{case_id}")
async def get_case(case_id: str):
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"http://localhost:{settings.memory_server_port}/cases/{case_id}",
                timeout=5.0,
            )
            return resp.json()
    except Exception:
        raise HTTPException(status_code=503, detail="Memory server unavailable")


@app.post("/cases/{case_id}/verdict")
async def update_verdict(case_id: str, verdict: str):
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"http://localhost:{settings.memory_server_port}/cases/verdict",
                json={"case_id": case_id, "verdict": verdict}, timeout=5.0,
            )
            return resp.json()
    except Exception:
        raise HTTPException(status_code=503, detail="Memory server unavailable")


@app.get("/health")
async def health():
    """Check health of all MCP servers."""
    servers = {
        "email": settings.email_server_port,
        "pdf": settings.pdf_server_port,
        "endpoint": settings.endpoint_server_port,
        "filesystem": settings.filesystem_server_port,
        "network": settings.network_server_port,
        "threatintel": settings.threatintel_server_port,
        "response": settings.response_server_port,
        "memory": settings.memory_server_port,
    }
    status = {}
    async with httpx.AsyncClient() as client:
        for name, port in servers.items():
            try:
                resp = await client.get(f"http://localhost:{port}/health", timeout=2.0)
                status[name] = "ok" if resp.status_code == 200 else "error"
            except Exception:
                status[name] = "unreachable"

    all_ok = all(v == "ok" for v in status.values())
    return {
        "orchestrator": "ok",
        "servers": status,
        "overall": "healthy" if all_ok else "degraded",
        "timestamp": datetime.utcnow().isoformat(),
    }
