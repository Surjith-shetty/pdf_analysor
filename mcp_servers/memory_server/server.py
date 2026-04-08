"""
mcp_servers/memory_server/server.py

MCP Server 8: Memory / Case History
Role: Persists all cases, context objects, decisions, and analyst verdicts.
      Enables future learning: "Have we seen this hash before?"
      Provides case lookup for the orchestrator.

Storage: SQLite via SQLAlchemy async.
"""
import json
from fastapi import FastAPI, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from pydantic import BaseModel
from models.database import get_db, init_db
from models.db_models import CaseTable, RawEventTable, ResponseLogTable
from models.schemas import UnifiedContext, AttackGraph, LLMReasoningOutput, ResponseAction
from utils.logger import get_logger

log = get_logger("memory_server")
app = FastAPI(title="Memory / Case History MCP Server")


@app.on_event("startup")
async def startup():
    await init_db()
    log.info("Memory server DB initialized")


class SaveCaseRequest(BaseModel):
    context: UnifiedContext
    graph: AttackGraph
    llm_output: LLMReasoningOutput
    response: ResponseAction


class VerdictUpdate(BaseModel):
    case_id: str
    verdict: str    # confirmed_tp | false_positive | under_review


@app.post("/cases/save")
async def save_case(req: SaveCaseRequest, db: AsyncSession = Depends(get_db)):
    """Persist a completed case to the database."""
    ctx = req.context
    record = CaseTable(
        case_id=ctx.case_id,
        created_at=ctx.timestamp,
        user=ctx.user,
        host=ctx.host,
        pdf_hash=ctx.pdf.hash,
        pdf_path=ctx.pdf.path,
        risk_level=ctx.scores.risk_level,
        total_score=ctx.scores.total_score,
        classification=req.llm_output.classification,
        recommended_action=req.llm_output.recommended_action,
        context_json=ctx.model_dump_json(),
        graph_json=req.graph.model_dump_json(),
        llm_output_json=req.llm_output.model_dump_json(),
        response_json=req.response.model_dump_json(),
    )
    db.add(record)
    await db.commit()
    log.info(f"Case {ctx.case_id} saved to memory")
    return {"status": "saved", "case_id": ctx.case_id}


@app.get("/cases/{case_id}")
async def get_case(case_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(CaseTable).where(CaseTable.case_id == case_id))
    row = result.scalar_one_or_none()
    if not row:
        return {"error": "not found"}
    return {
        "case_id": row.case_id,
        "risk_level": row.risk_level,
        "classification": row.classification,
        "context": json.loads(row.context_json),
        "llm_output": json.loads(row.llm_output_json),
    }


@app.get("/cases")
async def list_cases(limit: int = 20, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(CaseTable.case_id, CaseTable.created_at, CaseTable.user,
               CaseTable.risk_level, CaseTable.classification, CaseTable.analyst_verdict)
        .order_by(CaseTable.created_at.desc())
        .limit(limit)
    )
    rows = result.all()
    return [dict(r._mapping) for r in rows]


@app.post("/cases/verdict")
async def update_verdict(req: VerdictUpdate, db: AsyncSession = Depends(get_db)):
    await db.execute(
        update(CaseTable)
        .where(CaseTable.case_id == req.case_id)
        .values(analyst_verdict=req.verdict)
    )
    await db.commit()
    return {"status": "updated", "case_id": req.case_id, "verdict": req.verdict}


@app.get("/cases/hash/{pdf_hash}")
async def lookup_by_hash(pdf_hash: str, db: AsyncSession = Depends(get_db)):
    """Check if we've seen this PDF hash before — used for memory-based detection."""
    result = await db.execute(
        select(CaseTable.case_id, CaseTable.risk_level, CaseTable.classification, CaseTable.analyst_verdict)
        .where(CaseTable.pdf_hash == pdf_hash)
        .order_by(CaseTable.created_at.desc())
        .limit(5)
    )
    rows = result.all()
    return {"hash": pdf_hash, "previous_cases": [dict(r._mapping) for r in rows]}


@app.post("/events/save")
async def save_raw_event(
    case_id: str, event_type: str, source: str, payload: dict,
    db: AsyncSession = Depends(get_db)
):
    row = RawEventTable(
        case_id=case_id, event_type=event_type,
        source=source, payload=json.dumps(payload),
    )
    db.add(row)
    await db.commit()
    return {"status": "saved"}


@app.get("/health")
async def health():
    return {"status": "ok", "server": "memory_case_history"}
