"""
mcp_client/orchestrator.py

MCP Client — Central Orchestrator
Role: The brain of the system. Receives a TriggerEvent and runs the full pipeline:

  Step 1:  Receive trigger (PDF path + hash + user + host)
  Step 2:  Build unified context (query all MCP servers)
  Step 3:  Build attack graph
  Step 4:  Compute risk score
  Step 5:  Run LLM reasoning
  Step 6:  Execute response action
  Step 7:  Save case to memory

This is the single entry point for all analysis.
All other modules are called from here.
"""
import httpx
from datetime import datetime
from models.schemas import (
    TriggerEvent, UnifiedContext, AttackGraph,
    LLMReasoningOutput, ResponseAction,
)
from core.correlation.context_builder import build_context
from core.graph.builder import build_attack_graph
from core.scoring.engine import compute_risk_score
from core.llm.reasoner import reason_over_context
from core.response.decision_engine import execute_response
from config.settings import settings
from utils.logger import get_logger

log = get_logger("orchestrator")

MEMORY_URL = f"http://localhost:{settings.memory_server_port}"


async def _save_to_memory(
    ctx: UnifiedContext,
    graph: AttackGraph,
    llm: LLMReasoningOutput,
    response: ResponseAction,
):
    """Persist the completed case to the memory server."""
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{MEMORY_URL}/cases/save",
                json={
                    "context": ctx.model_dump(mode="json"),
                    "graph": graph.model_dump(mode="json"),
                    "llm_output": llm.model_dump(mode="json"),
                    "response": response.model_dump(mode="json"),
                },
                timeout=10.0,
            )
        log.info(f"Case {ctx.case_id} saved to memory")
    except Exception as e:
        log.warning(f"Memory server unreachable, case not persisted: {e}")


class AnalysisResult:
    """Container for the full pipeline output."""
    def __init__(
        self,
        context: UnifiedContext,
        graph: AttackGraph,
        llm_output: LLMReasoningOutput,
        response: ResponseAction,
        score_reasons: list[str],
    ):
        self.context = context
        self.graph = graph
        self.llm_output = llm_output
        self.response = response
        self.score_reasons = score_reasons

    def summary(self) -> dict:
        return {
            "case_id": self.context.case_id,
            "user": self.context.user,
            "host": self.context.host,
            "pdf_hash": self.context.pdf.hash,
            "risk_level": self.context.scores.risk_level,
            "total_score": self.context.scores.total_score,
            "classification": self.llm_output.classification,
            "confidence": self.llm_output.confidence,
            "recommended_action": self.llm_output.recommended_action,
            "attack_stage": self.llm_output.attack_stage,
            "explanation": self.llm_output.explanation,
            "response_result": self.response.result,
            "graph_nodes": len(self.graph.nodes),
            "graph_edges": len(self.graph.edges),
            "llm_available": self.llm_output.llm_available,
        }


async def run_pipeline(trigger: TriggerEvent) -> AnalysisResult:
    """
    Full 7-step analysis pipeline.
    Each step's output feeds the next.
    """
    log.info(f"Pipeline started | pdf={trigger.pdf_path} | user={trigger.user}@{trigger.host}")
    start = datetime.utcnow()

    # ── Step 1: Build unified context ─────────────────────────────────────────
    log.info("[1/7] Building unified context...")
    ctx = await build_context(trigger)

    # ── Step 2: Build attack graph ────────────────────────────────────────────
    log.info("[2/7] Building attack graph...")
    graph = build_attack_graph(ctx)

    # ── Step 3: Compute risk score ────────────────────────────────────────────
    log.info("[3/7] Computing risk score...")
    score_breakdown, score_reasons = compute_risk_score(ctx)
    ctx.scores = score_breakdown

    # ── Step 4: LLM reasoning ─────────────────────────────────────────────────
    log.info("[4/7] Running LLM reasoning...")
    llm_output = await reason_over_context(ctx, score_reasons, graph)

    # ── Step 5: Execute response ──────────────────────────────────────────────
    log.info("[5/7] Executing response action...")
    response = await execute_response(llm_output, ctx)

    # ── Step 6: Save to memory ────────────────────────────────────────────────
    log.info("[6/7] Saving case to memory...")
    await _save_to_memory(ctx, graph, llm_output, response)

    elapsed = (datetime.utcnow() - start).total_seconds()
    log.info(f"[7/7] Pipeline complete in {elapsed:.2f}s | "
             f"case={ctx.case_id} | level={ctx.scores.risk_level.upper()} | "
             f"action={response.action}")

    return AnalysisResult(
        context=ctx,
        graph=graph,
        llm_output=llm_output,
        response=response,
        score_reasons=score_reasons,
    )
