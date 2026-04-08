"""
mcp_client/orchestrator.py

MCP Client — Central Orchestrator
Runs the full 7-step pipeline. MCP servers are called via stdio subprocesses.
"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from datetime import datetime
from contextlib import asynccontextmanager
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from models.schemas import TriggerEvent, AttackGraph, LLMReasoningOutput, ResponseAction
from core.correlation.context_builder import build_context
from core.graph.builder import build_attack_graph
from core.scoring.engine import compute_risk_score
from core.llm.reasoner import reason_over_context
from core.response.decision_engine import execute_response, _select_action, _select_target
from utils.logger import get_logger

log = get_logger("orchestrator")

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SERVER_MODULES = {
    "response": "mcp_servers.response_server.server",
    "memory":   "mcp_servers.memory_server.server",
}


async def _call(server_name: str, tool: str, args: dict) -> dict | list:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", SERVER_MODULES[server_name]],
        env={**os.environ, "PYTHONPATH": _ROOT},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool, args)
            return json.loads(result.content[0].text)


class AnalysisResult:
    def __init__(self, context, graph, llm_output, response, score_reasons):
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
    log.info(f"Pipeline started | pdf={trigger.pdf_path} | user={trigger.user}@{trigger.host}")
    start = datetime.utcnow()

    # Step 1: Build unified context via MCP
    log.info("[1/7] Building unified context via MCP...")
    ctx = await build_context(trigger)

    # Step 2: Build attack graph
    log.info("[2/7] Building attack graph...")
    graph = build_attack_graph(ctx)

    # Step 3: Compute risk score
    log.info("[3/7] Computing risk score...")
    score_breakdown, score_reasons = compute_risk_score(ctx)
    ctx.scores = score_breakdown

    # Step 4: LLM reasoning
    log.info("[4/7] Running LLM reasoning...")
    llm_output = await reason_over_context(ctx, score_reasons, graph)

    # Step 5: Execute response via MCP response server
    log.info("[5/7] Executing response action via MCP...")
    action = _select_action(llm_output, ctx)
    target = _select_target(action, ctx)
    reason = (f"Case {ctx.case_id} | Score={ctx.scores.total_score} | "
              f"Level={ctx.scores.risk_level} | "
              f"{llm_output.explanation[0] if llm_output.explanation else ''}")
    try:
        resp_data = await _call("response", "execute_action", {
            "case_id": ctx.case_id, "action": action,
            "target": target, "reason": reason,
        })
        response = ResponseAction(**resp_data)
    except Exception as e:
        log.warning(f"Response MCP server error ({e}), simulating locally")
        response = ResponseAction(
            action=action, target=target or None, reason=reason,
            simulated=True, result=f"[LOCAL_SIMULATE] {action} on {target or ctx.host}",
        )

    # Step 6: Save to memory via MCP memory server
    log.info("[6/7] Saving case to memory via MCP...")
    try:
        await _call("memory", "save_case", {
            "context": ctx.model_dump(mode="json"),
            "graph": graph.model_dump(mode="json"),
            "llm_output": llm_output.model_dump(mode="json"),
            "response": response.model_dump(mode="json"),
        })
    except Exception as e:
        log.warning(f"Memory MCP server error ({e}), case not persisted")

    elapsed = (datetime.utcnow() - start).total_seconds()
    log.info(f"[7/7] Pipeline complete in {elapsed:.2f}s | "
             f"case={ctx.case_id} | level={ctx.scores.risk_level.upper()} | "
             f"action={response.action}")

    return AnalysisResult(
        context=ctx, graph=graph, llm_output=llm_output,
        response=response, score_reasons=score_reasons,
    )
