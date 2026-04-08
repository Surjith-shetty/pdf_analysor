"""
core/response/decision_engine.py

Decision & Response Engine
Role: Takes LLM output + risk score and decides the final response action.
      Calls the Response MCP server to execute (or simulate) the action.

Decision logic:
  - LLM recommendation is the primary signal
  - If LLM confidence < 0.6, fall back to score-based action
  - Policy overrides: never auto-isolate without critical score
  - All actions are logged regardless of mode
"""
from models.schemas import LLMReasoningOutput, UnifiedContext, ResponseAction
from config.settings import settings
from utils.logger import get_logger

log = get_logger("decision_engine")

# Minimum confidence required to trust LLM recommendation
LLM_CONFIDENCE_THRESHOLD = 0.6

# Score-based fallback action map
SCORE_ACTION_MAP = {
    "critical": "isolate_host",
    "high": "quarantine_file",
    "medium": "alert_analyst",
    "low": "log_only",
}


def _select_action(llm: LLMReasoningOutput, ctx: UnifiedContext) -> str:
    """
    Select the final response action.

    Priority:
      1. If LLM is available and confident → use LLM recommendation
      2. If LLM confidence is low → use score-based action
      3. Safety gate: never isolate_host unless score is critical
    """
    if llm.llm_available and llm.confidence >= LLM_CONFIDENCE_THRESHOLD:
        action = llm.recommended_action
        log.info(f"Using LLM recommendation: {action} (confidence={llm.confidence})")
    else:
        action = SCORE_ACTION_MAP.get(ctx.scores.risk_level, "log_only")
        log.info(f"Using score-based action: {action} (risk={ctx.scores.risk_level})")

    # Safety gate: isolate_host only if score is truly critical
    if action == "isolate_host" and ctx.scores.risk_level != "critical":
        action = "quarantine_file"
        log.warning("Downgraded isolate_host → quarantine_file (score not critical)")

    return action


def _select_target(action: str, ctx: UnifiedContext) -> str:
    """Determine the target for the action (PID, file path, or host)."""
    if action == "kill_process" and ctx.runtime.child_processes:
        return ctx.runtime.child_processes[-1]
    if action == "quarantine_file" and ctx.runtime.dropped_files:
        return ctx.runtime.dropped_files[0]
    if action == "isolate_host":
        return ctx.host
    return ""


async def execute_response(
    llm: LLMReasoningOutput,
    ctx: UnifiedContext,
) -> ResponseAction:
    """
    Decide and execute the response action.
    Called by the orchestrator which routes through the MCP response server.
    This function is kept for direct use in tests; the pipeline uses execute_response_via_mcp.
    """
    action = _select_action(llm, ctx)
    target = _select_target(action, ctx)
    reason = f"Case {ctx.case_id} | Score={ctx.scores.total_score} | Level={ctx.scores.risk_level} | {llm.explanation[0] if llm.explanation else ''}"
    return ResponseAction(
        action=action,
        target=target or None,
        reason=reason,
        simulated=True,
        result=f"[LOCAL_SIMULATE] {action} on {target or ctx.host}",
    )
