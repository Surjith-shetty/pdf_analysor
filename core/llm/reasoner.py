"""
core/llm/reasoner.py

LLM Reasoning Integration
Role: Takes the fully-built UnifiedContext + risk score + graph summary
      and asks the LLM to reason over it as a security analyst would.

Design principles:
  - LLM is NOT the primary detector. Risk score runs first.
  - LLM adds explainability and nuanced reasoning.
  - If LLM is unavailable, the system falls back to rule-based classification.
  - Output is strictly structured JSON — no free-form text parsing.

Prompt strategy:
  - System prompt: role + output schema
  - User prompt: structured context object (not raw logs)
  - Temperature: 0.1 (deterministic reasoning, not creative)
"""
import json
from models.schemas import UnifiedContext, LLMReasoningOutput, ScoreBreakdown, AttackGraph
from core.graph.builder import graph_to_summary
from config.settings import settings
from utils.logger import get_logger

log = get_logger("llm_reasoner")

SYSTEM_PROMPT = """You are an expert malware analyst and threat hunter.
You will be given a structured security context object describing a PDF-based attack chain.
Your job is to reason over the evidence and produce a structured JSON verdict.

You MUST respond with ONLY valid JSON matching this exact schema:
{
  "classification": "<benign|suspicious|malicious>",
  "confidence": <0.0-1.0>,
  "risk_level": "<low|medium|high|critical>",
  "explanation": ["<reason 1>", "<reason 2>", ...],
  "recommended_action": "<log_only|alert_analyst|kill_process|quarantine_file|isolate_host>",
  "attack_stage": "<initial_access|execution|persistence|c2|exfiltration|unknown>"
}

Rules:
- Base your reasoning on the provided evidence, not assumptions.
- If evidence is ambiguous, lean toward caution.
- The risk score is pre-computed — use it as a strong signal but apply your own judgment.
- Explain each reason concisely (1 sentence each).
- Do not include any text outside the JSON object.
"""


def _build_user_prompt(
    ctx: UnifiedContext,
    score_reasons: list[str],
    graph_summary: dict,
) -> str:
    """Build the structured context prompt sent to the LLM."""
    wa_block = ""
    if ctx.whatsapp and ctx.pdf.origin == "whatsapp_preview":
        wa_block = f"""
WHATSAPP SOURCE:
- App: {ctx.whatsapp.app_name}
- Chat Type: {ctx.whatsapp.chat_type}
- Sender JID: {ctx.whatsapp.sender_jid or 'unknown'}
- Group: {ctx.whatsapp.group_name or 'n/a'}
- Preview Only (not saved): {ctx.whatsapp.preview_only}
- Detection Confidence: {ctx.whatsapp.confidence}
"""

    return f"""Analyze this security context and provide your verdict:

CASE ID: {ctx.case_id}
USER: {ctx.user} | HOST: {ctx.host}

PDF CONTEXT:
- Hash: {ctx.pdf.hash}
- Origin: {ctx.pdf.origin}
- Sender: {ctx.pdf.sender} (reputation: {ctx.pdf.sender_reputation})
- Embedded JavaScript: {ctx.pdf.embedded_js}
- OpenAction: {ctx.pdf.open_action}
- Embedded Files: {ctx.pdf.embedded_files}
- Obfuscation Score: {ctx.pdf.obfuscation_score}
- Suspicious Keywords: {', '.join(ctx.pdf.suspicious_keywords) or 'none'}
{wa_block}
RUNTIME BEHAVIOR:
- PDF Reader: {ctx.runtime.reader_process or 'unknown'}
- Child Processes Spawned: {', '.join(ctx.runtime.child_processes) or 'none'}
- Commands Executed: {', '.join(ctx.runtime.commands) or 'none'}
- Files Dropped: {', '.join(ctx.runtime.dropped_files) or 'none'}
- Files Executed: {', '.join(ctx.runtime.executed_files) or 'none'}
- Network Destinations: {', '.join(ctx.runtime.network_destinations) or 'none'}

BASELINE DEVIATION:
- User normally runs PowerShell: {ctx.baseline.user_usually_runs_powershell}
- PDF reader spawning scripts rarity: {ctx.baseline.pdf_reader_spawning_scripts_rarity}
- User anomaly score: {ctx.baseline.user_anomaly_score}
- Host anomaly score: {ctx.baseline.host_anomaly_score}

THREAT INTELLIGENCE:
- Hash reputation: {ctx.intel.hash_reputation}
- IP reputation: {ctx.intel.ip_reputation}
- IP tags: {', '.join(ctx.intel.ip_tags) or 'none'}
- Domain reputation: {ctx.intel.domain_reputation}

RISK SCORE (pre-computed):
- Source: {ctx.scores.source_score} | PDF: {ctx.scores.pdf_score} | Behavior: {ctx.scores.behavior_score}
- Anomaly: {ctx.scores.anomaly_score} | Intel: {ctx.scores.intel_score}
- TOTAL: {ctx.scores.total_score} | LEVEL: {ctx.scores.risk_level.upper()}

SCORING REASONS:
{chr(10).join(f'- {r}' for r in score_reasons)}

ATTACK GRAPH SUMMARY:
- Nodes: {graph_summary['total_nodes']} | Edges: {graph_summary['total_edges']}
- Chain: {graph_summary['chain_preview']}

Provide your JSON verdict now:"""


def _fallback_classification(ctx: UnifiedContext) -> LLMReasoningOutput:
    """
    Rule-based fallback when LLM is unavailable.
    Maps risk level directly to classification and action.
    """
    level = ctx.scores.risk_level
    action_map = {
        "critical": "isolate_host",
        "high": "quarantine_file",
        "medium": "alert_analyst",
        "low": "log_only",
    }
    class_map = {
        "critical": "malicious",
        "high": "malicious",
        "medium": "suspicious",
        "low": "benign",
    }
    confidence_map = {"critical": 0.90, "high": 0.80, "medium": 0.60, "low": 0.30}

    explanation = [f"Risk score {ctx.scores.total_score} classified as {level} (LLM unavailable, using rule-based fallback)"]
    if ctx.pdf.embedded_js:
        explanation.append("PDF contains embedded JavaScript")
    if ctx.runtime.child_processes:
        explanation.append(f"PDF reader spawned: {', '.join(ctx.runtime.child_processes)}")
    if ctx.runtime.network_destinations:
        explanation.append(f"Process connected to: {', '.join(ctx.runtime.network_destinations)}")

    return LLMReasoningOutput(
        classification=class_map[level],
        confidence=confidence_map[level],
        risk_level=level,
        explanation=explanation,
        recommended_action=action_map[level],
        attack_stage="unknown",
        llm_available=False,
    )


async def reason_over_context(
    ctx: UnifiedContext,
    score_reasons: list[str],
    graph: AttackGraph,
) -> LLMReasoningOutput:
    """
    Main entry point for LLM reasoning.
    Tries the configured LLM provider, falls back to rule-based if unavailable.
    """
    graph_summary = graph_to_summary(graph)
    prompt = _build_user_prompt(ctx, score_reasons, graph_summary)

    try:
        from groq import AsyncGroq
        if settings.llm_api_key in ("sk-placeholder", "your_openai_api_key_here", ""):
            raise ValueError("LLM API key not configured")
        client = AsyncGroq(api_key=settings.llm_api_key)

        response = await client.chat.completions.create(
            model=settings.llm_model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
        )

        raw = response.choices[0].message.content or ""
        # Strip markdown code fences if the model wraps JSON in ```json ... ```
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip()
        if not raw:
            raise ValueError("LLM returned empty response")
        data = json.loads(raw)

        log.info(f"LLM verdict: {data.get('classification')} "
                 f"(confidence={data.get('confidence')}, action={data.get('recommended_action')})")

        return LLMReasoningOutput(
            classification=data["classification"],
            confidence=float(data["confidence"]),
            risk_level=data["risk_level"],
            explanation=data["explanation"],
            recommended_action=data["recommended_action"],
            attack_stage=data.get("attack_stage", "unknown"),
            llm_available=True,
        )

    except Exception as e:
        log.warning(f"LLM unavailable ({e}), using rule-based fallback")
        return _fallback_classification(ctx)
