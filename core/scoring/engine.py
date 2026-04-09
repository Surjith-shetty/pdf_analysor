"""
core/scoring/engine.py

Deterministic Risk Scoring Engine
Role: Computes a numeric risk score BEFORE LLM reasoning.
      This ensures the system works even if the LLM is unavailable.
      The LLM then reasons OVER this score, not instead of it.

Scoring dimensions:
  1. Source risk      (0–30)  — email origin, sender reputation
  2. PDF risk         (0–50)  — structural maliciousness indicators
  3. Behavior risk    (0–60)  — runtime process/file/network behavior
  4. Anomaly risk     (0–40)  — deviation from user/host baseline
  5. Intel risk       (0–30)  — threat intel reputation hits

Total max: 210
Thresholds (from settings):
  low      < 30
  medium   30–70
  high     70–120
  critical > 120
"""
from models.schemas import UnifiedContext, ScoreBreakdown
from config.settings import settings
from utils.logger import get_logger

log = get_logger("scoring_engine")


def _score_source(ctx: UnifiedContext) -> tuple[int, list[str]]:
    """
    Source risk: where did the PDF come from?
    Max 30 points.
    """
    score = 0
    reasons = []

    if ctx.pdf.origin == "external_email":
        score += 10
        reasons.append("PDF arrived via external email (+10)")

    rep = ctx.pdf.sender_reputation
    if rep == "malicious":
        score += 20
        reasons.append("Sender has malicious reputation (+20)")
    elif rep == "suspicious":
        score += 10
        reasons.append("Sender has suspicious reputation (+10)")
    elif rep == "unknown":
        score += 5
        reasons.append("Sender reputation unknown (+5)")

    return min(score, 30), reasons


def _score_pdf(ctx: UnifiedContext) -> tuple[int, list[str]]:
    """
    PDF structural risk.
    Max 50 points.
    """
    score = 0
    reasons = []
    pdf = ctx.pdf

    if pdf.embedded_js:
        score += 15
        reasons.append("PDF contains embedded JavaScript (+15)")
    if pdf.open_action:
        score += 15
        reasons.append("PDF has OpenAction/AutoAction (+15)")
    if pdf.embedded_files > 0:
        score += 10
        reasons.append(f"PDF has {pdf.embedded_files} embedded file(s) (+10)")
    if pdf.obfuscation_score > 0.7:
        score += 10
        reasons.append(f"High obfuscation score {pdf.obfuscation_score:.2f} (+10)")
    elif pdf.obfuscation_score > 0.4:
        score += 5
        reasons.append(f"Moderate obfuscation score {pdf.obfuscation_score:.2f} (+5)")

    if pdf.entropy > 7.0:
        score += 10
        reasons.append(f"Very high entropy {pdf.entropy:.2f} — likely encrypted/packed (+10)")
    elif pdf.entropy > 6.0:
        score += 5
        reasons.append(f"High entropy {pdf.entropy:.2f} — possible obfuscation (+5)")

    return min(score, 50), reasons


def _score_behavior(ctx: UnifiedContext) -> tuple[int, list[str]]:
    """
    Runtime behavior risk.
    Max 60 points.
    """
    score = 0
    reasons = []
    rt = ctx.runtime

    SUSPICIOUS_PROCS = {"powershell.exe", "powershell", "cmd.exe", "cmd",
                        "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"}

    for proc in rt.child_processes:
        if proc.lower() in SUSPICIOUS_PROCS:
            score += 15
            reasons.append(f"PDF reader spawned {proc} (+15)")

    if rt.dropped_files:
        score += 10
        reasons.append(f"{len(rt.dropped_files)} file(s) dropped (+10)")

    if rt.executed_files:
        score += 15
        reasons.append(f"{len(rt.executed_files)} dropped file(s) executed (+15)")

    if rt.network_destinations:
        score += 10
        reasons.append(f"Process connected to {len(rt.network_destinations)} external destination(s) (+10)")

    # Encoded command is a strong indicator
    for cmd in rt.commands:
        if "-enc" in cmd.lower() or "-encodedcommand" in cmd.lower():
            score += 10
            reasons.append("Encoded PowerShell command detected (+10)")
            break

    return min(score, 60), reasons


def _score_anomaly(ctx: UnifiedContext) -> tuple[int, list[str]]:
    """
    Anomaly/baseline deviation risk.
    Max 40 points.
    """
    score = 0
    reasons = []
    bl = ctx.baseline

    if bl.user_anomaly_score > 0.7:
        score += 20
        reasons.append(f"High user behavioral anomaly ({bl.user_anomaly_score:.2f}) (+20)")
    elif bl.user_anomaly_score > 0.3:
        score += 10
        reasons.append(f"Moderate user behavioral anomaly ({bl.user_anomaly_score:.2f}) (+10)")

    if bl.pdf_reader_spawning_scripts_rarity > 0.9 and ctx.runtime.child_processes:
        score += 15
        reasons.append(f"PDF reader spawning scripts is extremely rare for this user (+15)")

    if not bl.host_seen_destination_before and ctx.runtime.network_destinations:
        score += 5
        reasons.append("Host has never connected to this destination before (+5)")

    return min(score, 40), reasons


def _score_intel(ctx: UnifiedContext) -> tuple[int, list[str]]:
    """
    Threat intelligence risk.
    Max 30 points.
    """
    score = 0
    reasons = []
    intel = ctx.intel

    SEVERITY = {"malicious": 3, "suspicious": 2, "unknown": 1, "clean": 0}

    if SEVERITY.get(intel.hash_reputation, 0) >= 3:
        score += 20
        reasons.append("PDF hash is known malicious (+20)")
    elif SEVERITY.get(intel.hash_reputation, 0) >= 2:
        score += 10
        reasons.append("PDF hash is suspicious (+10)")

    if SEVERITY.get(intel.ip_reputation, 0) >= 3:
        score += 10
        reasons.append("Destination IP is known malicious (+10)")
    elif SEVERITY.get(intel.ip_reputation, 0) >= 2:
        score += 5
        reasons.append("Destination IP is suspicious (+5)")

    return min(score, 30), reasons


def _classify(total: int) -> str:
    if total >= settings.risk_critical:
        return "critical"
    if total >= settings.risk_high:
        return "high"
    if total >= settings.risk_medium:
        return "medium"
    return "low"


def compute_risk_score(ctx: UnifiedContext) -> tuple[ScoreBreakdown, list[str]]:
    """
    Main entry point. Returns (ScoreBreakdown, list_of_reason_strings).
    The reason list is passed to the LLM as structured context.
    """
    src_score, src_reasons = _score_source(ctx)
    pdf_score, pdf_reasons = _score_pdf(ctx)
    beh_score, beh_reasons = _score_behavior(ctx)
    ano_score, ano_reasons = _score_anomaly(ctx)
    int_score, int_reasons = _score_intel(ctx)

    total = src_score + pdf_score + beh_score + ano_score + int_score
    level = _classify(total)

    all_reasons = src_reasons + pdf_reasons + beh_reasons + ano_reasons + int_reasons

    log.info(
        f"Risk score: source={src_score} pdf={pdf_score} behavior={beh_score} "
        f"anomaly={ano_score} intel={int_score} TOTAL={total} LEVEL={level.upper()}"
    )

    breakdown = ScoreBreakdown(
        source_score=src_score,
        pdf_score=pdf_score,
        behavior_score=beh_score,
        anomaly_score=ano_score,
        intel_score=int_score,
        total_score=total,
        risk_level=level,
    )
    return breakdown, all_reasons
