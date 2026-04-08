"""
utils/notifier.py
Desktop notification sender for macOS using osascript.
"""
import subprocess

RISK_EMOJI = {
    "critical": "🚨",
    "high": "⚠️",
    "medium": "🔶",
    "low": "✅",
}

ACTION_EMOJI = {
    "deleted": "🗑️",
    "quarantined": "🔒",
    "kept by user": "⚠️",
}


def notify(title: str, message: str, subtitle: str = ""):
    """Send a native macOS desktop notification."""
    script = f'display notification "{message}" with title "{title}"'
    if subtitle:
        script += f' subtitle "{subtitle}"'
    try:
        subprocess.run(["osascript", "-e", script], check=True, capture_output=True)
    except Exception:
        print(f"\n🔔 {title} | {subtitle}\n   {message}\n")


def notify_result(pdf_name: str, result: dict):
    """Send analysis result as a notification."""
    risk = result.get("risk_level", "low")
    score = result.get("total_score", 0)
    action = result.get("recommended_action", "log_only")
    emoji = RISK_EMOJI.get(risk, "🔔")
    top_reason = (result.get("explanation") or [result.get("classification", "Analysis complete")])[0]
    notify(
        f"{emoji} PDF Risk: {risk.upper()} (score: {score})",
        f"{top_reason} → Action: {action}",
        pdf_name,
    )


def notify_threat_action(pdf_name: str, action_taken: str, details: str = ""):
    """Send a notification after a threat response action (delete/quarantine/keep)."""
    emoji = ACTION_EMOJI.get(action_taken, "🔔")
    notify(
        f"{emoji} File {action_taken.title()}: {pdf_name}",
        details,
        "PDF Threat Response",
    )
