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


def notify(title: str, message: str, subtitle: str = ""):
    """Send a native macOS desktop notification."""
    script = f'display notification "{message}" with title "{title}"'
    if subtitle:
        script += f' subtitle "{subtitle}"'
    try:
        subprocess.run(["osascript", "-e", script], check=True, capture_output=True)
    except Exception:
        # Fallback: just print
        print(f"\n🔔 {title} | {subtitle}\n   {message}\n")


def notify_result(pdf_name: str, result: dict):
    """Format and send analysis result as a notification."""
    risk = result.get("risk_level", "low")
    score = result.get("total_score", 0)
    action = result.get("recommended_action", "log_only")
    emoji = RISK_EMOJI.get(risk, "🔔")

    reasons = result.get("explanation", [])
    top_reason = reasons[0] if reasons else result.get("classification", "Analysis complete")

    title = f"{emoji} PDF Risk: {risk.upper()} (score: {score})"
    subtitle = f"{pdf_name}"
    message = f"{top_reason} → Action: {action}"

    notify(title, message, subtitle)
