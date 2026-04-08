"""
mcp_servers/email_server/server.py

MCP Server 1: Email / Source Metadata
Role: Provides email context for a given file hash or attachment name.
      In production this connects to an email gateway API or SIEM.
      In prototype mode it uses mock data + simple reputation heuristics.

Input:  { "attachment_hash": "...", "sender": "..." }
Output: EmailMetadata schema
"""
from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
from models.schemas import EmailMetadata
from utils.logger import get_logger

log = get_logger("email_server")
app = FastAPI(title="Email Metadata MCP Server")

# ── Mock email store (replace with real email gateway connector) ──────────────
MOCK_EMAILS: dict[str, dict] = {
    "deadbeef1234": {
        "sender": "attacker@evil-domain.ru",
        "sender_domain": "evil-domain.ru",
        "subject": "Invoice Q2 2024",
        "received_at": "2024-06-01T09:15:00",
        "attachment_name": "invoice_q2.pdf",
        "is_external": True,
        "spf_pass": False,
        "dkim_pass": False,
    },
    "aabbcc9900": {
        "sender": "hr@company.com",
        "sender_domain": "company.com",
        "subject": "Benefits Update",
        "received_at": "2024-06-01T10:00:00",
        "attachment_name": "benefits.pdf",
        "is_external": False,
        "spf_pass": True,
        "dkim_pass": True,
    },
}

# Domains with known bad reputation
SUSPICIOUS_DOMAINS = {"evil-domain.ru", "phish.xyz", "malware-drop.com"}


class EmailQuery(BaseModel):
    attachment_hash: str
    sender: str = ""


@app.post("/query", response_model=EmailMetadata)
async def query_email_metadata(q: EmailQuery) -> EmailMetadata:
    """
    Look up email metadata for a given attachment hash.
    Falls back to a minimal record if not found (e.g. file was downloaded, not emailed).
    """
    raw = MOCK_EMAILS.get(q.attachment_hash)

    if raw:
        domain = raw["sender_domain"]
        reputation = "malicious" if domain in SUSPICIOUS_DOMAINS else (
            "suspicious" if not raw["spf_pass"] else "clean"
        )
        log.info(f"Email metadata found for hash {q.attachment_hash}: reputation={reputation}")
        return EmailMetadata(
            sender=raw["sender"],
            sender_domain=domain,
            subject=raw["subject"],
            received_at=datetime.fromisoformat(raw["received_at"]),
            attachment_name=raw["attachment_name"],
            attachment_hash=q.attachment_hash,
            is_external=raw["is_external"],
            spf_pass=raw["spf_pass"],
            dkim_pass=raw["dkim_pass"],
            sender_reputation=reputation,
        )

    # No email record — file likely came from a download
    log.info(f"No email record for hash {q.attachment_hash}, treating as download origin")
    return EmailMetadata(
        sender=q.sender or "unknown",
        sender_domain="unknown",
        subject="",
        received_at=datetime.utcnow(),
        attachment_name="",
        attachment_hash=q.attachment_hash,
        is_external=True,
        spf_pass=False,
        dkim_pass=False,
        sender_reputation="unknown",
    )


@app.get("/health")
async def health():
    return {"status": "ok", "server": "email_metadata"}
