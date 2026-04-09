#!/usr/bin/env python3
"""
email_watcher.py
Polls Gmail via IMAP using App Password credentials from .env.

Usage:
  python run_all.py        # terminal 1
  python email_watcher.py  # terminal 2
"""
import asyncio
import email
import email.utils
import hashlib
import imaplib
import os
import sys
import tempfile
from datetime import datetime

import httpx
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

from watch import _analyze, _get_file_lock, notify

load_dotenv()

console = Console()

IMAP_HOST    = "imap.gmail.com"
IMAP_PORT    = 993
EMAIL_USER   = os.environ.get("EMAIL_USER", "")
EMAIL_PASS   = os.environ.get("EMAIL_PASS", "")
POLL_SECS    = int(os.environ.get("EMAIL_POLL_SECONDS", "30"))
ORCHESTRATOR = "http://localhost:8000"

_seen_uids: set[bytes] = set()
_initialized = False


def _parse_date(date_str: str) -> str:
    try:
        return email.utils.parsedate_to_datetime(date_str).isoformat()
    except Exception:
        return datetime.utcnow().isoformat()


def _connect() -> imaplib.IMAP4_SSL:
    mail = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
    mail.login(EMAIL_USER, EMAIL_PASS)
    mail.select("INBOX")
    return mail


def _parse_email(mail: imaplib.IMAP4_SSL, uid: bytes) -> tuple[dict, list[tuple[str, bytes]]]:
    _, data = mail.fetch(uid, "(RFC822)")
    msg = email.message_from_bytes(data[0][1])

    sender_raw    = msg.get("From", "unknown")
    sender_addr   = email.utils.parseaddr(sender_raw)[1]
    sender_domain = sender_addr.split("@")[-1] if "@" in sender_addr else "unknown"

    metadata = {
        "sender":        sender_addr,
        "sender_domain": sender_domain,
        "subject":       msg.get("Subject", ""),
        "received_at":   msg.get("Date", ""),
        "is_external":   True,
        "spf_pass":      False,
        "dkim_pass":     False,
    }

    pdfs = []
    for part in msg.walk():
        fname = part.get_filename() or ""
        if fname.lower().endswith(".pdf") or part.get_content_type() == "application/pdf":
            payload = part.get_payload(decode=True)
            if payload:
                pdfs.append((fname or "attachment.pdf", payload))

    return metadata, pdfs


async def _analyze_email_pdf(pdf_bytes: bytes, filename: str, meta: dict):
    pdf_hash = hashlib.sha256(pdf_bytes).hexdigest()

    with tempfile.NamedTemporaryFile(suffix=".pdf", prefix="email_", delete=False, dir="/tmp") as f:
        f.write(pdf_bytes)
        pdf_path = f.name

    console.print(f"\n[bold cyan]Email PDF:[/bold cyan] {filename}")
    console.print(f"  From:   [dim]{meta['sender']}[/dim]")
    console.print(f"  SHA256: [dim]{pdf_hash[:16]}...[/dim]")

    trigger = {
        "pdf_path": pdf_path,
        "pdf_hash": pdf_hash,
        "user":     os.environ.get("USER", "unknown"),
        "host":     os.uname().nodename,
        "origin":   "external_email",
        "email_metadata": {
            "sender":            meta["sender"],
            "sender_domain":     meta["sender_domain"],
            "subject":           meta["subject"],
            "received_at":       _parse_date(meta.get("received_at", "")),
            "attachment_name":   filename,
            "attachment_hash":   pdf_hash,
            "is_external":       True,
            "spf_pass":          False,
            "dkim_pass":         False,
            "sender_reputation": "unknown",
        },
    }

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(f"{ORCHESTRATOR}/analyze", json=trigger)
    except httpx.ConnectError:
        console.print("[red]Cannot reach orchestrator. Start with: python run_all.py[/red]")
        notify("Email Watcher Error", "Orchestrator not running", "Start with: python run_all.py")
        return

    if resp.status_code != 200:
        console.print(f"[red]Analysis failed: {resp.status_code}[/red]")
        console.print(f"[red]Detail: {resp.text[:500]}[/red]")
        return

    result = resp.json()
    risk  = result.get("risk_level", "low")
    score = result.get("total_score", 0)
    risk_color = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green"}.get(risk, "white")
    top_reason = (result.get("explanation") or ["No reason provided"])[0]

    console.print(Panel(
        f"[bold]File:[/bold] {filename}\n"
        f"[bold]From:[/bold] {meta['sender']}\n"
        f"[bold]Risk:[/bold] [{risk_color}]{risk.upper()}[/{risk_color}]  "
        f"[bold]Score:[/bold] {score}\n"
        f"[bold]Classification:[/bold] {result.get('classification')}\n"
        f"[bold]Action:[/bold] [yellow]{result.get('recommended_action')}[/yellow]\n"
        f"[bold]Reason:[/bold] {top_reason}",
        title="Email PDF Analysis",
        border_style=risk_color,
    ))

    notify(
        f"Email PDF: {risk.upper()} (score: {score})",
        top_reason,
        filename,
    )

    if risk in ("medium", "high", "critical"):
        lock = _get_file_lock(pdf_path)
        if lock.acquire(blocking=False):
            try:
                await _analyze(pdf_path)
            finally:
                lock.release()


async def poll_once():
    try:
        mail = _connect()
    except imaplib.IMAP4.error as e:
        console.print(f"[red]Login failed: {e}[/red]")
        return
    except Exception as e:
        console.print(f"[yellow]Connection error (will retry): {e}[/yellow]")
        await asyncio.sleep(30)
        return

    try:
        global _initialized

        _, all_data = mail.search(None, "ALL")
        all_uids = all_data[0].split() if all_data[0] else []

        if not _initialized:
            _seen_uids.update(all_uids)
            _initialized = True
            console.print(f"[dim]Skipped {len(all_uids)} existing emails. Watching for new ones...[/dim]")
            return

        candidates = [u for u in all_uids if u not in _seen_uids]

        if not candidates:
            console.print("[dim]No new emails.[/dim]")
            return

        console.print(f"[cyan]{len(candidates)} new email(s)...[/cyan]")
        for uid in candidates:
            _seen_uids.add(uid)
            try:
                meta, pdfs = _parse_email(mail, uid)
            except Exception as e:
                console.print(f"[red]Parse error: {e}[/red]")
                continue

            if not pdfs:
                console.print(f"  [dim]No PDF in email from {meta['sender']}[/dim]")
                continue

            console.print(f"  [green]{len(pdfs)} PDF(s) from {meta['sender']}[/green]")
            for fname, pdf_bytes in pdfs:
                await _analyze_email_pdf(pdf_bytes, fname, meta)
    finally:
        try:
            mail.logout()
        except Exception:
            pass


async def main():
    if not EMAIL_USER or not EMAIL_PASS:
        console.print("[red]EMAIL_USER / EMAIL_PASS not set in .env[/red]")
        sys.exit(1)

    console.print(f"[cyan]Connecting to Gmail as {EMAIL_USER}...[/cyan]")
    try:
        m = _connect()
        m.logout()
        console.print("[green]✓ Gmail connection successful[/green]")
    except Exception as e:
        console.print(f"[red]✗ Connection failed: {e}[/red]")
        sys.exit(1)

    console.print(Panel(
        f"[bold]Gmail PDF Watcher[/bold]\n"
        f"Account: [cyan]{EMAIL_USER}[/cyan]\n"
        f"Polling every [cyan]{POLL_SECS}s[/cyan] for unread emails with PDF attachments",
        border_style="cyan",
    ))

    notify("Gmail PDF Watcher Active", EMAIL_USER, f"Polling every {POLL_SECS}s")

    while True:
        await poll_once()
        await asyncio.sleep(POLL_SECS)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped.[/yellow]")
