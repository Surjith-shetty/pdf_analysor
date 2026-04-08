#!/usr/bin/env python3
"""
demo1.py
Benign scenario demo — clean internal PDF opened by a normal user.

Scenario:
  - PDF arrives from internal HR email (hr@company.com)
  - User opens it in Evince (Linux PDF reader)
  - No child processes spawned
  - No files dropped
  - No network connections made
  - Hash is clean, sender is trusted

Expected outcome: LOW risk, benign classification, log_only response.

Run AFTER starting all servers with: python run_all.py
"""
import asyncio
import httpx
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

console = Console()

BASE = "http://localhost:8000"
ENDPOINT = "http://localhost:8003"
FILESYSTEM = "http://localhost:8004"
NETWORK = "http://localhost:8005"


async def seed_benign_telemetry():
    """
    Push benign process/file/network events.
    Only a single PDF reader process — no children, no drops, no connections.
    """
    console.print("[bold cyan]Seeding benign telemetry...[/bold cyan]")
    now = datetime.utcnow().isoformat()

    async with httpx.AsyncClient() as client:

        # Only the PDF reader process itself — no suspicious children
        proc_event = {
            "pid": 2100,
            "name": "evince",
            "cmdline": "evince /home/alice/documents/benefits_2024.pdf",
            "parent_pid": 1800,
            "parent_name": "nautilus",
            "user": "alice",
            "host": "DESKTOP-HR-02",
            "timestamp": now,
            "event_type": "create",
        }
        try:
            resp = await client.post(f"{ENDPOINT}/ingest/process", json=proc_event, timeout=5.0)
            console.print(f"  ✓ endpoint (evince process): {resp.json()}")
        except Exception as e:
            console.print(f"  ✗ endpoint: {e}", style="red")

        # No file events — nothing dropped or executed
        console.print("  ✓ filesystem: no suspicious file events (clean)")

        # No network events — reader made no outbound connections
        console.print("  ✓ network: no outbound connections (clean)")


async def run_benign_analysis():
    """Trigger analysis for the benign PDF."""
    console.print("\n[bold cyan]Running analysis pipeline...[/bold cyan]")

    trigger = {
        "pdf_path": "/home/alice/documents/benefits_2024.pdf",
        "pdf_hash": "aabbcc9900",        # maps to "clean" in mock threat intel DB
        "user": "alice",
        "host": "DESKTOP-HR-02",
        "origin": "internal_email",
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(f"{BASE}/analyze", json=trigger)
        if resp.status_code != 200:
            console.print(f"[red]Error: {resp.status_code} {resp.text}[/red]")
            return
        result = resp.json()

    risk_color = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "green",
    }.get(result.get("risk_level", "low"), "white")

    console.print(Panel(
        f"[bold]Case ID:[/bold] {result['case_id']}\n"
        f"[bold]User:[/bold] {result['user']} @ {result['host']}\n"
        f"[bold]PDF Hash:[/bold] {result['pdf_hash']}\n"
        f"[bold]Risk Level:[/bold] [{risk_color}]{result['risk_level'].upper()}[/{risk_color}]\n"
        f"[bold]Total Score:[/bold] {result['total_score']}\n"
        f"[bold]Classification:[/bold] {result['classification']}\n"
        f"[bold]Confidence:[/bold] {result.get('confidence', 'N/A')}\n"
        f"[bold]Attack Stage:[/bold] {result.get('attack_stage', 'unknown')}\n"
        f"[bold]Response Action:[/bold] [bold green]{result['recommended_action']}[/bold green]\n"
        f"[bold]LLM Available:[/bold] {result.get('llm_available', False)}",
        title="[bold]Analysis Result — Benign Scenario[/bold]",
        border_style=risk_color,
    ))

    if result.get("explanation"):
        console.print("\n[bold]Explanation:[/bold]")
        for i, reason in enumerate(result["explanation"], 1):
            console.print(f"  {i}. {reason}")

    console.print(f"\n[bold]Response:[/bold] {result.get('response_result', 'N/A')}")
    console.print(f"[bold]Graph:[/bold] {result['graph_nodes']} nodes, {result['graph_edges']} edges")


async def check_health():
    console.print("[bold cyan]Checking system health...[/bold cyan]")
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            resp = await client.get(f"{BASE}/health")
            health = resp.json()
            status_color = "green" if health["overall"] == "healthy" else "yellow"
            console.print(f"  Overall: [{status_color}]{health['overall']}[/{status_color}]")
            for server, status in health["servers"].items():
                color = "green" if status == "ok" else "red"
                console.print(f"  {server}: [{color}]{status}[/{color}]")
        except Exception as e:
            console.print(f"  [red]Health check failed: {e}[/red]")
            console.print("  [yellow]Make sure all servers are running: python run_all.py[/yellow]")
            return False
    return True


async def main():
    console.print(Panel(
        "[bold]MCP-Based Context-Aware PDF Attack Chain Intelligence System[/bold]\n"
        "Benign Scenario Demo — Clean Internal PDF",
        border_style="green",
    ))

    ok = await check_health()
    if not ok:
        return

    await seed_benign_telemetry()
    await run_benign_analysis()


if __name__ == "__main__":
    asyncio.run(main())
