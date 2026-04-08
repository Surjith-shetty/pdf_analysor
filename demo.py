#!/usr/bin/env python3
"""
demo.py
End-to-end demo script.
Seeds mock telemetry into all MCP servers, then triggers a full analysis.

Run AFTER starting all servers with: python run_all.py

Usage:
  python demo.py                          # uses built-in mock
  python demo.py /path/to/real.pdf        # analyzes a real PDF
"""
import asyncio
import hashlib
import sys
import os
import httpx
from rich.console import Console
from rich.panel import Panel

console = Console()

BASE = "http://localhost:8000"
ENDPOINT = "http://localhost:8003"
FILESYSTEM = "http://localhost:8004"
NETWORK = "http://localhost:8005"


async def seed_mock_telemetry():
    """Push mock process/file/network events into the MCP servers."""
    console.print("[bold cyan]Seeding mock telemetry...[/bold cyan]")
    async with httpx.AsyncClient() as client:
        for url, name in [
            (f"{ENDPOINT}/seed/mock", "endpoint"),
            (f"{FILESYSTEM}/seed/mock", "filesystem"),
            (f"{NETWORK}/seed/mock", "network"),
        ]:
            try:
                resp = await client.post(url, timeout=5.0)
                console.print(f"  ✓ {name}: {resp.json()}")
            except Exception as e:
                console.print(f"  ✗ {name}: {e}", style="red")


async def run_analysis(pdf_path: str = None):
    """Trigger a full analysis pipeline."""
    console.print("\n[bold cyan]Running analysis pipeline...[/bold cyan]")

    if pdf_path and os.path.exists(pdf_path):
        pdf_hash = hashlib.sha256(open(pdf_path, "rb").read()).hexdigest()
        console.print(f"  Using real PDF: [green]{pdf_path}[/green]")
        console.print(f"  SHA256: [dim]{pdf_hash}[/dim]")
    else:
        if pdf_path:
            console.print(f"  [yellow]PDF not found at {pdf_path}, using mock[/yellow]")
        pdf_path = "/tmp/invoice_q2.pdf"
        pdf_hash = "deadbeef1234"

    trigger = {
        "pdf_path": pdf_path,
        "pdf_hash": pdf_hash,
        "user": "jdoe",
        "host": "WORKSTATION-01",
        "origin": "external_email",
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(f"{BASE}/analyze", json=trigger)
        if resp.status_code != 200:
            console.print(f"[red]Error: {resp.status_code} {resp.text}[/red]")
            return

        result = resp.json()

    # ── Display results ───────────────────────────────────────────────────────
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
        f"[bold]Response Action:[/bold] [bold yellow]{result['recommended_action']}[/bold yellow]\n"
        f"[bold]LLM Available:[/bold] {result.get('llm_available', False)}",
        title="[bold]Analysis Result[/bold]",
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
        "Research Prototype Demo",
        border_style="cyan",
    ))

    ok = await check_health()
    if not ok:
        return

    pdf_path = sys.argv[1] if len(sys.argv) > 1 else None
    await seed_mock_telemetry()
    await run_analysis(pdf_path)


if __name__ == "__main__":
    asyncio.run(main())
