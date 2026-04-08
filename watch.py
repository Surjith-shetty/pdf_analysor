#!/usr/bin/env python3
"""
watch.py
Background PDF watcher.
Monitors a folder for PDF open/create events, triggers the full analysis
pipeline, and shows a desktop notification with the result.

Usage:
  python watch.py                        # watches ~/Downloads by default
  python watch.py /path/to/watch/folder  # watches a custom folder
  python watch.py --start-servers        # also starts all MCP servers first

Press Ctrl+C to stop.
"""
import asyncio
import hashlib
import os
import sys
import time
import subprocess
import threading
from pathlib import Path

import httpx
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from rich.console import Console
from rich.panel import Panel

from utils.notifier import notify_result, notify

console = Console()

ORCHESTRATOR = "http://localhost:8000"
WATCH_FOLDER = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else str(Path.home() / "Downloads")
START_SERVERS = "--start-servers" in sys.argv

# Debounce: avoid re-analyzing the same file within 10 seconds
_recently_analyzed: dict[str, float] = {}
_DEBOUNCE_SECONDS = 10


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_debounced(path: str) -> bool:
    last = _recently_analyzed.get(path, 0)
    return (time.time() - last) < _DEBOUNCE_SECONDS


def _mark_analyzed(path: str):
    _recently_analyzed[path] = time.time()


async def _analyze(pdf_path: str):
    """Compute hash and call the orchestrator pipeline."""
    pdf_name = os.path.basename(pdf_path)

    # Mark immediately to suppress duplicate events before we even start
    _mark_analyzed(pdf_path)

    try:
        pdf_hash = _sha256(pdf_path)
    except PermissionError:
        console.print(f"[red]Permission denied: {pdf_name}[/red]")
        console.print("[yellow]Fix: System Settings → Privacy & Security → Full Disk Access → add your Terminal[/yellow]")
        return
    except Exception as e:
        console.print(f"[red]Could not hash {pdf_name}: {e}[/red]")
        return

    console.print(f"\n[bold cyan]PDF detected:[/bold cyan] {pdf_name}")
    console.print(f"  SHA256: [dim]{pdf_hash[:16]}...[/dim]")

    trigger = {
        "pdf_path": pdf_path,
        "pdf_hash": pdf_hash,
        "user": os.environ.get("USER", "unknown"),
        "host": os.uname().nodename,
        "origin": "local_open",
    }

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(f"{ORCHESTRATOR}/analyze", json=trigger)
            if resp.status_code != 200:
                console.print(f"[red]Analysis failed: {resp.status_code}[/red]")
                notify("PDF Analysis Failed", pdf_name, "Could not reach analysis server")
                return
            result = resp.json()
    except httpx.ConnectError:
        console.print("[red]Cannot reach orchestrator. Is run_all.py running?[/red]")
        notify("PDF Watcher Error", "Orchestrator not running", "Start with: python run_all.py")
        return

    risk = result.get("risk_level", "low")
    score = result.get("total_score", 0)
    risk_color = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green"}.get(risk, "white")

    console.print(Panel(
        f"[bold]File:[/bold] {pdf_name}\n"
        f"[bold]Risk:[/bold] [{risk_color}]{risk.upper()}[/{risk_color}]  "
        f"[bold]Score:[/bold] {score}\n"
        f"[bold]Action:[/bold] [yellow]{result.get('recommended_action')}[/yellow]\n"
        f"[bold]Reason:[/bold] {(result.get('explanation') or ['N/A'])[0]}",
        title="Analysis Result",
        border_style=risk_color,
    ))

    notify_result(pdf_name, result)
    _mark_analyzed(pdf_path)


def _run_analysis(pdf_path: str):
    """Run async analysis in a new event loop (called from watchdog thread)."""
    asyncio.run(_analyze(pdf_path))


class PDFHandler(FileSystemEventHandler):
    def _handle(self, path: str):
        if not path.lower().endswith(".pdf"):
            return
        if _is_debounced(path):
            return
        if not os.path.isfile(path):
            return
        # Run in a background thread so watchdog isn't blocked
        threading.Thread(target=_run_analysis, args=(path,), daemon=True).start()

    def on_created(self, event):
        if not event.is_directory:
            self._handle(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._handle(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._handle(event.dest_path)


def start_servers():
    """Launch all MCP servers in the background."""
    console.print("[bold cyan]Starting MCP servers...[/bold cyan]")
    proc = subprocess.Popen(
        [sys.executable, "run_all.py"],
        cwd=os.path.dirname(os.path.abspath(__file__)),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    console.print(f"  Servers starting (pid={proc.pid}), waiting 5s...")
    time.sleep(5)
    return proc


def wait_for_orchestrator(retries: int = 10, delay: float = 2.0) -> bool:
    """Poll until the orchestrator is up."""
    import httpx as _httpx
    for i in range(retries):
        try:
            r = _httpx.get(f"{ORCHESTRATOR}/health", timeout=2.0)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        console.print(f"  Waiting for orchestrator... ({i+1}/{retries})")
        time.sleep(delay)
    return False


if __name__ == "__main__":
    console.print(Panel(
        "[bold]PDF Attack Chain Watcher[/bold]\n"
        f"Monitoring: [cyan]{WATCH_FOLDER}[/cyan]",
        border_style="cyan",
    ))

    server_proc = None
    if START_SERVERS:
        server_proc = start_servers()

    if not wait_for_orchestrator():
        console.print("[red]Orchestrator not reachable. Start servers with: python run_all.py[/red]")
        console.print("[yellow]Or run: python watch.py --start-servers[/yellow]")
        sys.exit(1)

    console.print(f"[green]✓ Orchestrator ready[/green]")
    console.print(f"[green]✓ Watching {WATCH_FOLDER} for PDFs...[/green]")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    notify("PDF Watcher Active", f"Monitoring {WATCH_FOLDER}", "Any PDF opened will be analyzed")

    observer = Observer()
    observer.schedule(PDFHandler(), WATCH_FOLDER, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping watcher...[/yellow]")
        observer.stop()
        if server_proc:
            server_proc.terminate()

    observer.join()
    console.print("[green]Done.[/green]")
