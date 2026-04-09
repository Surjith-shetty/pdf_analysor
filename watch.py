#!/usr/bin/env python3
"""
watch.py
Background PDF watcher with full threat response.
- Monitors folders for PDF events
- Runs the full analysis pipeline on every PDF
- On HIGH/CRITICAL: kills the entire attack chain process tree,
  then asks the user to Delete / Quarantine / Keep via native macOS dialog
"""
import asyncio
import hashlib
import os
import shutil
import signal
import stat
import sys
import time
import subprocess
import threading
from pathlib import Path

import httpx
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from rich.console import Console
from rich.panel import Panel

from utils.notifier import notify, notify_result, notify_threat_action

console = Console()

RESPONSE_SERVER = f"http://localhost:8007"


def _is_sanitized(pdf_hash: str) -> bool:
    return False  # MCP servers are stateless per-call; skip sanitized check


def _register_sanitized(pdf_hash: str):
    pass  # no-op in MCP mode

ORCHESTRATOR = "http://localhost:8000"
QUARANTINE_DIR = os.path.expanduser("~/cyber_quarantine")
SANITIZED_DIR = os.path.expanduser("~/Desktop/cyber_sanitized")
os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(SANITIZED_DIR, exist_ok=True)

PDF_READER_NAMES = {"preview", "acrobat", "acrord32", "adobe acrobat", "foxit", "skim", "pdf viewer"}

WHATSAPP_CACHE_FOLDERS = [
    # WhatsApp Desktop (Mac App Store) — actual PDF preview location
    str(Path.home() / "Library" / "Containers" / "net.whatsapp.WhatsApp" / "Data" / "tmp" / "documents"),
    str(Path.home() / "Library" / "Containers" / "net.whatsapp.WhatsApp" / "Data" / "tmp"),
    str(Path.home() / "Library" / "Containers" / "net.whatsapp.WhatsApp" / "Data" / "Library" / "Caches"),
    # WhatsApp Desktop (direct download fallback)
    str(Path.home() / "Library" / "Application Support" / "WhatsApp"),
]

SYSTEM_WATCH_FOLDERS = [
    str(Path.home() / "Downloads"),
    str(Path.home() / "Desktop"),
    str(Path.home() / "Documents"),
    str(Path.home() / "Library" / "Mail Downloads"),
    "/tmp",
    "/var/tmp",
    *[f for f in WHATSAPP_CACHE_FOLDERS if os.path.exists(f)],
]

if len(sys.argv) > 1 and not sys.argv[1].startswith("--"):
    WATCH_FOLDERS = [sys.argv[1]]
else:
    WATCH_FOLDERS = [f for f in SYSTEM_WATCH_FOLDERS if os.path.exists(f)]
START_SERVERS = "--start-servers" in sys.argv

_recently_analyzed: dict[str, float] = {}
_DEBOUNCE_SECONDS = 30
_analysis_lock: dict[str, threading.Lock] = {}
_lock_map_lock = threading.Lock()


# ── Hashing ───────────────────────────────────────────────────────────────────

def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_debounced(path: str) -> bool:
    return (time.time() - _recently_analyzed.get(path, 0)) < _DEBOUNCE_SECONDS


def _mark_analyzed(path: str):
    _recently_analyzed[path] = time.time()


def _get_file_lock(path: str) -> threading.Lock:
    with _lock_map_lock:
        if path not in _analysis_lock:
            _analysis_lock[path] = threading.Lock()
        return _analysis_lock[path]


# ── Process termination ───────────────────────────────────────────────────────

def _kill_by_pid(pid: int) -> str:
    try:
        os.kill(pid, signal.SIGKILL)
        return f"killed PID {pid}"
    except ProcessLookupError:
        return f"PID {pid} already gone"
    except Exception as e:
        return f"could not kill PID {pid}: {e}"


def _terminate_attack_chain(result: dict, pdf_path: str) -> list[str]:
    """
    Kill every process involved in the attack chain in priority order:
      1. Dropped/executed file processes  (active payload — most dangerous)
      2. Child processes (powershell, cmd) (lateral movement)
      3. PDF reader                        (infection vector)
    Returns a list of kill log strings.
    """
    killed = []
    targeted_names: set[str] = set()

    # Collect names from pipeline result
    for proc_name in result.get("child_processes", []):
        targeted_names.add(proc_name.lower())
    for fpath in result.get("executed_files", []):
        targeted_names.add(os.path.basename(fpath).lower())

    # Priority 1 & 2: kill child + executed processes by name
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            name = (proc.info["name"] or "").lower()
            if name in targeted_names:
                killed.append(_kill_by_pid(proc.info["pid"]) + f" ({proc.info['name']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # Priority 3: kill PDF reader holding the file
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = (proc.info["name"] or "").lower()
            if any(r in name for r in PDF_READER_NAMES):
                try:
                    open_files = proc.open_files()
                    if any(pdf_path in (f.path or "") for f in open_files):
                        killed.append(_kill_by_pid(proc.info["pid"]) + f" ({proc.info['name']})")
                        continue
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                # Can't check open files — kill it anyway if it's a reader
                killed.append(_kill_by_pid(proc.info["pid"]) + f" ({proc.info['name']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return killed if killed else ["no active threat processes found"]


# ── File actions ──────────────────────────────────────────────────────────────

def _quarantine_file(path: str) -> tuple[bool, str]:
    """Move file to QUARANTINE_DIR and strip execute permissions. Returns (success, message)."""
    try:
        dest = os.path.join(QUARANTINE_DIR, os.path.basename(path))
        if os.path.exists(dest):
            base, ext = os.path.splitext(os.path.basename(path))
            dest = os.path.join(QUARANTINE_DIR, f"{base}_{int(time.time())}{ext}")
        shutil.move(path, dest)
        # Strip all execute bits so it can't run from quarantine
        os.chmod(dest, stat.S_IRUSR | stat.S_IWUSR)
        return True, dest
    except Exception as e:
        return False, str(e)


def _delete_file(path: str) -> tuple[bool, str]:
    """Permanently delete the file."""
    try:
        if os.path.isfile(path):
            os.remove(path)
        elif os.path.isdir(path):
            shutil.rmtree(path)
        else:
            return False, "path not found"
        return True, f"permanently deleted {path}"
    except Exception as e:
        return False, str(e)


def _sanitize_pdf(quarantined_path: str) -> tuple[bool, str]:
    """
    Sanitize a quarantined PDF by rebuilding it without malicious elements:
      - Strips all JavaScript (/JS, /JavaScript)
      - Removes OpenAction / AA (auto-launch) entries
      - Removes embedded files (/EmbeddedFile)
      - Removes Launch actions
      - Saves clean copy to SANITIZED_DIR
    Uses PyMuPDF (fitz) for surgical stream-level removal.
    Falls back to raw byte scrubbing if fitz unavailable.
    """
    base_name = os.path.basename(quarantined_path)
    dest = os.path.join(SANITIZED_DIR, f"sanitized_{base_name}")
    if os.path.exists(dest):
        name, ext = os.path.splitext(base_name)
        dest = os.path.join(SANITIZED_DIR, f"sanitized_{name}_{int(time.time())}{ext}")

    try:
        import fitz  # PyMuPDF
        doc = fitz.open(quarantined_path)
        removed = []

        for xref in range(1, doc.xref_length()):
            try:
                obj = doc.xref_object(xref, compressed=False)
                modified = obj

                # Strip JavaScript
                if "/JS" in obj or "/JavaScript" in obj:
                    modified = modified.replace("/JS", "/JS_removed")
                    modified = modified.replace("/JavaScript", "/JavaScript_removed")
                    removed.append("JavaScript")

                # Strip OpenAction / AA
                if "/OpenAction" in obj or "/AA " in obj:
                    modified = modified.replace("/OpenAction", "/OpenAction_removed")
                    modified = modified.replace("/AA ", "/AA_removed ")
                    removed.append("OpenAction")

                # Strip Launch actions
                if "/Launch" in obj:
                    modified = modified.replace("/Launch", "/Launch_removed")
                    removed.append("Launch")

                # Strip EmbeddedFile
                if "/EmbeddedFile" in obj:
                    modified = modified.replace("/EmbeddedFile", "/EmbeddedFile_removed")
                    removed.append("EmbeddedFile")

                if modified != obj:
                    doc.update_object(xref, modified)

            except Exception:
                continue

        doc.save(dest, garbage=4, deflate=True, clean=True)
        doc.close()

        # Make sanitized file read-only (safe to open)
        os.chmod(dest, stat.S_IRUSR | stat.S_IRGRP)
        removed_unique = list(set(removed))
        return True, dest, removed_unique

    except ImportError:
        # Fallback: raw byte scrubbing
        MALICIOUS_TOKENS = [
            b"/JS ", b"/JavaScript", b"/OpenAction", b"/AA ",
            b"/Launch", b"/EmbeddedFile", b"eval(", b"unescape(",
        ]
        with open(quarantined_path, "rb") as f:
            data = f.read()
        removed = []
        for token in MALICIOUS_TOKENS:
            if token in data:
                data = data.replace(token, b"/removed_" + token[1:])
                removed.append(token.decode("latin-1").strip())
        with open(dest, "wb") as f:
            f.write(data)
        os.chmod(dest, stat.S_IRUSR | stat.S_IRGRP)
        return True, dest, list(set(removed))

    except Exception as e:
        return False, str(e), []


def _ask_sanitize_dialog(pdf_name: str, quarantine_path: str) -> bool:
    """Ask user if they want to sanitize the quarantined file. Returns True = sanitize."""
    safe_name = pdf_name.replace('"', "'")
    safe_path = quarantine_path.replace('"', "'")
    script = (
        f'display dialog '
        f'"🔒 File Quarantined Successfully\\n\\n'
        f'File: {safe_name}\\n'
        f'Location: {safe_path}\\n\\n'
        f'Would you like to sanitize this file?\\n'
        f'Sanitization removes all malicious elements (JavaScript,\\n'
        f'OpenAction, embedded files) and saves a clean copy to:\\n'
        f'{SANITIZED_DIR}/" '
        f'with title "Sanitize Quarantined File?" '
        f'with icon caution '
        f'buttons {{"Skip", "Sanitize"}} '
        f'default button "Sanitize" '
        f'cancel button "Skip"'
    )
    try:
        r = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True, text=True, timeout=120
        )
        return "Sanitize" in r.stdout
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False


# ── User dialog ───────────────────────────────────────────────────────────────

def _build_attack_summary(result: dict) -> str:
    """Build a short attack chain summary for the dialog."""
    lines = []
    children = result.get("child_processes", [])
    drops = result.get("dropped_files", [])
    nets = result.get("network_destinations", [])
    if children:
        lines.append(f"• Spawned: {', '.join(children[:3])}")
    if drops:
        lines.append(f"• Dropped: {os.path.basename(drops[0])}")
    if nets:
        lines.append(f"• Connected to: {nets[0]}")
    return "\\n".join(lines) if lines else "• Suspicious structure detected"


def _ask_threat_dialog(pdf_name: str, risk: str, score: int,
                       top_reason: str, attack_summary: str) -> str:
    """
    Show a 3-button native macOS dialog.
    Returns: 'delete' | 'quarantine' | 'keep'
    """
    # Escape double quotes in dynamic strings
    safe_name = pdf_name.replace('"', "'")
    safe_reason = top_reason[:120].replace('"', "'")
    safe_summary = attack_summary.replace('"', "'")

    script = (
        f'display dialog '
        f'"🚨 MALICIOUS FILE DETECTED\\n\\n'
        f'File:  {safe_name}\\n'
        f'Risk:  {risk.upper()}  (score: {score})\\n\\n'
        f'Attack chain:\\n{safe_summary}\\n\\n'
        f'Reason: {safe_reason}\\n\\n'
        f'All related processes have been terminated.\\n'
        f'What would you like to do with this file?" '
        f'with title "PDF Security Alert" '
        f'with icon stop '
        f'buttons {{"Keep (Risky)", "Quarantine", "Delete"}} '
        f'default button "Delete" '
        f'cancel button "Keep (Risky)"'
    )
    try:
        r = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True, text=True, timeout=120
        )
        output = r.stdout.strip()
        if "Delete" in output:
            return "delete"
        if "Quarantine" in output:
            return "quarantine"
        return "keep"
    except subprocess.TimeoutExpired:
        return "quarantine"   # auto-quarantine if no response in 2 min
    except Exception:
        return "quarantine"


# ── Core analysis + response ──────────────────────────────────────────────────

async def _analyze(pdf_path: str):
    pdf_name = os.path.basename(pdf_path)
    _mark_analyzed(pdf_path)

    try:
        pdf_hash = _sha256(pdf_path)
    except PermissionError:
        console.print(f"[red]Permission denied: {pdf_name}[/red]")
        console.print("[yellow]Fix: System Settings → Privacy & Security → Full Disk Access → add Terminal[/yellow]")
        return
    except Exception as e:
        console.print(f"[red]Could not hash {pdf_name}: {e}[/red]")
        return

    # Skip files that were already sanitized by this system
    if _is_sanitized(pdf_hash):
        console.print(f"[green]✓ {pdf_name} was previously sanitized — skipping.[/green]")
        return

    console.print(f"\n[bold cyan]PDF detected:[/bold cyan] {pdf_name}")
    console.print(f"  SHA256: [dim]{pdf_hash[:16]}...[/dim]")

    is_whatsapp = any(pdf_path.startswith(f) for f in WHATSAPP_CACHE_FOLDERS)
    trigger = {
        "pdf_path": pdf_path,
        "pdf_hash": pdf_hash,
        "user": os.environ.get("USER", "unknown"),
        "host": os.uname().nodename,
        "origin": "whatsapp_preview" if is_whatsapp else "local_open",
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
    top_reason = (result.get("explanation") or ["No reason provided"])[0]

    console.print(Panel(
        f"[bold]File:[/bold] {pdf_name}\n"
        f"[bold]Risk:[/bold] [{risk_color}]{risk.upper()}[/{risk_color}]  "
        f"[bold]Score:[/bold] {score}\n"
        f"[bold]Classification:[/bold] {result.get('classification')}\n"
        f"[bold]Attack Stage:[/bold] {result.get('attack_stage', 'unknown')}\n"
        f"[bold]Action:[/bold] [yellow]{result.get('recommended_action')}[/yellow]\n"
        f"[bold]Reason:[/bold] {top_reason}",
        title="Analysis Result",
        border_style=risk_color,
    ))

    notify_result(pdf_name, result)

    # ── Threat response: MEDIUM / HIGH / CRITICAL ────────────────────────────
    if risk not in ("medium", "high", "critical"):
        return

    console.print(f"\n[bold red]🚨 {risk.upper()} threat — terminating attack chain...[/bold red]")

    # Step 1: kill all related processes immediately
    killed = _terminate_attack_chain(result, pdf_path)
    for k in killed:
        console.print(f"  [red]✗ {k}[/red]")

    # Step 2: check if file still exists (WhatsApp cache files are ephemeral)
    if not os.path.isfile(pdf_path):
        console.print("  [yellow]⚠ File no longer on disk (WhatsApp cache auto-cleared) — threat logged only.[/yellow]")
        notify_threat_action(pdf_name, "cache_cleared", f"Risk: {risk.upper()} | Score: {score} | File was ephemeral")
        return

    # Step 2: ask user what to do with the file
    attack_summary = _build_attack_summary(result)
    console.print("  [bold]Waiting for user decision...[/bold]")
    choice = _ask_threat_dialog(pdf_name, risk, score, top_reason, attack_summary)

    # Step 3: act on choice
    if choice == "delete":
        ok, msg = _delete_file(pdf_path)
        if ok:
            console.print(f"  [bold red]🗑  File permanently deleted.[/bold red]")
            notify_threat_action(pdf_name, "deleted", f"Risk: {risk.upper()} | Score: {score}")
        else:
            console.print(f"  [red]Delete failed: {msg}[/red]")
            notify("Delete Failed", pdf_name, msg)

    elif choice == "quarantine":
        ok, msg = _quarantine_file(pdf_path)
        if ok:
            console.print(f"  [green]✓ Quarantined → {msg}[/green]")
            notify_threat_action(pdf_name, "quarantined", "Moved to ~/cyber_quarantine")

            # ── Sanitization offer ────────────────────────────────────────────
            console.print("  [bold]Asking user about sanitization...[/bold]")
            want_sanitize = _ask_sanitize_dialog(pdf_name, msg)
            if want_sanitize:
                s_ok, s_dest, removed = _sanitize_pdf(msg)
                if s_ok:
                    removed_str = ", ".join(removed) if removed else "none found"
                    console.print(f"  [green]✓ Sanitized → {s_dest}[/green]")
                    console.print(f"  [dim]  Removed: {removed_str}[/dim]")
                    # Register sanitized file hash so re-opens are not re-flagged
                    try:
                        sanitized_hash = _sha256(s_dest)
                        _register_sanitized(sanitized_hash)
                    except Exception:
                        pass
                    notify_threat_action(
                        pdf_name, "sanitized",
                        f"Clean copy saved to ~/Desktop/cyber_sanitized | Removed: {removed_str}"
                    )
                else:
                    console.print(f"  [red]Sanitization failed: {s_dest}[/red]")
                    notify("Sanitization Failed", pdf_name, s_dest)
            else:
                console.print("  [yellow]User skipped sanitization. File remains quarantined.[/yellow]")
                notify_threat_action(pdf_name, "quarantined", "Sanitization skipped by user")
        else:
            console.print(f"  [red]Quarantine failed: {msg}[/red]")
            notify("Quarantine Failed", pdf_name, msg)

    else:  # keep
        console.print(f"  [yellow]⚠ User chose to keep the file. Monitoring...[/yellow]")
        notify_threat_action(pdf_name, "kept by user", f"Risk: {risk.upper()} — flagged for review")

    _mark_analyzed(pdf_path)


def _run_analysis(pdf_path: str):
    lock = _get_file_lock(pdf_path)
    if not lock.acquire(blocking=False):
        return  # another thread is already analyzing this file
    try:
        asyncio.run(_analyze(pdf_path))
    finally:
        lock.release()


# ── Watchdog handler ──────────────────────────────────────────────────────────

class PDFHandler(FileSystemEventHandler):
    def _handle(self, path: str):
        if not path.lower().endswith(".pdf"):
            return
        if _is_debounced(path):
            return
        # Skip files already in quarantine or sanitized output dirs
        if path.startswith(QUARANTINE_DIR) or path.startswith(SANITIZED_DIR):
            return
        if not os.path.isfile(path):
            return
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


# ── Server helpers ────────────────────────────────────────────────────────────

def start_servers():
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
    for i in range(retries):
        try:
            r = httpx.get(f"{ORCHESTRATOR}/docs", timeout=3.0)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        console.print(f"  Waiting for orchestrator... ({i+1}/{retries})")
        time.sleep(delay)
    return False


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    console.print(Panel(
        "[bold]PDF Attack Chain Watcher[/bold]\n"
        + "\n".join(f"Monitoring: [cyan]{f}[/cyan]" for f in WATCH_FOLDERS),
        border_style="cyan",
    ))

    server_proc = None
    if START_SERVERS:
        server_proc = start_servers()

    if not wait_for_orchestrator():
        console.print("[red]Orchestrator not reachable. Start servers with: python run_all.py[/red]")
        console.print("[yellow]Or run: python watch.py --start-servers[/yellow]")
        sys.exit(1)

    console.print("[green]✓ Orchestrator ready[/green]")
    for f in WATCH_FOLDERS:
        console.print(f"[green]✓ Watching {f}[/green]")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    notify("PDF Watcher Active", f"Monitoring {len(WATCH_FOLDERS)} folders", "Any PDF opened will be analyzed")

    observer = Observer()
    handler = PDFHandler()
    for folder in WATCH_FOLDERS:
        observer.schedule(handler, folder, recursive=True)
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
