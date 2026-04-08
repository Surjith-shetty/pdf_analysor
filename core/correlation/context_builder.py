"""
core/correlation/context_builder.py

Context Fusion Engine
Role: Queries all MCP servers and assembles the UnifiedContext object.
      This is the "intelligence fusion" step — raw telemetry becomes structured context.

Flow:
  1. Query email server for source metadata
  2. Query PDF server for structural analysis
  3. Query endpoint server for child processes
  4. Query filesystem server for dropped/executed files
  5. Query network server for connections
  6. Query threat intel server for reputation enrichment
  7. Run baseline comparison
  8. Assemble UnifiedContext

All queries are made via HTTP to the MCP servers (or directly imported in monolith mode).
"""
import httpx
from models.schemas import (
    TriggerEvent, UnifiedContext, PDFContext, RuntimeContext,
    BaselineResult, ThreatIntelResult, EmailMetadata,
    PDFAnalysisResult, ProcessEvent, FileEvent, NetworkEvent,
)
from core.baseline.engine import compute_baseline
from config.settings import settings
from utils.logger import get_logger

log = get_logger("context_builder")

# MCP server base URLs
EMAIL_URL = f"http://localhost:{settings.email_server_port}"
PDF_URL = f"http://localhost:{settings.pdf_server_port}"
ENDPOINT_URL = f"http://localhost:{settings.endpoint_server_port}"
FILESYSTEM_URL = f"http://localhost:{settings.filesystem_server_port}"
NETWORK_URL = f"http://localhost:{settings.network_server_port}"
THREATINTEL_URL = f"http://localhost:{settings.threatintel_server_port}"


async def _post(client: httpx.AsyncClient, url: str, payload: dict) -> dict:
    """Helper: POST to an MCP server, return JSON or empty dict on failure."""
    try:
        resp = await client.post(url, json=payload, timeout=10.0)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        log.warning(f"MCP server call failed {url}: {e}")
        return {}


async def build_context(trigger: TriggerEvent) -> UnifiedContext:
    """
    Orchestrate all MCP server queries and fuse results into UnifiedContext.
    Uses a single httpx client for connection reuse.
    """
    async with httpx.AsyncClient() as client:

        # ── 1. Email metadata ─────────────────────────────────────────────────
        email_data = await _post(
            client, f"{EMAIL_URL}/query",
            {"attachment_hash": trigger.pdf_hash, "sender": ""}
        )
        email = EmailMetadata(**email_data) if email_data else None

        # ── 2. PDF static analysis ────────────────────────────────────────────
        pdf_data = await _post(
            client, f"{PDF_URL}/analyze",
            {"pdf_path": trigger.pdf_path, "pdf_hash": trigger.pdf_hash}
        )
        pdf_analysis = PDFAnalysisResult(**pdf_data) if pdf_data else None

        # ── 3. Child processes from PDF reader ────────────────────────────────
        proc_data = await _post(
            client, f"{ENDPOINT_URL}/query/children",
            {"parent_name": "AcroRd32.exe", "user": trigger.user,
             "host": trigger.host, "window_seconds": 600}
        )
        processes: list[ProcessEvent] = [ProcessEvent(**p) for p in (proc_data if isinstance(proc_data, list) else [])]

        # ── 4. File drops ─────────────────────────────────────────────────────
        file_data = await _post(
            client, f"{FILESYSTEM_URL}/query/drops",
            {"user": trigger.user, "host": trigger.host,
             "window_seconds": 600, "suspicious_only": True}
        )
        file_events: list[FileEvent] = [FileEvent(**f) for f in (file_data if isinstance(file_data, list) else [])]

        # ── 5. Network connections ────────────────────────────────────────────
        net_data = await _post(
            client, f"{NETWORK_URL}/query/connections",
            {"user": trigger.user, "host": trigger.host, "window_seconds": 600}
        )
        net_events: list[NetworkEvent] = [NetworkEvent(**n) for n in (net_data if isinstance(net_data, list) else [])]

        # ── 6. Threat intel enrichment ────────────────────────────────────────
        dropped_hashes = [fe.file_hash for fe in file_events if fe.file_hash]
        dest_ips = [ne.dst_ip for ne in net_events]
        dest_domains = [ne.dns_query for ne in net_events if ne.dns_query]

        intel_data = await _post(
            client, f"{THREATINTEL_URL}/enrich",
            {
                "hashes": [trigger.pdf_hash] + dropped_hashes,
                "ips": dest_ips,
                "domains": dest_domains,
            }
        )
        intel = ThreatIntelResult(**intel_data) if intel_data else ThreatIntelResult()

    # ── 7. Assemble runtime context ───────────────────────────────────────────
    child_proc_names = [p.name for p in processes]
    commands = [p.cmdline for p in processes if p.cmdline]
    dropped_files = [fe.path for fe in file_events if fe.operation == "create"]
    executed_files = [fe.path for fe in file_events if fe.operation == "execute"]
    network_dests = list(set(dest_ips + dest_domains))

    runtime = RuntimeContext(
        reader_process="AcroRd32.exe" if processes else None,
        child_processes=child_proc_names,
        commands=commands,
        dropped_files=dropped_files,
        executed_files=executed_files,
        network_destinations=network_dests,
        dns_queries=dest_domains,
    )

    # ── 8. PDF context ────────────────────────────────────────────────────────
    origin = trigger.origin
    sender = ""
    sender_rep = "unknown"

    if email:
        origin = "external_email" if email.is_external else "internal_email"
        sender = email.sender
        sender_rep = email.sender_reputation

    pdf_ctx = PDFContext(
        hash=trigger.pdf_hash,
        path=trigger.pdf_path,
        origin=origin,
        sender=sender,
        sender_reputation=sender_rep,
        embedded_js=pdf_analysis.has_javascript if pdf_analysis else False,
        open_action=pdf_analysis.has_open_action if pdf_analysis else False,
        embedded_files=pdf_analysis.has_embedded_files if pdf_analysis else 0,
        obfuscation_score=pdf_analysis.obfuscation_score if pdf_analysis else 0.0,
        suspicious_keywords=pdf_analysis.suspicious_keywords if pdf_analysis else [],
    )

    # ── 9. Baseline comparison ────────────────────────────────────────────────
    baseline = compute_baseline(trigger.user, trigger.host, runtime)

    # ── 10. Assemble unified context ──────────────────────────────────────────
    ctx = UnifiedContext(
        user=trigger.user,
        host=trigger.host,
        pdf=pdf_ctx,
        runtime=runtime,
        baseline=baseline,
        intel=intel,
    )

    log.info(f"Context built for case {ctx.case_id}: "
             f"children={len(child_proc_names)}, drops={len(dropped_files)}, "
             f"network={len(network_dests)}")

    return ctx
