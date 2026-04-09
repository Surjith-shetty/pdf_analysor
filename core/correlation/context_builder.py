"""
core/correlation/context_builder.py

Context Fusion Engine — queries all MCP servers via stdio and assembles UnifiedContext.
build_context() is the single entry point used by the orchestrator.
"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from models.schemas import (
    TriggerEvent, UnifiedContext, PDFContext, RuntimeContext,
    EmailMetadata, PDFAnalysisResult, ProcessEvent, FileEvent,
    NetworkEvent, ThreatIntelResult, WhatsAppMetadata,
)
from core.baseline.engine import compute_baseline
from utils.logger import get_logger

log = get_logger("context_builder")

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SERVER_MODULES = {
    "email":       "mcp_servers.email_server.server",
    "pdf":         "mcp_servers.pdf_server.server",
    "endpoint":    "mcp_servers.endpoint_server.server",
    "filesystem":  "mcp_servers.filesystem_server.server",
    "network":     "mcp_servers.network_server.server",
    "threatintel": "mcp_servers.threatintel_server.server",
    "whatsapp":    "mcp_servers.whatsapp_server.server",
}


async def _call(server_name: str, tool: str, args: dict) -> dict | list:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", SERVER_MODULES[server_name]],
        env={**os.environ, "PYTHONPATH": _ROOT},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool, args)
            return json.loads(result.content[0].text)


async def build_context(trigger: TriggerEvent) -> UnifiedContext:
    # 1. Email metadata — use real data from trigger if provided, else mock lookup
    if trigger.email_metadata:
        email = trigger.email_metadata
    else:
        email_data = await _call("email", "query_email_metadata",
                                 {"attachment_hash": trigger.pdf_hash, "sender": ""})
        email = EmailMetadata(**email_data) if email_data else None

    # 1b. WhatsApp metadata — only when origin is whatsapp_preview
    whatsapp_meta = None
    if trigger.origin == "whatsapp_preview":
        wa_data = await _call("whatsapp", "detect_whatsapp_source", {"pdf_path": trigger.pdf_path})
        whatsapp_meta = WhatsAppMetadata(**wa_data) if wa_data else WhatsAppMetadata(confidence=0.5)

    # 2. PDF analysis
    pdf_data = await _call("pdf", "analyze_pdf",
                           {"pdf_path": trigger.pdf_path, "pdf_hash": trigger.pdf_hash})
    pdf_analysis = PDFAnalysisResult(**pdf_data) if pdf_data else None

    # 3. Child processes
    proc_data = await _call("endpoint", "query_child_processes",
                            {"parent_name": "AcroRd32.exe", "user": trigger.user,
                             "host": trigger.host, "window_seconds": 600})
    processes = [ProcessEvent(**p) for p in (proc_data if isinstance(proc_data, list) else [])]

    # 4. File drops
    file_data = await _call("filesystem", "query_file_drops",
                            {"user": trigger.user, "host": trigger.host,
                             "window_seconds": 600, "suspicious_only": True})
    file_events = [FileEvent(**f) for f in (file_data if isinstance(file_data, list) else [])]

    # 5. Network connections
    net_data = await _call("network", "query_connections",
                           {"user": trigger.user, "host": trigger.host, "window_seconds": 600})
    net_events = [NetworkEvent(**n) for n in (net_data if isinstance(net_data, list) else [])]

    # 6. Threat intel
    dropped_hashes = [fe.file_hash for fe in file_events if fe.file_hash]
    dest_ips = [ne.dst_ip for ne in net_events]
    dest_domains = [ne.dns_query for ne in net_events if ne.dns_query]
    intel_data = await _call("threatintel", "enrich_indicators", {
        "hashes": [trigger.pdf_hash] + dropped_hashes,
        "ips": dest_ips,
        "domains": dest_domains,
    })
    intel = ThreatIntelResult(**intel_data) if intel_data else ThreatIntelResult()

    # Assemble
    child_proc_names = [p.name for p in processes]
    dropped_files = [fe.path for fe in file_events if fe.operation == "create"]
    executed_files = [fe.path for fe in file_events if fe.operation == "execute"]
    network_dests = list(set(dest_ips + dest_domains))

    runtime = RuntimeContext(
        reader_process="AcroRd32.exe" if processes else None,
        child_processes=child_proc_names,
        commands=[p.cmdline for p in processes if p.cmdline],
        dropped_files=dropped_files,
        executed_files=executed_files,
        network_destinations=network_dests,
        dns_queries=dest_domains,
    )

    origin = trigger.origin
    sender, sender_rep = "", "unknown"
    if email:
        origin = "external_email" if email.is_external else "internal_email"
        sender = email.sender
        sender_rep = email.sender_reputation

    pdf_ctx = PDFContext(
        hash=trigger.pdf_hash, path=trigger.pdf_path, origin=origin,
        sender=sender, sender_reputation=sender_rep,
        embedded_js=pdf_analysis.has_javascript if pdf_analysis else False,
        open_action=pdf_analysis.has_open_action if pdf_analysis else False,
        embedded_files=pdf_analysis.has_embedded_files if pdf_analysis else 0,
        obfuscation_score=pdf_analysis.obfuscation_score if pdf_analysis else 0.0,
        entropy=pdf_analysis.entropy if pdf_analysis else 0.0,
        suspicious_keywords=pdf_analysis.suspicious_keywords if pdf_analysis else [],
    )

    baseline = compute_baseline(trigger.user, trigger.host, runtime)

    ctx = UnifiedContext(
        user=trigger.user, host=trigger.host,
        pdf=pdf_ctx, runtime=runtime, baseline=baseline, intel=intel,
        whatsapp=whatsapp_meta,
    )
    log.info(f"Context built for case {ctx.case_id}: "
             f"children={len(child_proc_names)}, drops={len(dropped_files)}, "
             f"network={len(network_dests)}")
    return ctx
