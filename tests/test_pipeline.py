"""
tests/test_pipeline.py

Test suite for the core pipeline components.
Tests run without any external services (no MCP servers needed).
Uses mock data to validate scoring, graph building, and baseline logic.
"""
import pytest
import os
from datetime import datetime
from models.schemas import (
    UnifiedContext, PDFContext, RuntimeContext, BaselineResult,
    ThreatIntelResult, ScoreBreakdown, TriggerEvent, AttackGraph,
    WhatsAppMetadata,
)
from core.scoring.engine import compute_risk_score
from core.graph.builder import build_attack_graph, graph_to_summary
from core.baseline.engine import compute_baseline


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_malicious_context() -> UnifiedContext:
    """Full attack chain context — should score critical."""
    return UnifiedContext(
        user="jdoe",
        host="WORKSTATION-01",
        pdf=PDFContext(
            hash="deadbeef1234",
            path="/tmp/invoice_q2.pdf",
            origin="external_email",
            sender="attacker@evil-domain.ru",
            sender_reputation="malicious",
            embedded_js=True,
            open_action=True,
            embedded_files=1,
            obfuscation_score=0.85,
            suspicious_keywords=["/JS", "/OpenAction", "/EmbeddedFile"],
        ),
        runtime=RuntimeContext(
            reader_process="AcroRd32.exe",
            child_processes=["powershell.exe", "cmd.exe"],
            commands=["powershell -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdA=="],
            dropped_files=["C:\\Users\\jdoe\\AppData\\Local\\Temp\\temp.exe"],
            executed_files=["C:\\Users\\jdoe\\AppData\\Local\\Temp\\temp.exe"],
            network_destinations=["185.220.101.45", "c2.evil-domain.ru"],
        ),
        baseline=BaselineResult(
            user_usually_runs_powershell=False,
            user_usually_runs_cmd=False,
            host_seen_destination_before=False,
            pdf_reader_spawning_scripts_rarity=0.98,
            user_anomaly_score=0.8,
            host_anomaly_score=0.3,
        ),
        intel=ThreatIntelResult(
            hash_reputation="malicious",
            ip_reputation="malicious",
            domain_reputation="malicious",
            hash_detections=45,
            ip_tags=["tor_exit_node", "c2_server"],
            domain_tags=["phishing"],
        ),
    )


def make_benign_context() -> UnifiedContext:
    """Normal PDF open — should score low."""
    return UnifiedContext(
        user="admin",
        host="SERVER-01",
        pdf=PDFContext(
            hash="aabbcc9900",
            path="/home/admin/report.pdf",
            origin="internal_email",
            sender="hr@company.com",
            sender_reputation="clean",
            embedded_js=False,
            open_action=False,
            embedded_files=0,
            obfuscation_score=0.0,
        ),
        runtime=RuntimeContext(
            reader_process="evince",
            child_processes=[],
            commands=[],
            dropped_files=[],
            executed_files=[],
            network_destinations=[],
        ),
        baseline=BaselineResult(
            user_usually_runs_powershell=True,
            user_usually_runs_cmd=True,
            host_seen_destination_before=True,
            pdf_reader_spawning_scripts_rarity=0.0,
            user_anomaly_score=0.0,
            host_anomaly_score=0.0,
        ),
        intel=ThreatIntelResult(
            hash_reputation="clean",
            ip_reputation="clean",
            domain_reputation="clean",
        ),
    )


# ── Scoring Tests ─────────────────────────────────────────────────────────────

def test_malicious_context_scores_critical():
    ctx = make_malicious_context()
    breakdown, reasons = compute_risk_score(ctx)
    assert breakdown.risk_level == "critical", f"Expected critical, got {breakdown.risk_level}"
    assert breakdown.total_score >= 120
    assert len(reasons) > 0


def test_benign_context_scores_low():
    ctx = make_benign_context()
    breakdown, reasons = compute_risk_score(ctx)
    assert breakdown.risk_level == "low", f"Expected low, got {breakdown.risk_level}"
    assert breakdown.total_score < 30


def test_score_breakdown_components():
    ctx = make_malicious_context()
    breakdown, _ = compute_risk_score(ctx)
    # Each component should be non-zero for a malicious context
    assert breakdown.source_score > 0
    assert breakdown.pdf_score > 0
    assert breakdown.behavior_score > 0
    assert breakdown.anomaly_score > 0
    assert breakdown.intel_score > 0


def test_score_components_within_bounds():
    ctx = make_malicious_context()
    breakdown, _ = compute_risk_score(ctx)
    assert 0 <= breakdown.source_score <= 30
    assert 0 <= breakdown.pdf_score <= 50
    assert 0 <= breakdown.behavior_score <= 60
    assert 0 <= breakdown.anomaly_score <= 40
    assert 0 <= breakdown.intel_score <= 30


# ── Graph Tests ───────────────────────────────────────────────────────────────

def test_attack_graph_builds_correctly():
    ctx = make_malicious_context()
    graph = build_attack_graph(ctx)
    assert isinstance(graph, AttackGraph)
    assert len(graph.nodes) > 0
    assert len(graph.edges) > 0


def test_attack_graph_has_expected_node_types():
    ctx = make_malicious_context()
    graph = build_attack_graph(ctx)
    node_types = {n.node_type for n in graph.nodes}
    assert "pdf" in node_types
    assert "reader_process" in node_types
    assert "child_process" in node_types


def test_attack_graph_has_expected_edges():
    ctx = make_malicious_context()
    graph = build_attack_graph(ctx)
    relations = {e.relation for e in graph.edges}
    assert "spawned" in relations
    assert "wrote" in relations
    assert "connected_to" in relations


def test_graph_summary():
    ctx = make_malicious_context()
    graph = build_attack_graph(ctx)
    summary = graph_to_summary(graph)
    assert "total_nodes" in summary
    assert "total_edges" in summary
    assert summary["total_nodes"] > 0


# ── Baseline Tests ────────────────────────────────────────────────────────────

def test_baseline_detects_anomaly():
    runtime = RuntimeContext(
        child_processes=["powershell.exe"],
        commands=["powershell -enc ..."],
        network_destinations=["185.220.101.45"],
    )
    result = compute_baseline("jdoe", "WORKSTATION-01", runtime)
    assert result.user_anomaly_score > 0
    assert result.pdf_reader_spawning_scripts_rarity > 0.9


def test_baseline_normal_admin():
    runtime = RuntimeContext(
        child_processes=["powershell.exe"],
        commands=["powershell Get-Process"],
        network_destinations=[],
    )
    result = compute_baseline("admin", "SERVER-01", runtime)
    # Admin normally runs PowerShell — should not be anomalous
    assert result.user_usually_runs_powershell is True


# ── Context Object Tests ──────────────────────────────────────────────────────

def test_unified_context_serialization():
    ctx = make_malicious_context()
    json_str = ctx.model_dump_json()
    assert "case_id" in json_str
    assert "deadbeef1234" in json_str


def test_trigger_event_creation():
    trigger = TriggerEvent(
        pdf_path="/tmp/test.pdf",
        pdf_hash="abc123",
        user="testuser",
        host="testhost",
        origin="external_email",
    )
    assert trigger.event_id != ""
    assert trigger.user == "testuser"


# ── WhatsApp Detection Tests ─────────────────────────────────────────────────────

WA_CACHE_PATH = os.path.expanduser(
    "~/Library/Containers/net.whatsapp.WhatsApp/Data/Library/Caches/DOC-20240601-WA0003.pdf"
)


def make_whatsapp_context(chat_type: str = "individual", sender_jid: str = None) -> UnifiedContext:
    return UnifiedContext(
        user="jdoe",
        host="MACBOOK-01",
        pdf=PDFContext(
            hash="wa1234abcd",
            path=WA_CACHE_PATH,
            origin="whatsapp_preview",
            sender="",
            sender_reputation="unknown",
            embedded_js=False,
            open_action=False,
        ),
        runtime=RuntimeContext(),
        baseline=BaselineResult(),
        intel=ThreatIntelResult(),
        whatsapp=WhatsAppMetadata(
            app_name="WhatsApp",
            sender_jid=sender_jid,
            chat_type=chat_type,
            preview_only=True,
            confidence=0.9,
        ),
    )


def test_whatsapp_origin_scores_source_correctly():
    """whatsapp_preview origin should score 15 base + extras, capped at 30."""
    ctx = make_whatsapp_context(chat_type="individual", sender_jid="919876543210@s.whatsapp.net")
    breakdown, reasons = compute_risk_score(ctx)
    assert breakdown.source_score >= 15
    assert breakdown.source_score <= 30
    assert any("WhatsApp" in r for r in reasons)


def test_whatsapp_group_chat_adds_score():
    """Group chat should add +5 on top of base +15."""
    ctx_individual = make_whatsapp_context(chat_type="individual", sender_jid="123@s.whatsapp.net")
    ctx_group = make_whatsapp_context(chat_type="group", sender_jid="123@s.whatsapp.net")
    score_individual, _ = compute_risk_score(ctx_individual)
    score_group, _ = compute_risk_score(ctx_group)
    assert score_group.source_score > score_individual.source_score


def test_whatsapp_unknown_sender_adds_score():
    """Unknown sender JID should add +3."""
    ctx_known = make_whatsapp_context(sender_jid="919876543210@s.whatsapp.net")
    ctx_unknown = make_whatsapp_context(sender_jid=None)
    score_known, _ = compute_risk_score(ctx_known)
    score_unknown, _ = compute_risk_score(ctx_unknown)
    assert score_unknown.source_score > score_known.source_score


def test_whatsapp_does_not_affect_email_scoring():
    """Existing email-origin scoring must be unchanged."""
    ctx = make_malicious_context()  # origin=external_email, no whatsapp field
    breakdown, reasons = compute_risk_score(ctx)
    assert breakdown.source_score > 0
    assert not any("WhatsApp" in r for r in reasons)


def test_whatsapp_context_serialization():
    """UnifiedContext with WhatsAppMetadata must serialize cleanly."""
    ctx = make_whatsapp_context()
    data = ctx.model_dump()
    assert data["whatsapp"]["app_name"] == "WhatsApp"
    assert data["whatsapp"]["preview_only"] is True


def test_non_whatsapp_context_has_no_whatsapp_field():
    """Normal contexts must have whatsapp=None."""
    ctx = make_benign_context()
    assert ctx.whatsapp is None
