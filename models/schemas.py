"""
models/schemas.py
All Pydantic models used across the system.
These define the shape of every event, context object, and response.
"""
from __future__ import annotations
from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field
import uuid


# ─── Raw Event Models (ingested from telemetry sources) ───────────────────────

class EmailMetadata(BaseModel):
    sender: str
    sender_domain: str
    subject: str
    received_at: datetime
    attachment_name: str
    attachment_hash: str
    is_external: bool = True
    spf_pass: bool = False
    dkim_pass: bool = False
    sender_reputation: str = "unknown"  # clean | suspicious | malicious | unknown


class PDFAnalysisResult(BaseModel):
    hash: str
    path: str
    file_size: int
    has_javascript: bool = False
    has_open_action: bool = False
    has_embedded_files: int = 0
    has_launch_action: bool = False
    has_uri_action: bool = False
    has_acroform: bool = False
    obfuscation_score: float = 0.0       # 0.0 – 1.0
    entropy: float = 0.0
    suspicious_keywords: list[str] = Field(default_factory=list)
    streams_count: int = 0
    pdf_version: str = "unknown"


class ProcessEvent(BaseModel):
    pid: int
    name: str
    cmdline: str
    parent_pid: int
    parent_name: str
    user: str
    host: str
    timestamp: datetime
    event_type: str = "create"  # create | terminate


class FileEvent(BaseModel):
    path: str
    operation: str          # create | write | delete | rename | execute
    process_name: str
    process_pid: int
    user: str
    host: str
    timestamp: datetime
    file_hash: Optional[str] = None


class NetworkEvent(BaseModel):
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    process_name: str
    process_pid: int
    user: str
    host: str
    timestamp: datetime
    bytes_sent: int = 0
    dns_query: Optional[str] = None


class ThreatIntelResult(BaseModel):
    hash_reputation: str = "unknown"     # clean | suspicious | malicious | unknown
    ip_reputation: str = "unknown"
    domain_reputation: str = "unknown"
    hash_detections: int = 0
    ip_tags: list[str] = Field(default_factory=list)
    domain_tags: list[str] = Field(default_factory=list)
    source: str = "mock"


class BaselineResult(BaseModel):
    user_usually_runs_powershell: bool = False
    user_usually_runs_cmd: bool = False
    host_seen_destination_before: bool = False
    pdf_reader_spawning_scripts_rarity: float = 0.0   # 0.0 = common, 1.0 = never seen
    user_anomaly_score: float = 0.0
    host_anomaly_score: float = 0.0


# ─── Unified Context Object ────────────────────────────────────────────────────

class PDFContext(BaseModel):
    hash: str
    path: str
    origin: str = "unknown"             # external_email | download | internal
    sender: Optional[str] = None
    sender_reputation: str = "unknown"
    embedded_js: bool = False
    open_action: bool = False
    embedded_files: int = 0
    obfuscation_score: float = 0.0
    suspicious_keywords: list[str] = Field(default_factory=list)


class RuntimeContext(BaseModel):
    reader_process: Optional[str] = None
    child_processes: list[str] = Field(default_factory=list)
    commands: list[str] = Field(default_factory=list)
    dropped_files: list[str] = Field(default_factory=list)
    executed_files: list[str] = Field(default_factory=list)
    network_destinations: list[str] = Field(default_factory=list)
    dns_queries: list[str] = Field(default_factory=list)


class ScoreBreakdown(BaseModel):
    source_score: int = 0
    pdf_score: int = 0
    behavior_score: int = 0
    anomaly_score: int = 0
    intel_score: int = 0
    total_score: int = 0
    risk_level: str = "low"             # low | medium | high | critical


class UnifiedContext(BaseModel):
    case_id: str = Field(default_factory=lambda: f"case_{uuid.uuid4().hex[:8]}")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    user: str
    host: str
    pdf: PDFContext
    runtime: RuntimeContext = Field(default_factory=RuntimeContext)
    baseline: BaselineResult = Field(default_factory=BaselineResult)
    intel: ThreatIntelResult = Field(default_factory=ThreatIntelResult)
    scores: ScoreBreakdown = Field(default_factory=ScoreBreakdown)


# ─── LLM Reasoning Output ─────────────────────────────────────────────────────

class LLMReasoningOutput(BaseModel):
    classification: str                 # benign | suspicious | malicious
    confidence: float
    risk_level: str                     # low | medium | high | critical
    explanation: list[str]
    recommended_action: str             # log_only | alert_analyst | kill_process | quarantine_file | isolate_host
    attack_stage: str                   # initial_access | execution | persistence | c2 | exfiltration | unknown
    llm_available: bool = True


# ─── Attack Graph ──────────────────────────────────────────────────────────────

class GraphNode(BaseModel):
    node_id: str
    node_type: str      # email | pdf | reader_process | child_process | dropped_file | executed_file | network_ip | domain
    label: str
    attributes: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str       # delivered_to | opened_by | spawned | wrote | executed | connected_to


class AttackGraph(BaseModel):
    case_id: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ─── Response / Decision ──────────────────────────────────────────────────────

class ResponseAction(BaseModel):
    action: str                         # log_only | alert_analyst | kill_process | quarantine_file | isolate_host
    target: Optional[str] = None        # pid, file path, host id
    reason: str
    simulated: bool = True
    executed_at: datetime = Field(default_factory=datetime.utcnow)
    result: str = "pending"


# ─── Case Record (stored in DB) ───────────────────────────────────────────────

class CaseRecord(BaseModel):
    case_id: str
    created_at: datetime
    user: str
    host: str
    pdf_hash: str
    risk_level: str
    total_score: int
    classification: str
    recommended_action: str
    analyst_verdict: Optional[str] = None   # confirmed_tp | false_positive | under_review
    context_json: str                        # serialized UnifiedContext
    graph_json: str                          # serialized AttackGraph
    llm_output_json: str                     # serialized LLMReasoningOutput
    response_json: str                       # serialized ResponseAction


# ─── Trigger Event (entry point into the system) ──────────────────────────────

class TriggerEvent(BaseModel):
    """Sent to the MCP orchestrator to kick off a full analysis pipeline."""
    event_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    pdf_path: str
    pdf_hash: str
    user: str
    host: str
    origin: str = "unknown"
    email_metadata: Optional[EmailMetadata] = None
    triggered_at: datetime = Field(default_factory=datetime.utcnow)
