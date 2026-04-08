"""
models/db_models.py
SQLAlchemy ORM models.
Each table maps to a domain concept: cases, events, baselines, decisions.
"""
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, JSON
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class CaseTable(Base):
    __tablename__ = "cases"

    case_id = Column(String, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = Column(String, nullable=False)
    host = Column(String, nullable=False)
    pdf_hash = Column(String, nullable=False)
    pdf_path = Column(String)
    risk_level = Column(String)                 # low | medium | high | critical
    total_score = Column(Integer, default=0)
    classification = Column(String)             # benign | suspicious | malicious
    recommended_action = Column(String)
    analyst_verdict = Column(String, nullable=True)
    context_json = Column(Text)                 # full UnifiedContext as JSON string
    graph_json = Column(Text)                   # AttackGraph as JSON string
    llm_output_json = Column(Text)
    response_json = Column(Text)


class RawEventTable(Base):
    """Stores every raw telemetry event before normalization."""
    __tablename__ = "raw_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String, nullable=True)
    event_type = Column(String)                 # process | file | network | pdf | email
    source = Column(String)                     # which MCP server produced it
    payload = Column(Text)                      # raw JSON string
    received_at = Column(DateTime, default=datetime.utcnow)


class BaselineTable(Base):
    """Per-user and per-host behavioral baselines."""
    __tablename__ = "baselines"

    id = Column(Integer, primary_key=True, autoincrement=True)
    entity_type = Column(String)                # user | host
    entity_id = Column(String)                  # username or hostname
    feature = Column(String)                    # e.g. "runs_powershell"
    value = Column(Float, default=0.0)          # frequency / probability
    sample_count = Column(Integer, default=0)
    last_updated = Column(DateTime, default=datetime.utcnow)


class ThreatIntelCacheTable(Base):
    """Cache threat intel lookups to avoid repeated API calls."""
    __tablename__ = "threat_intel_cache"

    id = Column(Integer, primary_key=True, autoincrement=True)
    indicator_type = Column(String)             # hash | ip | domain
    indicator_value = Column(String, unique=True)
    reputation = Column(String)
    tags = Column(JSON)
    detections = Column(Integer, default=0)
    source = Column(String)
    cached_at = Column(DateTime, default=datetime.utcnow)


class ResponseLogTable(Base):
    """Audit log of every response action taken."""
    __tablename__ = "response_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String)
    action = Column(String)
    target = Column(String, nullable=True)
    reason = Column(Text)
    simulated = Column(Boolean, default=True)
    result = Column(String)
    executed_at = Column(DateTime, default=datetime.utcnow)
