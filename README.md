# MCP-Based Context-Aware PDF Attack Chain Intelligence System

A research-grade security prototype that detects malicious PDF-driven attack chains by fusing multi-layer telemetry, behavioral baselines, threat intelligence, and LLM reasoning.

---

## Architecture

```
                        ┌─────────────────────────────────┐
                        │     MCP Client / Orchestrator    │
                        │         (api/main.py)            │
                        │    run_pipeline(TriggerEvent)    │
                        └──────────────┬──────────────────┘
                                       │ queries
          ┌────────────────────────────┼────────────────────────────┐
          │                            │                            │
   ┌──────▼──────┐            ┌────────▼───────┐          ┌────────▼───────┐
   │ Email Server│            │  PDF Server    │          │Endpoint Server │
   │  port 8001  │            │  port 8002     │          │  port 8003     │
   └─────────────┘            └────────────────┘          └────────────────┘
          │                            │                            │
   ┌──────▼──────┐            ┌────────▼───────┐          ┌────────▼───────┐
   │  FS Server  │            │Network Server  │          │ThreatIntel Srv │
   │  port 8004  │            │  port 8005     │          │  port 8006     │
   └─────────────┘            └────────────────┘          └────────────────┘
          │                            │                            │
   ┌──────▼──────┐            ┌────────▼───────┐
   │Response Srv │            │ Memory Server  │
   │  port 8007  │            │  port 8008     │
   └─────────────┘            └────────────────┘
```

## Full Pipeline (18 Steps)

```
Email/Download → PDF on disk → PDF opened → Reader process
→ Child process → File drop → Execution → Network connection
→ Threat intel → Baseline comparison → Context fusion
→ Attack graph → Risk score → LLM reasoning → Response → Memory
```

## Project Structure

```
cyber/
├── api/
│   └── main.py                    # FastAPI orchestrator API (port 8000)
├── mcp_client/
│   └── orchestrator.py            # Central pipeline runner
├── mcp_servers/
│   ├── email_server/server.py     # Email metadata (port 8001)
│   ├── pdf_server/server.py       # PDF static analysis (port 8002)
│   ├── endpoint_server/server.py  # Process telemetry (port 8003)
│   ├── filesystem_server/server.py# File events (port 8004)
│   ├── network_server/server.py   # Network connections (port 8005)
│   ├── threatintel_server/server.py# Threat intel (port 8006)
│   ├── response_server/server.py  # Response actions (port 8007)
│   └── memory_server/server.py    # Case history (port 8008)
├── core/
│   ├── correlation/context_builder.py  # Fuses all MCP outputs
│   ├── graph/builder.py                # NetworkX attack graph
│   ├── scoring/engine.py               # Deterministic risk scoring
│   ├── llm/reasoner.py                 # LLM reasoning + fallback
│   ├── response/decision_engine.py     # Action selection
│   └── baseline/engine.py             # User/host anomaly detection
├── models/
│   ├── schemas.py                 # All Pydantic models
│   ├── db_models.py               # SQLAlchemy ORM models
│   └── database.py                # Async DB engine
├── config/
│   └── settings.py                # Central config from .env
├── utils/
│   ├── helpers.py                 # Shared utilities
│   └── logger.py                  # Rich logger
├── data/
│   └── mock_telemetry/            # Test scenarios
├── tests/
│   └── test_pipeline.py           # Pytest test suite
├── utils/
│   ├── helpers.py                 # Shared utilities
│   ├── logger.py                  # Rich logger
│   └── notifier.py                # Desktop notification sender
├── run_all.py                     # Launch all servers
├── watch.py                       # Background PDF watcher + notifier
├── demo.py                        # End-to-end demo
├── requirements.txt
└── .env                           # Configuration
```

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
pip install pydantic-settings  # required for config
```

### 2. Configure

Edit `.env` — at minimum set your LLM API key if you want LLM reasoning:
```
LLM_API_KEY=sk-your-key-here
```
The system works without an LLM key using rule-based fallback.

### 3. Start all servers

```bash
python run_all.py
```

### 4. Run the background watcher (real-time PDF monitoring)

```bash
# Watch ~/Downloads (default), servers must already be running
python watch.py

# Watch a custom folder
python watch.py /path/to/folder

# Start servers automatically then watch
python watch.py --start-servers
```

Whenever a PDF is opened or saved in the watched folder, the full pipeline runs and a desktop notification appears with the risk result.

### 5. Run the demo (manual one-shot)

```bash
# With mock data
python demo.py

# With a real PDF
python demo.py /path/to/real.pdf
```

### 5. Run tests

```bash
pytest tests/ -v
```

### 6. Use the API directly

```bash
# Trigger analysis
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "pdf_path": "/tmp/invoice_q2.pdf",
    "pdf_hash": "deadbeef1234",
    "user": "jdoe",
    "host": "WORKSTATION-01",
    "origin": "external_email"
  }'

# Check health
curl http://localhost:8000/health

# List cases
curl http://localhost:8000/cases

# API docs
open http://localhost:8000/docs
```

---

## Risk Scoring

| Dimension     | Max Score | What it measures                          |
|---------------|-----------|-------------------------------------------|
| Source        | 30        | Email origin, sender reputation           |
| PDF Structure | 50        | JS, OpenAction, embedded files, entropy   |
| Behavior      | 60        | Child processes, file drops, network      |
| Anomaly       | 40        | Deviation from user/host baseline         |
| Threat Intel  | 30        | Hash/IP/domain reputation                 |
| **Total**     | **210**   |                                           |

| Level    | Score Range |
|----------|-------------|
| Low      | 0–29        |
| Medium   | 30–69       |
| High     | 70–119      |
| Critical | 120+        |

---

## Context Object

The system produces a unified context object for every case:

```json
{
  "case_id": "case_abc12345",
  "user": "jdoe",
  "host": "WORKSTATION-01",
  "pdf": {
    "hash": "deadbeef1234",
    "origin": "external_email",
    "sender_reputation": "malicious",
    "embedded_js": true,
    "open_action": true,
    "obfuscation_score": 0.85
  },
  "runtime": {
    "reader_process": "AcroRd32.exe",
    "child_processes": ["powershell.exe", "cmd.exe"],
    "dropped_files": ["C:\\...\\temp.exe"],
    "network_destinations": ["185.220.101.45"]
  },
  "scores": {
    "total_score": 175,
    "risk_level": "critical"
  }
}
```

---

## Attack Graph

Nodes: `email → pdf → reader_process → child_process → dropped_file → executed_file → network_ip`

Edges: `delivered_to | opened_by | spawned | wrote | executed | connected_to`

---

## Response Actions

| Action           | Trigger Condition              | Mode       |
|------------------|-------------------------------|------------|
| `log_only`       | Low risk                       | Always     |
| `alert_analyst`  | Medium risk                    | Always     |
| `kill_process`   | High risk + active process     | Simulate   |
| `quarantine_file`| High risk + dropped executable | Simulate   |
| `isolate_host`   | Critical risk only             | Simulate   |

Set `RESPONSE_MODE=enforce` in `.env` to enable real actions.

---

## Extending the System

- **Add a new MCP server**: Create `mcp_servers/new_server/server.py`, add port to `.env`, query it in `core/correlation/context_builder.py`
- **Add scoring dimension**: Add a `_score_*` function in `core/scoring/engine.py`
- **Swap LLM**: Change `LLM_PROVIDER` and `LLM_BASE_URL` in `.env` (any OpenAI-compatible API works)
- **Add real telemetry**: Replace mock seed endpoints with Sysmon/EDR/Zeek connectors

---

## Research Value

- **Cross-layer fusion**: Email + PDF + Process + File + Network + Baseline + Intel
- **Explainable scoring**: Every point has a labeled reason
- **Attack chain graph**: Full kill chain as a queryable graph
- **LLM as analyst**: Structured reasoning over pre-computed context
- **Adaptive response**: Graduated actions based on confidence + risk
- **Case memory**: Historical cases improve future detection
