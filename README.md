# MCP-Based Context-Aware PDF Attack Chain Intelligence System

A research-grade security prototype that detects malicious PDF-driven attack chains by fusing multi-layer telemetry, behavioral baselines, threat intelligence, and LLM reasoning.

---

## Architecture

MCP servers are **not** long-running HTTP processes. They are spawned on-demand as **stdio subprocesses** by the MCP client, communicate via JSON-RPC 2.0 over stdin/stdout, and exit when done. No ports are needed for inter-server communication.

```
                        ┌─────────────────────────────────┐
                        │        FastAPI HTTP API          │
                        │         (api/main.py)            │
                        │          port 8000               │
                        └──────────────┬──────────────────┘
                                       │
                        ┌──────────────▼──────────────────┐
                        │     MCP Client / Orchestrator    │
                        │     (mcp_client/orchestrator.py) │
                        │       ClientSession + stdio      │
                        └──────────────┬──────────────────┘
                                       │ spawns subprocesses (stdio JSON-RPC)
          ┌────────────────────────────┼────────────────────────────┐
          │                            │                            │
   ┌──────▼──────┐            ┌────────▼───────┐          ┌────────▼───────┐
   │ email_server│            │  pdf_server    │          │endpoint_server │
   │  (stdio)    │            │  (stdio)       │          │  (stdio)       │
   └─────────────┘            └────────────────┘          └────────────────┘
   ┌─────────────┐            ┌────────────────┐          ┌────────────────┐
   │filesystem_  │            │network_server  │          │threatintel_    │
   │server(stdio)│            │  (stdio)       │          │server (stdio)  │
   └─────────────┘            └────────────────┘          └────────────────┘
   ┌─────────────┐            ┌────────────────┐
   │response_    │            │ memory_server  │
   │server(stdio)│            │  (stdio)       │
   └─────────────┘            └────────────────┘
```

### How MCP is used

Each server is a proper MCP server using the official `mcp` Python SDK:

- **Transport**: `stdio` — JSON-RPC 2.0 over stdin/stdout
- **Server side**: `mcp.server.Server` + `@server.list_tools()` / `@server.call_tool()`
- **Client side**: `mcp.ClientSession` + `StdioServerParameters` + `stdio_client`
- **Invocation**: `await session.call_tool(tool_name, args)`

Servers are spawned per-call via `subprocess` and terminated automatically — no persistent processes, no ports, no HTTP between components.

---

## Full Pipeline (7 Steps)

```
[1] Build unified context   → MCP calls to email, pdf, endpoint, filesystem, network, threatintel servers
[2] Build attack graph      → NetworkX graph from context (local)
[3] Compute risk score      → Deterministic scoring engine (local)
[4] LLM reasoning           → Groq/OpenAI-compatible API call
[5] Execute response        → MCP call to response_server
[6] Save to memory          → MCP call to memory_server
[7] Return result           → FastAPI response to caller
```

---

## MCP Tools by Server

| Server | Tools |
|--------|-------|
| `email_server` | `query_email_metadata` |
| `pdf_server` | `analyze_pdf` |
| `endpoint_server` | `ingest_process_event`, `query_child_processes`, `seed_mock_processes` |
| `filesystem_server` | `ingest_file_event`, `query_file_drops`, `seed_mock_files` |
| `network_server` | `ingest_network_event`, `query_connections`, `seed_mock_network` |
| `threatintel_server` | `enrich_indicators` |
| `response_server` | `execute_action` |
| `memory_server` | `save_case`, `get_case`, `list_cases`, `update_verdict`, `lookup_by_hash` |

---

## Project Structure

```
cyber2/
├── api/
│   └── main.py                    # FastAPI HTTP API (port 8000)
├── mcp_client/
│   └── orchestrator.py            # MCP client — runs the 7-step pipeline
├── mcp_servers/
│   ├── email_server/server.py     # MCP server: email metadata
│   ├── pdf_server/server.py       # MCP server: PDF static analysis
│   ├── endpoint_server/server.py  # MCP server: process telemetry
│   ├── filesystem_server/server.py# MCP server: file events
│   ├── network_server/server.py   # MCP server: network connections
│   ├── threatintel_server/server.py# MCP server: threat intelligence
│   ├── response_server/server.py  # MCP server: response actions
│   └── memory_server/server.py    # MCP server: case history (SQLite)
├── core/
│   ├── correlation/context_builder.py  # Calls MCP servers, assembles UnifiedContext
│   ├── graph/builder.py                # NetworkX attack graph
│   ├── scoring/engine.py               # Deterministic risk scoring
│   ├── llm/reasoner.py                 # LLM reasoning + rule-based fallback
│   ├── response/decision_engine.py     # Action selection logic
│   └── baseline/engine.py             # User/host anomaly detection
├── models/
│   ├── schemas.py                 # Pydantic models
│   ├── db_models.py               # SQLAlchemy ORM models
│   └── database.py                # Async SQLite engine
├── config/
│   └── settings.py                # Settings loaded from .env
├── utils/
│   ├── helpers.py                 # Shared utilities
│   ├── logger.py                  # Rich logger
│   └── notifier.py                # Desktop notification sender
├── data/
│   └── mock_telemetry/            # Test scenarios
├── tests/
│   └── test_pipeline.py           # Pytest test suite
├── run_all.py                     # Starts the FastAPI server (only process needed)
├── watch.py                       # Background PDF watcher + notifier
├── demo.py                        # End-to-end demo
├── requirements.txt
└── .env                           # Configuration
```

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure

Edit `.env` — set your LLM API key for LLM reasoning:
```
LLM_API_KEY=sk-your-key-here
```
The system works without an LLM key using rule-based fallback.

### 3. Start the API

```bash
python run_all.py
```

This starts only the FastAPI server on port 8000. MCP servers are spawned automatically on-demand — no other processes needed.

### 4. Run the background watcher (real-time PDF monitoring)

```bash
# Watch ~/Downloads (default)
python watch.py

# Watch a custom folder
python watch.py /path/to/folder
```

Whenever a PDF is opened or saved in the watched folder, the full pipeline runs and a desktop notification appears with the risk result.

### 5. Run the demo (manual one-shot)

```bash
# With mock data
python demo.py

# With a real PDF
python demo.py /path/to/real.pdf
```

### 6. Run tests

```bash
pytest tests/ -v
```

### 7. Use the API directly

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

# Check health (probes all 8 MCP servers)
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

- **Add a new MCP server**: Create `mcp_servers/new_server/server.py` using `mcp.server.Server` + stdio transport, then call it in `core/correlation/context_builder.py`
- **Add scoring dimension**: Add a `_score_*` function in `core/scoring/engine.py`
- **Swap LLM**: Change `LLM_PROVIDER` and `LLM_BASE_URL` in `.env` (any OpenAI-compatible API works)
- **Add real telemetry**: Replace mock seed tools with Sysmon/EDR/Zeek connectors

---

## Research Value

- **True MCP**: All 8 analysis servers use the official MCP SDK with stdio JSON-RPC transport
- **Cross-layer fusion**: Email + PDF + Process + File + Network + Baseline + Intel
- **Explainable scoring**: Every point has a labeled reason
- **Attack chain graph**: Full kill chain as a queryable graph
- **LLM as analyst**: Structured reasoning over pre-computed context
- **Adaptive response**: Graduated actions based on confidence + risk
- **Case memory**: Historical cases improve future detection
