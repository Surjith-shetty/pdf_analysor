"""
mcp_servers/response_server/server.py

MCP Server 7: Response Action Executor
Role: Executes (or simulates) response actions decided by the orchestrator.
      In simulate mode: logs what WOULD happen.
      In enforce mode: calls real OS/EDR APIs.

Supported actions:
  - log_only          → just record the case
  - alert_analyst     → send notification (mock: print/log)
  - kill_process      → terminate a PID
  - quarantine_file   → move file to quarantine dir
  - isolate_host      → block network (mock: log firewall rule)
"""
import os
import shutil
from datetime import datetime
from fastapi import FastAPI
from pydantic import BaseModel
from config.settings import settings
from models.schemas import ResponseAction
from utils.logger import get_logger

log = get_logger("response_server")
app = FastAPI(title="Response Action MCP Server")

QUARANTINE_DIR = "/tmp/cyber_quarantine"
os.makedirs(QUARANTINE_DIR, exist_ok=True)

# Audit log of all actions taken this session
_action_log: list[ResponseAction] = []


class ActionRequest(BaseModel):
    case_id: str
    action: str
    target: str = ""
    reason: str = ""


def _kill_process(pid: int, simulated: bool) -> str:
    if simulated:
        return f"[SIMULATED] Would kill PID {pid}"
    try:
        os.kill(pid, 9)
        return f"Killed PID {pid}"
    except Exception as e:
        return f"Failed to kill PID {pid}: {e}"


def _quarantine_file(path: str, simulated: bool) -> str:
    if simulated:
        return f"[SIMULATED] Would quarantine {path}"
    try:
        dest = os.path.join(QUARANTINE_DIR, os.path.basename(path))
        shutil.move(path, dest)
        return f"Quarantined {path} -> {dest}"
    except Exception as e:
        return f"Failed to quarantine {path}: {e}"


def _isolate_host(host: str, simulated: bool) -> str:
    if simulated:
        return f"[SIMULATED] Would isolate host {host} (block all outbound)"
    # In production: call EDR API or push firewall rule
    return f"[ENFORCE] Host isolation for {host} — integrate with EDR API"


def _alert_analyst(case_id: str, reason: str) -> str:
    # In production: send to SIEM, PagerDuty, Slack webhook, etc.
    log.warning(f"🚨 ANALYST ALERT | Case: {case_id} | {reason}")
    return f"Alert sent for case {case_id}"


@app.post("/execute", response_model=ResponseAction)
async def execute_action(req: ActionRequest) -> ResponseAction:
    simulated = settings.response_mode == "simulate"
    result = "unknown"

    if req.action == "log_only":
        result = f"Case {req.case_id} logged"
        log.info(f"[LOG_ONLY] {result}")

    elif req.action == "alert_analyst":
        result = _alert_analyst(req.case_id, req.reason)

    elif req.action == "kill_process":
        try:
            pid = int(req.target)
        except ValueError:
            pid = 0
        result = _kill_process(pid, simulated)
        log.warning(f"[KILL_PROCESS] {result}")

    elif req.action == "quarantine_file":
        result = _quarantine_file(req.target, simulated)
        log.warning(f"[QUARANTINE] {result}")

    elif req.action == "isolate_host":
        result = _isolate_host(req.target, simulated)
        log.critical(f"[ISOLATE_HOST] {result}")

    else:
        result = f"Unknown action: {req.action}"
        log.error(result)

    action = ResponseAction(
        action=req.action,
        target=req.target or None,
        reason=req.reason,
        simulated=simulated,
        executed_at=datetime.utcnow(),
        result=result,
    )
    _action_log.append(action)
    return action


@app.get("/log", response_model=list[ResponseAction])
async def get_action_log():
    return _action_log


@app.get("/health")
async def health():
    return {"status": "ok", "server": "response_action", "mode": settings.response_mode}
