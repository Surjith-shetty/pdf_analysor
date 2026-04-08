"""
mcp_servers/response_server/server.py
MCP Server 7: Response Action Executor — real MCP SDK (stdio transport)
Tool: execute_action(case_id, action, target, reason) -> ResponseAction JSON
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import shutil, stat, signal
from datetime import datetime
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
from models.schemas import ResponseAction
from config.settings import settings
from utils.logger import get_logger

log = get_logger("response_server")
server = Server("response-server")

QUARANTINE_DIR = os.path.expanduser("~/cyber_quarantine")
os.makedirs(QUARANTINE_DIR, exist_ok=True)

_action_log: list[ResponseAction] = []


def _kill_process(pid: int, simulated: bool) -> str:
    if simulated: return f"[SIMULATED] Would kill PID {pid}"
    try:
        os.kill(pid, signal.SIGKILL)
        return f"Killed PID {pid}"
    except Exception as e:
        return f"Failed to kill PID {pid}: {e}"


def _quarantine_file(path: str, simulated: bool) -> str:
    if simulated: return f"[SIMULATED] Would quarantine {path}"
    try:
        dest = os.path.join(QUARANTINE_DIR, os.path.basename(path))
        if os.path.exists(dest):
            base, ext = os.path.splitext(os.path.basename(path))
            dest = os.path.join(QUARANTINE_DIR, f"{base}_{int(datetime.utcnow().timestamp())}{ext}")
        shutil.move(path, dest)
        os.chmod(dest, stat.S_IRUSR | stat.S_IWUSR)
        return f"Quarantined {path} → {dest}"
    except Exception as e:
        return f"Failed to quarantine {path}: {e}"


def _isolate_host(host: str, simulated: bool) -> str:
    if simulated: return f"[SIMULATED] Would isolate host {host}"
    return f"[ENFORCE] Host isolation for {host} — integrate with EDR API"


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [Tool(
        name="execute_action",
        description="Execute a response action (log_only, alert_analyst, kill_process, quarantine_file, isolate_host)",
        inputSchema={
            "type": "object",
            "properties": {
                "case_id": {"type": "string"},
                "action": {"type": "string"},
                "target": {"type": "string", "default": ""},
                "reason": {"type": "string", "default": ""},
            },
            "required": ["case_id", "action"],
        },
    )]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name != "execute_action":
        raise ValueError(f"Unknown tool: {name}")

    simulated = settings.response_mode == "simulate"
    action = arguments["action"]
    case_id = arguments["case_id"]
    target = arguments.get("target", "")
    reason = arguments.get("reason", "")

    if action == "log_only":
        result = f"Case {case_id} logged"
    elif action == "alert_analyst":
        log.warning(f"🚨 ANALYST ALERT | Case: {case_id} | {reason}")
        result = f"Alert sent for case {case_id}"
    elif action == "kill_process":
        result = _kill_process(int(target) if target.isdigit() else 0, simulated)
    elif action == "quarantine_file":
        result = _quarantine_file(target, simulated)
    elif action == "isolate_host":
        result = _isolate_host(target, simulated)
    else:
        result = f"Unknown action: {action}"

    response = ResponseAction(
        action=action, target=target or None, reason=reason,
        simulated=simulated, executed_at=datetime.utcnow(), result=result,
    )
    _action_log.append(response)
    return [TextContent(type="text", text=response.model_dump_json())]


async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
