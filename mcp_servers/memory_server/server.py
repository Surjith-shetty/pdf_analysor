"""
mcp_servers/memory_server/server.py
MCP Server 8: Memory / Case History — real MCP SDK (stdio transport)
Tools: save_case, get_case, list_cases, update_verdict, lookup_by_hash
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import json, asyncio
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
from sqlalchemy import select, update
from models.database import get_db, init_db
from models.db_models import CaseTable
from models.schemas import UnifiedContext, AttackGraph, LLMReasoningOutput, ResponseAction
from utils.logger import get_logger

log = get_logger("memory_server")
server = Server("memory-server")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="save_case",
            description="Persist a completed analysis case to the database",
            inputSchema={
                "type": "object",
                "properties": {
                    "context": {"type": "object"},
                    "graph": {"type": "object"},
                    "llm_output": {"type": "object"},
                    "response": {"type": "object"},
                },
                "required": ["context", "graph", "llm_output", "response"],
            },
        ),
        Tool(
            name="get_case",
            description="Retrieve a case by case_id",
            inputSchema={"type": "object", "properties": {"case_id": {"type": "string"}}, "required": ["case_id"]},
        ),
        Tool(
            name="list_cases",
            description="List recent cases",
            inputSchema={"type": "object", "properties": {"limit": {"type": "integer", "default": 20}}},
        ),
        Tool(
            name="update_verdict",
            description="Update analyst verdict for a case",
            inputSchema={
                "type": "object",
                "properties": {"case_id": {"type": "string"}, "verdict": {"type": "string"}},
                "required": ["case_id", "verdict"],
            },
        ),
        Tool(
            name="lookup_by_hash",
            description="Check if a PDF hash has been seen before",
            inputSchema={"type": "object", "properties": {"pdf_hash": {"type": "string"}}, "required": ["pdf_hash"]},
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    await init_db()  # idempotent — creates tables if not exist
    async for db in get_db():
        if name == "save_case":
            ctx = UnifiedContext(**arguments["context"])
            record = CaseTable(
                case_id=ctx.case_id, created_at=ctx.timestamp,
                user=ctx.user, host=ctx.host,
                pdf_hash=ctx.pdf.hash, pdf_path=ctx.pdf.path,
                risk_level=ctx.scores.risk_level, total_score=ctx.scores.total_score,
                classification=arguments["llm_output"].get("classification"),
                recommended_action=arguments["llm_output"].get("recommended_action"),
                context_json=ctx.model_dump_json(),
                graph_json=json.dumps(arguments["graph"]),
                llm_output_json=json.dumps(arguments["llm_output"]),
                response_json=json.dumps(arguments["response"]),
            )
            db.add(record)
            await db.commit()
            return [TextContent(type="text", text=json.dumps({"status": "saved", "case_id": ctx.case_id}))]

        elif name == "get_case":
            result = await db.execute(select(CaseTable).where(CaseTable.case_id == arguments["case_id"]))
            row = result.scalar_one_or_none()
            if not row:
                return [TextContent(type="text", text=json.dumps({"error": "not found"}))]
            return [TextContent(type="text", text=json.dumps({
                "case_id": row.case_id, "risk_level": row.risk_level,
                "classification": row.classification,
                "context": json.loads(row.context_json),
                "llm_output": json.loads(row.llm_output_json),
            }))]

        elif name == "list_cases":
            result = await db.execute(
                select(CaseTable.case_id, CaseTable.created_at, CaseTable.user,
                       CaseTable.risk_level, CaseTable.classification, CaseTable.analyst_verdict)
                .order_by(CaseTable.created_at.desc())
                .limit(arguments.get("limit", 20))
            )
            rows = result.all()
            return [TextContent(type="text", text=json.dumps([dict(r._mapping) for r in rows], default=str))]

        elif name == "update_verdict":
            await db.execute(
                update(CaseTable)
                .where(CaseTable.case_id == arguments["case_id"])
                .values(analyst_verdict=arguments["verdict"])
            )
            await db.commit()
            return [TextContent(type="text", text=json.dumps({"status": "updated"}))]

        elif name == "lookup_by_hash":
            result = await db.execute(
                select(CaseTable.case_id, CaseTable.risk_level, CaseTable.classification, CaseTable.analyst_verdict)
                .where(CaseTable.pdf_hash == arguments["pdf_hash"])
                .order_by(CaseTable.created_at.desc()).limit(5)
            )
            rows = result.all()
            return [TextContent(type="text", text=json.dumps({
                "hash": arguments["pdf_hash"],
                "previous_cases": [dict(r._mapping) for r in rows],
            }))]

    raise ValueError(f"Unknown tool: {name}")


async def main():
    await init_db()
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
