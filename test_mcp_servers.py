#!/usr/bin/env python3
"""
test_mcp_servers.py
Tests every MCP server endpoint to confirm they are all working.

Run AFTER starting all servers with: python run_all.py

Usage:
  python test_mcp_servers.py
"""
import asyncio
import httpx
from rich.console import Console
from rich.table import Table

console = Console()

SERVERS = {
    "orchestrator":  "http://localhost:8000",
    "email":         "http://localhost:8001",
    "pdf":           "http://localhost:8002",
    "endpoint":      "http://localhost:8003",
    "filesystem":    "http://localhost:8004",
    "network":       "http://localhost:8005",
    "threatintel":   "http://localhost:8006",
    "response":      "http://localhost:8007",
    "memory":        "http://localhost:8008",
}

results = []


def record(server: str, endpoint: str, passed: bool, detail: str = ""):
    results.append((server, endpoint, passed, detail))
    status = "[green]✓ PASS[/green]" if passed else "[red]✗ FAIL[/red]"
    console.print(f"  {status}  [{server}] {endpoint}  {detail}")


async def test_health(client: httpx.AsyncClient):
    """Test /health on all servers."""
    console.print("\n[bold cyan]── Health Checks ──[/bold cyan]")
    for name, base in SERVERS.items():
        try:
            r = await client.get(f"{base}/health", timeout=5.0)
            data = r.json()
            # orchestrator returns {"orchestrator": "ok", "overall": ...}
            # all other servers return {"status": "ok"}
            ok = r.status_code == 200 and (
                data.get("status") == "ok" or data.get("orchestrator") == "ok"
            )
            record(name, "GET /health", ok, str(data))
        except Exception as e:
            record(name, "GET /health", False, str(e))


async def test_email_server(client: httpx.AsyncClient):
    console.print("\n[bold cyan]── Email Server (8001) ──[/bold cyan]")
    # Known hash
    r = await client.post("http://localhost:8001/query",
                          json={"attachment_hash": "deadbeef1234"}, timeout=5.0)
    ok = r.status_code == 200 and r.json().get("sender_reputation") == "malicious"
    record("email", "POST /query (known hash)", ok, f"reputation={r.json().get('sender_reputation')}")

    # Unknown hash — should return unknown
    r = await client.post("http://localhost:8001/query",
                          json={"attachment_hash": "unknown999"}, timeout=5.0)
    ok = r.status_code == 200 and r.json().get("sender_reputation") == "unknown"
    record("email", "POST /query (unknown hash)", ok, f"reputation={r.json().get('sender_reputation')}")


async def test_pdf_server(client: httpx.AsyncClient):
    console.print("\n[bold cyan]── PDF Server (8002) ──[/bold cyan]")
    # Mock path — falls back to mock analysis
    r = await client.post("http://localhost:8002/analyze",
                          json={"pdf_path": "/tmp/invoice_q2.pdf", "pdf_hash": "deadbeef1234"},
                          timeout=10.0)
    ok = r.status_code == 200
    data = r.json()
    record("pdf", "POST /analyze (mock path)", ok,
           f"js={data.get('has_javascript')} entropy={data.get('entropy')}")


async def test_endpoint_server(client: httpx.AsyncClient):
    console.print("\n[bold cyan]── Endpoint Server (8003) ──[/bold cyan]")
    # Seed mock
    r = await client.post("http://localhost:8003/seed/mock", timeout=5.0)
    ok = r.status_code == 200 and r.json().get("status") == "seeded"
    record("endpoint", "POST /seed/mock", ok, str(r.json()))

    # Query children
    r = await client.post("http://localhost:8003/query/children",
                          json={"parent_name": "AcroRd32.exe", "window_seconds": 300},
                          timeout=5.0)
    ok = r.status_code == 200 and len(r.json()) > 0
    record("endpoint", "POST /query/children", ok, f"{len(r.json())} events")

    # Query suspicious
    r = await client.post("http://localhost:8003/query/suspicious",
                          json={"parent_name": "AcroRd32.exe", "window_seconds": 300},
                          timeout=5.0)
    ok = r.status_code == 200
    record("endpoint", "POST /query/suspicious", ok, f"{len(r.json())} suspicious")


async def test_filesystem_server(client: httpx.AsyncClient):
    console.print("\n[bold cyan]── Filesystem Server (8004) ──[/bold cyan]")
    r = await client.post("http://localhost:8004/seed/mock", timeout=5.0)
    ok = r.status_code == 200 and r.json().get("status") == "seeded"
    record("filesystem", "POST /seed/mock", ok, str(r.json()))

    r = await client.post("http://localhost:8004/query/drops",
                          json={"process_name": "powershell.exe", "suspicious_only": True},
                          timeout=5.0)
    ok = r.status_code == 200
    record("filesystem", "POST /query/drops (suspicious)", ok, f"{len(r.json())} drops")


async def test_network_server(client: httpx.AsyncClient):
    console.print("\n[bold cyan]── Network Server (8005) ──[/bold cyan]")
    r = await client.post("http://localhost:8005/seed/mock", timeout=5.0)
    ok = r.status_code == 200 and r.json().get("status") == "seeded"
    record("network", "POST /seed/mock", ok, str(r.json()))

    r = await client.post("http://localhost:8005/query/connections",
                          json={"process_name": "temp.exe", "window_seconds": 300},
                          timeout=5.0)
    ok = r.status_code == 200 and len(r.json()) > 0
    record("network", "POST /query/connections", ok, f"{len(r.json())} connections")

    r = await client.post("http://localhost:8005/query/suspicious_connections",
                          json={"process_name": "temp.exe"}, timeout=5.0)
    ok = r.status_code == 200
    record("network", "POST /query/suspicious_connections", ok, f"{len(r.json())} suspicious")


async def test_threatintel_server(client: httpx.AsyncClient):
    console.print("\n[bold cyan]── ThreatIntel Server (8006) ──[/bold cyan]")
    r = await client.post("http://localhost:8006/enrich",
                          json={
                              "hashes": ["deadbeef1234"],
                              "ips": ["185.220.101.45"],
                              "domains": ["evil-domain.ru"],
                          }, timeout=10.0)
    ok = r.status_code == 200
    data = r.json()
    record("threatintel", "POST /enrich", ok,
           f"hash={data.get('hash_reputation')} ip={data.get('ip_reputation')} domain={data.get('domain_reputation')}")


async def test_response_server(client: httpx.AsyncClient):
    console.print("\n[bold cyan]── Response Server (8007) ──[/bold cyan]")
    r = await client.post("http://localhost:8007/execute",
                          json={"case_id": "test-001", "action": "log_only", "reason": "test"},
                          timeout=5.0)
    ok = r.status_code == 200 and "logged" in r.json().get("result", "")
    record("response", "POST /execute (log_only)", ok, r.json().get("result"))

    r = await client.post("http://localhost:8007/execute",
                          json={"case_id": "test-001", "action": "alert_analyst", "reason": "test alert"},
                          timeout=5.0)
    ok = r.status_code == 200
    record("response", "POST /execute (alert_analyst)", ok, r.json().get("result"))

    r = await client.get("http://localhost:8007/log", timeout=5.0)
    ok = r.status_code == 200 and len(r.json()) >= 2
    record("response", "GET /log", ok, f"{len(r.json())} actions logged")


async def test_memory_server(client: httpx.AsyncClient):
    console.print("\n[bold cyan]── Memory Server (8008) ──[/bold cyan]")
    r = await client.get("http://localhost:8008/cases", timeout=5.0)
    ok = r.status_code == 200
    record("memory", "GET /cases", ok, f"{len(r.json())} cases stored")

    r = await client.get("http://localhost:8008/cases/hash/deadbeef1234", timeout=5.0)
    ok = r.status_code == 200 and "previous_cases" in r.json()
    record("memory", "GET /cases/hash/:hash", ok, f"{len(r.json().get('previous_cases', []))} previous cases")


async def test_full_pipeline(client: httpx.AsyncClient):
    console.print("\n[bold cyan]── Full Pipeline (Orchestrator) ──[/bold cyan]")
    r = await client.post("http://localhost:8000/analyze",
                          json={
                              "pdf_path": "/tmp/invoice_q2.pdf",
                              "pdf_hash": "deadbeef1234",
                              "user": "testuser",
                              "host": "TEST-HOST",
                              "origin": "external_email",
                          }, timeout=60.0)
    ok = r.status_code == 200
    data = r.json()
    record("orchestrator", "POST /analyze (full pipeline)", ok,
           f"risk={data.get('risk_level')} score={data.get('total_score')} action={data.get('recommended_action')}")

    r = await client.get("http://localhost:8000/cases", timeout=5.0)
    ok = r.status_code == 200
    record("orchestrator", "GET /cases", ok, f"{len(r.json())} cases")


def print_summary():
    console.print("\n")
    table = Table(title="MCP Server Test Summary", show_lines=True)
    table.add_column("Server", style="cyan")
    table.add_column("Endpoint")
    table.add_column("Status")
    table.add_column("Detail", style="dim")

    passed = sum(1 for _, _, ok, _ in results if ok)
    failed = sum(1 for _, _, ok, _ in results if not ok)

    for server, endpoint, ok, detail in results:
        status = "[green]PASS[/green]" if ok else "[red]FAIL[/red]"
        table.add_row(server, endpoint, status, detail[:60])

    console.print(table)
    color = "green" if failed == 0 else "red"
    console.print(f"\n[{color}]Results: {passed} passed, {failed} failed out of {len(results)} tests[/{color}]")


async def main():
    console.print("[bold]MCP Server Test Suite[/bold]")
    console.print("Make sure all servers are running: [cyan]python run_all.py[/cyan]\n")

    async with httpx.AsyncClient(timeout=10.0) as client:
        await test_health(client)

        # Stop early if no servers are reachable
        if not any(ok for _, _, ok, _ in results):
            console.print("\n[red]No servers are running. Start them first:[/red]")
            console.print("  [cyan]python run_all.py[/cyan]")
            return

        await test_email_server(client)
        await test_pdf_server(client)
        await test_endpoint_server(client)
        await test_filesystem_server(client)
        await test_network_server(client)
        await test_threatintel_server(client)
        await test_response_server(client)
        await test_memory_server(client)
        await test_full_pipeline(client)

    print_summary()


if __name__ == "__main__":
    asyncio.run(main())
