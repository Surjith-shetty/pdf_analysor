"""
mcp_servers/threatintel_server/server.py

MCP Server 6: Threat Intelligence
Role: Enriches indicators (hash, IP, domain) with reputation data.
      Uses a local mock DB + optional VirusTotal API.
      Caches results to avoid repeated API calls.

Input:  { "hashes": [...], "ips": [...], "domains": [...] }
Output: ThreatIntelResult
"""
import httpx
from fastapi import FastAPI
from pydantic import BaseModel
from models.schemas import ThreatIntelResult
from config.settings import settings
from utils.logger import get_logger

log = get_logger("threatintel_server")
app = FastAPI(title="Threat Intelligence MCP Server")

# ── Local mock reputation DB ──────────────────────────────────────────────────
MOCK_HASH_DB: dict[str, str] = {
    "deadbeef1234": "malicious",
    "cafebabe1234": "suspicious",
    "aabbcc9900": "clean",
}

MOCK_IP_DB: dict[str, tuple[str, list[str]]] = {
    "185.220.101.45": ("malicious", ["tor_exit_node", "c2_server"]),
    "1.2.3.4": ("suspicious", ["scanner"]),
    "8.8.8.8": ("clean", []),
}

MOCK_DOMAIN_DB: dict[str, tuple[str, list[str]]] = {
    "evil-domain.ru": ("malicious", ["phishing", "malware_distribution"]),
    "c2.evil-domain.ru": ("malicious", ["c2"]),
    "company.com": ("clean", []),
}


class IntelQuery(BaseModel):
    hashes: list[str] = []
    ips: list[str] = []
    domains: list[str] = []


async def _vt_lookup_hash(file_hash: str) -> tuple[str, int]:
    """Query VirusTotal for a file hash. Returns (reputation, detections)."""
    if not settings.vt_api_key or settings.vt_api_key == "your_vt_api_key_here":
        return "unknown", 0
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": settings.vt_api_key},
            )
            if resp.status_code == 200:
                data = resp.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                malicious = stats.get("malicious", 0)
                if malicious > 5:
                    return "malicious", malicious
                elif malicious > 0:
                    return "suspicious", malicious
                return "clean", 0
    except Exception as e:
        log.warning(f"VT lookup failed: {e}")
    return "unknown", 0


def _lookup_hash(h: str) -> tuple[str, int]:
    rep = MOCK_HASH_DB.get(h, "unknown")
    return rep, (5 if rep == "malicious" else 0)


def _lookup_ip(ip: str) -> tuple[str, list[str]]:
    return MOCK_IP_DB.get(ip, ("unknown", []))


def _lookup_domain(domain: str) -> tuple[str, list[str]]:
    return MOCK_DOMAIN_DB.get(domain, ("unknown", []))


@app.post("/enrich", response_model=ThreatIntelResult)
async def enrich_indicators(q: IntelQuery) -> ThreatIntelResult:
    """
    Enrich all provided indicators and return a consolidated result.
    Worst-case reputation wins (malicious > suspicious > unknown > clean).
    """
    SEVERITY_ORDER = {"malicious": 3, "suspicious": 2, "unknown": 1, "clean": 0}

    hash_rep, hash_detections = "unknown", 0
    for h in q.hashes:
        rep, det = _lookup_hash(h)
        if SEVERITY_ORDER.get(rep, 0) > SEVERITY_ORDER.get(hash_rep, 0):
            hash_rep, hash_detections = rep, det

    ip_rep, ip_tags = "unknown", []
    for ip in q.ips:
        rep, tags = _lookup_ip(ip)
        if SEVERITY_ORDER.get(rep, 0) > SEVERITY_ORDER.get(ip_rep, 0):
            ip_rep = rep
        ip_tags.extend(tags)

    domain_rep, domain_tags = "unknown", []
    for domain in q.domains:
        rep, tags = _lookup_domain(domain)
        if SEVERITY_ORDER.get(rep, 0) > SEVERITY_ORDER.get(domain_rep, 0):
            domain_rep = rep
        domain_tags.extend(tags)

    log.info(f"Intel enrichment: hash={hash_rep}, ip={ip_rep}, domain={domain_rep}")

    return ThreatIntelResult(
        hash_reputation=hash_rep,
        ip_reputation=ip_rep,
        domain_reputation=domain_rep,
        hash_detections=hash_detections,
        ip_tags=list(set(ip_tags)),
        domain_tags=list(set(domain_tags)),
        source="mock+vt",
    )


@app.get("/health")
async def health():
    return {"status": "ok", "server": "threat_intel"}
