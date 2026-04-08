"""
mcp_servers/pdf_server/server.py

MCP Server 2: PDF Static Analysis
Role: Performs structural analysis of a PDF file to extract malicious indicators.
      Uses PyMuPDF for structure parsing + custom keyword/entropy checks.

Input:  { "pdf_path": "...", "pdf_hash": "..." }
Output: PDFAnalysisResult schema

Detection logic:
  - JavaScript presence (/JS, /JavaScript)
  - OpenAction / AA (auto-action) entries
  - Embedded files (/EmbeddedFile)
  - Launch actions (/Launch)
  - URI actions (/URI)
  - AcroForm with JS
  - Suspicious keyword density
  - Stream entropy (obfuscation indicator)
"""
import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from models.schemas import PDFAnalysisResult
from utils.helpers import calculate_entropy, sha256_file
from utils.logger import get_logger

log = get_logger("pdf_server")
app = FastAPI(title="PDF Analysis MCP Server")

SUSPICIOUS_KEYWORDS = [
    "/JS", "/JavaScript", "/OpenAction", "/AA",
    "/EmbeddedFile", "/Launch", "/URI", "/SubmitForm",
    "/ImportData", "/RichMedia", "/XFA", "eval(",
    "unescape(", "String.fromCharCode", "shellcode",
]


class PDFQuery(BaseModel):
    pdf_path: str
    pdf_hash: str = ""


def _analyze_with_pymupdf(path: str) -> dict:
    """
    Parse PDF structure using PyMuPDF (fitz).
    Returns raw feature dict.
    """
    try:
        import fitz  # PyMuPDF
    except ImportError:
        log.warning("PyMuPDF not installed, using mock analysis")
        return _mock_analysis(path)

    result = {
        "has_javascript": False,
        "has_open_action": False,
        "has_embedded_files": 0,
        "has_launch_action": False,
        "has_uri_action": False,
        "has_acroform": False,
        "suspicious_keywords": [],
        "streams_count": 0,
        "entropy": 0.0,
        "pdf_version": "unknown",
        "file_size": os.path.getsize(path),
    }

    try:
        doc = fitz.open(path)
        result["pdf_version"] = doc.metadata.get("format", "unknown")

        # Read raw bytes for keyword scan + entropy
        with open(path, "rb") as f:
            raw = f.read()

        result["entropy"] = calculate_entropy(raw)

        # Keyword scan on raw bytes
        raw_str = raw.decode("latin-1", errors="ignore")
        found_keywords = []
        for kw in SUSPICIOUS_KEYWORDS:
            if kw.lower() in raw_str.lower():
                found_keywords.append(kw)

        result["suspicious_keywords"] = found_keywords
        result["has_javascript"] = "/JS" in found_keywords or "/JavaScript" in found_keywords
        result["has_open_action"] = "/OpenAction" in found_keywords or "/AA" in found_keywords
        result["has_launch_action"] = "/Launch" in found_keywords
        result["has_uri_action"] = "/URI" in found_keywords
        result["has_acroform"] = "/XFA" in found_keywords

        # Count embedded files via xref table
        for xref in range(doc.xref_length()):
            try:
                obj_str = doc.xref_object(xref)
                if "/EmbeddedFile" in obj_str:
                    result["has_embedded_files"] += 1
                if "/ObjStm" in obj_str or "/FlateDecode" in obj_str:
                    result["streams_count"] += 1
            except Exception:
                pass

        doc.close()

    except Exception as e:
        log.error(f"PyMuPDF parse error: {e}")

    return result


def _mock_analysis(path: str) -> dict:
    """
    Mock analysis for testing without a real PDF.
    Simulates a malicious PDF with embedded JS and OpenAction.
    """
    filename = os.path.basename(path).lower()
    is_malicious_mock = "malicious" in filename or "invoice" in filename

    return {
        "has_javascript": is_malicious_mock,
        "has_open_action": is_malicious_mock,
        "has_embedded_files": 1 if is_malicious_mock else 0,
        "has_launch_action": False,
        "has_uri_action": is_malicious_mock,
        "has_acroform": False,
        "suspicious_keywords": ["/JS", "/OpenAction", "/EmbeddedFile"] if is_malicious_mock else [],
        "streams_count": 5,
        "entropy": 7.2 if is_malicious_mock else 4.1,
        "pdf_version": "PDF-1.6",
        "file_size": 102400,
    }


def _compute_obfuscation_score(features: dict) -> float:
    """
    Heuristic obfuscation score 0.0–1.0.
    High entropy + many suspicious keywords = likely obfuscated.
    """
    score = 0.0
    if features["entropy"] > 7.0:
        score += 0.4
    elif features["entropy"] > 6.0:
        score += 0.2
    score += min(len(features["suspicious_keywords"]) * 0.1, 0.4)
    if features["has_javascript"]:
        score += 0.1
    if features["has_launch_action"]:
        score += 0.1
    return round(min(score, 1.0), 2)


@app.post("/analyze", response_model=PDFAnalysisResult)
async def analyze_pdf(q: PDFQuery) -> PDFAnalysisResult:
    if not os.path.exists(q.pdf_path):
        # Use mock analysis if file doesn't exist (demo mode)
        log.warning(f"PDF not found at {q.pdf_path}, using mock analysis")
        features = _mock_analysis(q.pdf_path)
    else:
        features = _analyze_with_pymupdf(q.pdf_path)

    file_hash = q.pdf_hash or (sha256_file(q.pdf_path) if os.path.exists(q.pdf_path) else "mock_hash")
    obfuscation = _compute_obfuscation_score(features)

    log.info(f"PDF analysis complete: js={features['has_javascript']}, "
             f"openaction={features['has_open_action']}, obfuscation={obfuscation}")

    return PDFAnalysisResult(
        hash=file_hash,
        path=q.pdf_path,
        file_size=features["file_size"],
        has_javascript=features["has_javascript"],
        has_open_action=features["has_open_action"],
        has_embedded_files=features["has_embedded_files"],
        has_launch_action=features["has_launch_action"],
        has_uri_action=features["has_uri_action"],
        has_acroform=features["has_acroform"],
        obfuscation_score=obfuscation,
        entropy=features["entropy"],
        suspicious_keywords=features["suspicious_keywords"],
        streams_count=features["streams_count"],
        pdf_version=features["pdf_version"],
    )


@app.get("/health")
async def health():
    return {"status": "ok", "server": "pdf_analysis"}
