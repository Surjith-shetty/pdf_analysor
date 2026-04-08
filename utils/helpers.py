"""
utils/helpers.py
Shared utility functions: hashing, path classification, process risk checks.
"""
import hashlib
import math
import os
from pathlib import Path


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def calculate_entropy(data: bytes) -> float:
    """Shannon entropy — high entropy suggests encryption/obfuscation."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


# Processes that should never be spawned by a PDF reader
SUSPICIOUS_CHILD_PROCESSES = {
    "powershell.exe", "powershell",
    "cmd.exe", "cmd",
    "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "wmic.exe",
    "msiexec.exe", "schtasks.exe",
    "bash", "sh", "zsh",
}

# Paths that indicate suspicious file drops
SUSPICIOUS_PATHS = {
    "temp", "tmp", "appdata", "roaming", "local",
    "programdata", "public", "downloads",
}

PDF_READER_PROCESSES = {
    "acrord32.exe", "acrobat.exe", "foxitreader.exe",
    "sumatrapdf.exe", "evince", "okular", "preview",
}


def is_suspicious_child(process_name: str) -> bool:
    return process_name.lower() in SUSPICIOUS_CHILD_PROCESSES


def is_suspicious_path(file_path: str) -> bool:
    lower = file_path.lower()
    return any(p in lower for p in SUSPICIOUS_PATHS)


def is_pdf_reader(process_name: str) -> bool:
    return process_name.lower() in PDF_READER_PROCESSES


def classify_file_extension(path: str) -> str:
    ext = Path(path).suffix.lower()
    if ext in {".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".hta", ".scr"}:
        return "executable"
    if ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx"}:
        return "document"
    return "other"
