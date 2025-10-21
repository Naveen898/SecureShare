"""Scanning service.

Provides two layers:
1. Optional ClamAV daemon scan (if CLAMAV_ENABLED=1 and clamd reachable).
2. Lightweight heuristic including EICAR test string detection (so you can demo locally).

Usage in routes: scan_file(filename, data_bytes)
Returns: dict { is_clean: bool, engine: str, reason: str | None }
"""
import os
from typing import Optional

EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

def _clamav_scan(data: bytes) -> Optional[dict]:
    """Attempt a ClamAV scan, return result dict or None if unavailable."""
    if os.getenv("CLAMAV_ENABLED", "0") != "1":
        return None
    try:
        import clamd  # type: ignore
        host = os.getenv("CLAMAV_HOST", "127.0.0.1")
        port = int(os.getenv("CLAMAV_PORT", "3310"))
        cd = clamd.ClamdNetworkSocket(host=host, port=port, timeout=5)
        # PING to ensure reachable
        try:
            cd.ping()
        except Exception:
            return None
        result = cd.instream(data)
        # result format: {'stream': ('OK', None)} or ('FOUND', 'MalwareName')
        status, sig = result.get('stream', (None, None))
        if status == 'OK':
            return {"is_clean": True, "engine": "clamav", "reason": None}
        if status == 'FOUND':
            return {"is_clean": False, "engine": "clamav", "reason": f"Detected: {sig}"}
        return {"is_clean": False, "engine": "clamav", "reason": f"Unknown status: {status}"}
    except Exception:
        return None

def _heuristic_scan(filename: str, data: bytes) -> dict:
    # EICAR test detection
    if EICAR_SIGNATURE in data:
        return {"is_clean": False, "engine": "heuristic", "reason": "EICAR test signature detected"}
    # Basic disallow for demo: block Windows executables & scripts if desired
    blocked_ext = {'.exe', '.bat', '.cmd', '.ps1', '.vbs'}
    lower = filename.lower()
    if any(lower.endswith(ext) for ext in blocked_ext):
        return {"is_clean": False, "engine": "heuristic", "reason": "Blocked file extension"}
    return {"is_clean": True, "engine": "heuristic", "reason": None}

def scan_file(filename: str, data: bytes) -> dict:
    # Try ClamAV first if enabled
    clam_result = _clamav_scan(data)
    if clam_result is not None:
        return clam_result
    # Fallback heuristic
    return _heuristic_scan(filename, data)