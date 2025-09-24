"""
Append-only audit log with hash chaining.
Writes to logs/audit.jsonl (relative to this file) by default.
"""
from __future__ import annotations

import json
import os
import time
import hashlib
from typing import Optional, Dict, Any

BASE_DIR = os.path.dirname(__file__)
DEFAULT_AUDIT_PATH = os.path.join(BASE_DIR, "logs", "audit.jsonl")


def _ensure_dir(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)


def _last_entry_hash(path: str) -> Optional[str]:
    if not os.path.exists(path):
        return None
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size == 0:
                return None
            # Read last line
            f.seek(max(0, size - 4096))
            tail = f.read().decode("utf-8", errors="ignore")
            lines = [ln for ln in tail.splitlines() if ln.strip()]
            if not lines:
                return None
            last = json.loads(lines[-1])
            return last.get("entry_hash")
    except Exception:
        return None


def _entry_hash(obj: Dict[str, Any]) -> str:
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha3_256(data).hexdigest()


def append_entry(operation: str, actor_fp: str, object_hash: str,
                 recipients: Optional[list] = None,
                 path: str = DEFAULT_AUDIT_PATH,
                 extra: Optional[Dict[str, Any]] = None) -> str:
    """Append an audit entry and return the entry hash."""
    _ensure_dir(path)
    prev = _last_entry_hash(path)
    entry = {
        "ts": time.time(),
        "op": operation,
        "actor": actor_fp,
        "object": object_hash,
        "recipients": recipients or [],
        "prev": prev,
    }
    if extra:
        entry["extra"] = extra
    entry_hash = _entry_hash(entry)
    entry["entry_hash"] = entry_hash
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry_hash
