"""
Alert log as hash-chained JSON Lines: each entry stores the hash of the one
before it, so editing, removing or reordering an old alert breaks the chain.

It isn't a signature: someone who rewrites every later entry too won't be
caught, so copy logs off the vehicle if that matters.
"""

import json
import hashlib
import threading
import time
from pathlib import Path


class SecureLogger:
    def __init__(self, path: str = "ids_alerts.jsonl"):
        self.path = Path(path)
        self.prev_hash = self._recover_last_hash() or "0" * 64
        self._lock = threading.Lock()

    def _recover_last_hash(self):
        """On restart, chain continues from the last entry already on disk."""
        if not self.path.exists():
            return None
        last_hash = None
        with open(self.path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        last_hash = json.loads(line).get("hash")
                    except json.JSONDecodeError:
                        continue
        return last_hash

    def log(self, alert: dict) -> None:
        with self._lock:
            entry = {**alert, "prev_hash": self.prev_hash, "logged_at": time.time()}
            entry_str = json.dumps(entry, sort_keys=True, default=str)
            entry = json.loads(entry_str)
            entry_hash = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
            entry["hash"] = entry_hash
            with open(self.path, "a") as f:
                f.write(json.dumps(entry) + "\n")
            self.prev_hash = entry_hash

    def verify_chain(self) -> bool:
        """Offline integrity check — walk the file and confirm every
        entry's prev_hash matches the running chain."""
        if not self.path.exists():
            return True
        with open(self.path, "r") as f:
            return verify_lines(f) is not None


def verify_entry(line: str, prev: str):
    """Check one log line against the running chain hash. Returns the
    entry's own hash if it is intact and chained to `prev`, else None."""
    try:
        entry = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(entry, dict):
        return None
    stored_hash = entry.pop("hash", None)
    recomputed = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
    if stored_hash is None or recomputed != stored_hash or entry.get("prev_hash") != prev:
        return None
    return stored_hash


def verify_lines(lines, prev: str = "0" * 64):
    """Walk an iterable of log lines. Returns the final chain hash if the
    whole chain is intact, else None."""
    for line in lines:
        line = line.strip()
        if not line:
            continue
        prev = verify_entry(line, prev)
        if prev is None:
            return None
    return prev
