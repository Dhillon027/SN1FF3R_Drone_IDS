"""
Reads the flight controller's parameter table and compares it with a saved
trusted baseline (JSON: capture time, system ID, hash, excluded patterns and
every parameter value).
"""

import json
import time
from pathlib import Path
from typing import Callable, Dict, Optional

from .detectors.firmware_integrity_checker import hash_params, diff_params


def fetch_params(master, timeout_s: float = 60.0,
                 progress: Optional[Callable[[int, int], None]] = None) -> Dict[str, float]:
    """Download the whole parameter table, re-requesting any that got lost."""
    master.mav.param_request_list_send(master.target_system, master.target_component)
    params: Dict[str, float] = {}
    seen_idx = set()
    total = None
    deadline = time.time() + timeout_s
    last_rx = time.time()
    while time.time() < deadline:
        m = master.recv_match(type="PARAM_VALUE", blocking=True, timeout=0.5)
        if m is not None:
            if m.get_srcSystem() != master.target_system:
                continue
            last_rx = time.time()
            name = m.param_id.rstrip("\x00") if isinstance(m.param_id, str) else m.param_id.decode().rstrip("\x00")
            params[name] = float(m.param_value)
            if m.param_index != 65535:
                seen_idx.add(m.param_index)
            total = m.param_count
            if progress:
                progress(len(seen_idx), total)
            if total and len(seen_idx) >= total:
                return params
        elif total and time.time() - last_rx > 1.0:
            missing = [i for i in range(total) if i not in seen_idx][:20]
            for i in missing:
                master.mav.param_request_read_send(master.target_system, master.target_component, b"", i)
            last_rx = time.time()
    if total is None:
        raise TimeoutError("No PARAM_VALUE received -- is the vehicle connected?")
    raise TimeoutError(f"Only received {len(seen_idx)}/{total} parameters before timing out")


def save_baseline(path: str, params: Dict[str, float], exclude, sysid=None) -> dict:
    data = {
        "captured_at": time.time(),
        "sysid": sysid,
        "count": len(params),
        "exclude": list(exclude),
        "hash": hash_params(params, exclude),
        "params": params,
    }
    Path(path).write_text(json.dumps(data, indent=1, sort_keys=True))
    return data


def compare_to_baseline(path: str, current: Dict[str, float], exclude=None) -> dict:
    base = json.loads(Path(path).read_text())
    ex = sorted(set(base.get("exclude", [])) | set(exclude or []))
    changes = diff_params(base["params"], current, ex)
    return {
        "ok": not changes,
        "baseline_hash": hash_params(base["params"], ex),
        "current_hash": hash_params(current, ex),
        "captured_at": base.get("captured_at"),
        "checked": len(current),
        "changes": [{"name": n, "baseline": b, "current": c} for n, b, c in changes],
    }
