"""
Parameter (firmware/config) tampering check against a trusted baseline.

Runs on demand rather than per message, because reading the whole
parameter table takes a few seconds. Parameters that change on their own
are skipped (see `param_integrity_exclude` in config.py).
"""

import fnmatch
import hashlib
from typing import Dict, Iterable, List, Optional, Tuple


def _filtered(param_dict: dict, exclude: Iterable[str] = ()) -> Dict[str, float]:
    pats = list(exclude)
    return {k: v for k, v in param_dict.items()
            if not any(fnmatch.fnmatchcase(k, p) for p in pats)}


def _norm(v) -> float:
    # float32 values: normalise so the same value always hashes the same
    return float(f"{float(v):.7g}")


def hash_params(param_dict: dict, exclude: Iterable[str] = ()) -> str:
    items = sorted((k, _norm(v)) for k, v in _filtered(param_dict, exclude).items())
    return hashlib.sha256(str(items).encode()).hexdigest()


def capture_baseline(param_dict: dict, exclude: Iterable[str] = ()) -> str:
    """Hash to store right after a trusted firmware flash or setup."""
    return hash_params(param_dict, exclude)


def diff_params(baseline: dict, current: dict, exclude: Iterable[str] = ()
                ) -> List[Tuple[str, Optional[float], Optional[float]]]:
    """(name, was, now) for each changed, added or removed parameter."""
    b, c = _filtered(baseline, exclude), _filtered(current, exclude)
    out = []
    for k in sorted(set(b) | set(c)):
        bv = _norm(b[k]) if k in b else None
        cv = _norm(c[k]) if k in c else None
        if bv != cv:
            out.append((k, bv, cv))
    return out


def check_integrity(current_params: dict, known_good_hash: str, exclude: Iterable[str] = ()):
    current_hash = hash_params(current_params, exclude)
    if current_hash != known_good_hash:
        return True, 1.0, "Parameter table hash mismatch — possible firmware/config tampering"
    return False, 0.0, None
