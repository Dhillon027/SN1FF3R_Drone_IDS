"""
All detector thresholds, with defaults, optionally loaded from YAML.

Different airframes need different limits (a fixed-wing flies faster than a
survey quad), so each vehicle gets a config file instead of a code change.
Without a file the multirotor defaults below are used.
"""

from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Set

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


@dataclass
class DetectorConfig:
    # gps_spoof_detector
    max_plausible_speed_mps: float = 40.0
    gps_zscore_threshold: float = 4.0
    # max distance between the raw GPS fix and the EKF position
    gps_ekf_divergence_m: float = 30.0

    # gps_jamming_detector
    gps_jam_sats_drop: int = 6
    gps_jam_max_h_acc_m: float = 50.0

    # dos_detector
    heartbeat_timeout_s: float = 3.0
    flood_zscore_threshold: float = 5.0
    # a flood must also be at least this many times the usual rate
    flood_rate_ratio: float = 3.0

    # command_injection_detector
    authorized_source_ids: Set[int] = field(default_factory=lambda: {255})
    max_seq_gap: int = 5

    # telemetry_manipulation_detector
    alt_tolerance_m: float = 15.0
    # VFR_HUD readings older than this are not used for the cross-check
    baro_max_age_s: float = 2.0

    # engine
    min_confidence: float = 0.0
    # repeat hits within this window become a count, not new lines (0 = off)
    alert_cooldown_s: float = 3.0

    # black box
    blackbox_pre_buffer: int = 200
    blackbox_post_window_s: float = 5.0

    # params that change on their own and are skipped by the integrity check
    param_integrity_exclude: List[str] = field(default_factory=lambda: [
        "STAT_*", "BARO*_GND_PRESS", "BARO*_GND_TEMP", "GND_ABS_PRESS",
        "GND_TEMP", "INS_GYR*OFFS*", "INS_GYROFFS*", "COMPASS_OFS*",
        "COMPASS_DEC", "MIS_TOTAL", "SYSID_SW_MREV", "FORMAT_VERSION",
        "MOT_THST_HOVER",   # learned in flight
        "ARSPD*_OFFSET",    # re-zeroed at boot
    ])


def load_config(path: str = None) -> DetectorConfig:
    """Load thresholds from YAML; anything not in the file keeps its default."""
    if path is None:
        return DetectorConfig()

    if not _HAS_YAML:
        raise RuntimeError(
            "PyYAML is required to load a config file. Install it with: "
            "pip install pyyaml  (or run without --config to use defaults)."
        )

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(p, "r") as f:
        raw: Dict[str, Any] = yaml.safe_load(f) or {}

    if not isinstance(raw, dict):
        raise ValueError(f"Config file {path} must be a YAML mapping of key: value")

    defaults = asdict(DetectorConfig())
    unknown = sorted(set(raw) - set(defaults))
    if unknown:
        raise ValueError(
            f"Unknown key(s) in {path}: {', '.join(unknown)}. "
            f"Valid keys: {', '.join(sorted(defaults))}"
        )
    raw = {k: v for k, v in raw.items() if v is not None}

    merged = {**defaults, **raw}
    merged["authorized_source_ids"] = set(merged["authorized_source_ids"])
    return DetectorConfig(**merged)
