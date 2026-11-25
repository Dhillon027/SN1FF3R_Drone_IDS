"""
Denial of service: the vehicle's heartbeat going silent (jamming) and
message floods measured against the link's learned normal rate.
"""

from ..config import DetectorConfig

_DEFAULT = DetectorConfig()


def check_dos(msg, features, config: DetectorConfig = _DEFAULT):
    stale = features.get("time_since_heartbeat_s")
    if stale is not None and stale > config.heartbeat_timeout_s:
        return True, 0.85, f"No vehicle HEARTBEAT for {stale:.1f}s — possible link jam/DoS"

    z = features.get("msg_rate_zscore")
    # must be both unusual and several times normal, so a GCS doubling its rates isn't a flood
    if z is not None and z > config.flood_zscore_threshold \
            and features.get("msg_rate_ratio", float("inf")) >= config.flood_rate_ratio:
        rate = features.get("msg_rate_hz", 0.0)
        base = features.get("msg_rate_baseline_hz", 0.0)
        return True, 0.7, (f"Message rate {rate:.0f} Hz vs ~{base:.0f} Hz baseline "
                           f"({z:.1f} std devs) — possible flood")

    return False, 0.0, None
