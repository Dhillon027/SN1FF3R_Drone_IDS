"""
GPS spoofing, in three layers:
  1. a hard speed limit on how fast the raw GPS fix or the EKF position moved;
  2. the raw GPS fix drifting away from the EKF's own estimate;
  3. a learned baseline of how far each fix lands from where the reported
     velocity predicted (normal acceleration keeps this small, a jump doesn't).
"""

from ..config import DetectorConfig

_DEFAULT = DetectorConfig()


_GPS_TYPES = frozenset({"GLOBAL_POSITION_INT", "GPS_RAW_INT"})


def check_gps_spoof(msg, features, config: DetectorConfig = _DEFAULT):
    if msg.get("mavpackettype") not in _GPS_TYPES:
        return False, 0.0, None
    cap = config.max_plausible_speed_mps

    raw_speed = features.get("gps_raw_jump_speed_mps")
    if raw_speed is not None and raw_speed > cap:
        return True, 0.9, f"Raw GPS fix jumped at {raw_speed:.1f} m/s (hard cap {cap:g})"

    speed = features.get("position_jump_speed_mps")
    if speed is not None and speed > cap:
        return True, 0.9, f"Implausible position jump: {speed:.1f} m/s (hard cap {cap:g})"

    div = features.get("gps_ekf_divergence_m")
    if div is not None and div > config.gps_ekf_divergence_m:
        return True, 0.8, (f"Raw GPS disagrees with EKF position by {div:.0f} m "
                           f"(limit {config.gps_ekf_divergence_m:g} m) — possible spoof/glitch")

    z = features.get("position_jump_zscore", 0.0)
    if z > config.gps_zscore_threshold:
        res = features.get("position_residual_mps", 0.0)
        return True, 0.6, (f"Position moved {res:.1f} m/s off its reported velocity "
                           f"({z:.1f} std devs above baseline)")

    return False, 0.0, None
