"""
Telemetry tampering: GLOBAL_POSITION_INT and VFR_HUD both report MSL
altitude on ArduPilot, so a large difference means one was forged.
"""

from ..config import DetectorConfig

_DEFAULT = DetectorConfig()


def check_telemetry_consistency(msg, features, config: DetectorConfig = _DEFAULT):
    if msg.get("mavpackettype") != "GLOBAL_POSITION_INT":
        return False, 0.0, None

    gps_alt = features.get("gps_alt_msl_m")
    baro_alt = features.get("baro_alt_msl_m")
    if gps_alt is None or baro_alt is None:
        return False, 0.0, None
    # ignore a stale VFR_HUD, and the boot period before the streams first agree
    if features.get("baro_age_s", 0.0) > config.baro_max_age_s:
        return False, 0.0, None
    if not features.get("alt_streams_synced", 1.0):
        return False, 0.0, None

    diff = abs(gps_alt - baro_alt)
    if diff > config.alt_tolerance_m:
        return True, 0.75, (f"Altitude mismatch: GLOBAL_POSITION_INT {gps_alt:.1f} m vs "
                            f"VFR_HUD {baro_alt:.1f} m (Δ{diff:.1f} m)")

    return False, 0.0, None
