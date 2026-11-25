"""
GPS jamming: after a good fix has been held, the fix is lost, the satellite
count falls well below its learned level, or the reported accuracy collapses.
"""

from ..config import DetectorConfig

_DEFAULT = DetectorConfig()


def check_gps_jamming(msg, features, config: DetectorConfig = _DEFAULT):
    if msg.get("mavpackettype") != "GPS_RAW_INT" or not features.get("gps_had_fix"):
        return False, 0.0, None

    fix = features.get("gps_fix_type", 0)
    if fix < 3:
        return True, 0.8, f"GPS fix lost (fix type {fix}) — possible GPS jamming"

    sats, base = features.get("gps_sats"), features.get("gps_sats_baseline")
    if sats is not None and base is not None and base - sats >= config.gps_jam_sats_drop:
        return True, 0.7, f"GPS satellites dropped to {sats} from ~{base:.0f} — possible GPS jamming"

    hacc = features.get("gps_h_acc_m")
    if hacc is not None and hacc > config.gps_jam_max_h_acc_m:
        return True, 0.6, (f"GPS accuracy degraded to {hacc:.0f} m "
                           f"(limit {config.gps_jam_max_h_acc_m:g} m) — possible GPS jamming")

    return False, 0.0, None
