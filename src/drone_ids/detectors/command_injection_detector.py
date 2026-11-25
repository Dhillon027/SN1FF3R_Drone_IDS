"""
Flags commands from a system ID that isn't trusted, and sequence-number
anomalies from a sender (a repeated number looks like a replay). The
vehicle's own ID is always trusted, since ArduPilot sends commands too.
"""

from ..config import DetectorConfig

_DEFAULT = DetectorConfig()

COMMAND_TYPES = ("COMMAND_LONG", "COMMAND_INT", "SET_MODE", "SET_POSITION_TARGET_LOCAL_NED",
                 "SET_POSITION_TARGET_GLOBAL_INT", "MISSION_SET_CURRENT", "PARAM_SET")


def check_command_injection(msg, features, config: DetectorConfig = _DEFAULT):
    mtype = msg.get("mavpackettype")
    if mtype not in COMMAND_TYPES:
        return False, 0.0, None

    header = msg.get("_header", {}) or {}
    source = header.get("srcSystem")
    vehicle = features.get("vehicle_sysid")
    cmd = msg.get("command", "")
    what = f"{mtype}{f' cmd={cmd}' if cmd != '' else ''}"

    if source is not None and source not in config.authorized_source_ids and source != vehicle:
        return True, 0.85, f"Unauthorized {what} from system ID {source}"

    gap = features.get("seq_gap")
    if gap is not None:
        if gap == 0:
            return True, 0.6, f"{what} repeats the previous sequence number — possible replay"
        if gap > config.max_seq_gap and features.get("seq_continuous"):
            return True, 0.5, f"{what} after a sequence gap of {gap} — possible injected command"

    return False, 0.0, None
