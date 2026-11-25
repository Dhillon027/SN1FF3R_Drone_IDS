"""
Test-only attack simulator for ArduPilot SITL, used by `sn1ff3r attack` and
the GUI's attack lab.

The GPS test only changes SITL's simulator-only SIM_GPS* parameters and puts
them back afterwards. The other tests send packets only to the IDS's own
port, never to the autopilot.

Expected SITL setup:
    sim_vehicle.py -v ArduCopter --console --map \
        --out=udp:127.0.0.1:14560 --out=udp:127.0.0.1:14551
    14560 -> the IDS, 14551 -> this module (GPS test and parameter checks)
"""

import time
from typing import Callable, Optional, Tuple

from pymavlink import mavutil

Log = Callable[[str], None]

# SITL GPS glitch offsets in degrees (newer name first, then the pre-4.5 one)
GLITCH_PARAMS = [("SIM_GPS1_GLTCH_X", "SIM_GPS1_GLTCH_Y"), ("SIM_GPS_GLITCH_X", "SIM_GPS_GLITCH_Y")]


def parse_udp_target(connect: str) -> Optional[Tuple[str, int]]:
    """(host, port) the IDS listens on, if it's a UDP listener."""
    parts = connect.split(":")
    if len(parts) == 3 and parts[0] in ("udpin", "udp"):
        host = parts[1] if parts[1] not in ("0.0.0.0", "") else "127.0.0.1"
        return host, int(parts[2])
    return None


def connect(port: int = 14551, timeout: float = 10.0, log: Log = print):
    """Listen on a MAVProxy output so we can talk to SITL through it."""
    m = mavutil.mavlink_connection(f"udpin:127.0.0.1:{port}", source_system=255, source_component=190)
    log(f"Waiting for SITL heartbeat on port {port}...")
    hb = m.wait_heartbeat(timeout=timeout)
    if hb is None:
        m.close()
        raise TimeoutError(
            f"No heartbeat on udp port {port} within {timeout:.0f}s. Start SITL with a MAVProxy "
            f"output there, e.g.  sim_vehicle.py -v ArduCopter --console --map --out=udp:127.0.0.1:{port}")
    log(f"SITL link up (vehicle system {m.target_system}).")
    return m


def _drain(master, limit: int = 20000) -> None:
    """Throw away queued telemetry so replies aren't stuck behind it."""
    for _ in range(limit):
        if master.recv_match(blocking=False) is None:
            return


def set_param(master, name: str, value: float, timeout: float = 4.5) -> bool:
    """Set a parameter and wait for the echo. False if it doesn't exist."""
    _drain(master)
    for _ in range(3):
        master.mav.param_set_send(master.target_system, master.target_component,
                                  name.encode(), float(value), mavutil.mavlink.MAV_PARAM_TYPE_REAL32)
        deadline = time.time() + timeout / 3
        while time.time() < deadline:
            m = master.recv_match(type="PARAM_VALUE", blocking=True, timeout=0.3)
            # vector params echo all members, so an old value may arrive first
            if m is not None and m.param_id.rstrip("\x00") == name \
                    and abs(m.param_value - value) < 1e-6 + abs(value) * 1e-5:
                return True
    return False


def inject_gps_spoof(master, offset_deg: float = 0.001, duration_s: float = 15.0,
                     log: Log = print, stop: Optional[Callable[[], bool]] = None) -> None:
    """Shift SITL's simulated GPS by `offset_deg` (0.001 deg is about 111 m)
    for `duration_s`, then put it back."""
    names = None
    for x, y in GLITCH_PARAMS:
        if set_param(master, x, offset_deg):
            names = (x, y)
            break
    if names is None:
        raise RuntimeError("SITL did not accept SIM_GPS1_GLTCH_X / SIM_GPS_GLITCH_X -- "
                           "is this link connected to SITL (not a real vehicle)?")
    set_param(master, names[1], offset_deg)
    log(f"[gps_spoof] GPS fix shifted by {offset_deg} deg (~{offset_deg * 111320:.0f} m) via {names[0]}/{names[1]}")
    try:
        end = time.time() + duration_s
        while time.time() < end and not (stop and stop()):
            master.recv_match(blocking=True, timeout=0.2)
    finally:
        ok = set_param(master, names[0], 0.0) and set_param(master, names[1], 0.0)
        log("[gps_spoof] glitch removed, GPS restored" if ok else
            f"[gps_spoof] WARNING: could not confirm restore -- set {names[0]} and {names[1]} to 0 manually")


def inject_command_injection(ids_host: str = "127.0.0.1", ids_port: int = 14550,
                             src_sysid: int = 99, target_sysid: int = 1, log: Log = print) -> None:
    """Send a mode-change command from an untrusted system ID to the IDS's port.
    It goes only to the IDS, never to SITL."""
    direct = mavutil.mavlink_connection(f"udpout:{ids_host}:{ids_port}",
                                        source_system=src_sysid, source_component=1)
    direct.mav.command_long_send(
        target_sysid, 1, mavutil.mavlink.MAV_CMD_DO_SET_MODE, 0,
        1, 4, 0, 0, 0, 0, 0,  # custom mode 4 = GUIDED on Copter
    )
    direct.close()
    log(f"[command_injection] COMMAND_LONG DO_SET_MODE(GUIDED) from rogue system {src_sysid} -> IDS {ids_host}:{ids_port}")


def flood_dos(ids_host: str = "127.0.0.1", ids_port: int = 14550, seconds: float = 3.0,
              rate_hz: float = 1500.0, log: Log = print) -> None:
    """Flood the IDS's port with junk heartbeats."""
    direct = mavutil.mavlink_connection(f"udpout:{ids_host}:{ids_port}", source_system=250)
    n = 0
    interval = 1.0 / rate_hz
    end = time.time() + seconds
    next_t = time.time()
    while time.time() < end:
        direct.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
        n += 1
        next_t += interval
        delay = next_t - time.time()
        if delay > 0:
            time.sleep(delay)
    direct.close()
    log(f"[dos] flooded {n} heartbeats (~{n / seconds:.0f} Hz for {seconds:g}s) -> IDS {ids_host}:{ids_port}")


def forge_telemetry(ids_host: str, ids_port: int, vehicle_sysid: int,
                    get_position: Callable[[], Tuple[float, float, float, float, int]],
                    offset_m: float = 150.0, count: int = 12, log: Log = print) -> None:
    """Send position reports to the IDS, as the vehicle, with the altitude
    raised by `offset_m`. `get_position()` returns the latest real
    (lat, lon, alt_msl, alt_rel, time_boot_ms)."""
    direct = mavutil.mavlink_connection(f"udpout:{ids_host}:{ids_port}",
                                        source_system=vehicle_sysid, source_component=1)
    # read the real altitude once, or our own packets would compound the offset
    _, _, true_msl, true_rel, _ = get_position()
    for _ in range(count):
        lat, lon, _, _, boot_ms = get_position()
        alt_msl, alt_rel = true_msl, true_rel
        direct.mav.global_position_int_send(
            int(boot_ms), int(lat * 1e7), int(lon * 1e7),
            int((alt_msl + offset_m) * 1000), int((alt_rel + offset_m) * 1000), 0, 0, 0, 65535)
        time.sleep(0.2)
    direct.close()
    log(f"[telemetry_forgery] {count} forged GLOBAL_POSITION_INT as system {vehicle_sysid}, altitude +{offset_m:g} m")


def read_vehicle_position(master, timeout: float = 5.0):
    """(lat, lon, alt_msl, alt_rel, time_boot_ms) from the SITL link."""
    m = master.recv_match(type="GLOBAL_POSITION_INT", blocking=True, timeout=timeout)
    if m is None:
        raise TimeoutError("No GLOBAL_POSITION_INT from SITL")
    return m.lat / 1e7, m.lon / 1e7, m.alt / 1000.0, m.relative_alt / 1000.0, m.time_boot_ms


JAM_HELP = """Link jamming can't be produced from outside the receiver on a UDP link.
Ways to test the heartbeat-loss detector:
  * In the GUI (sn1ff3r gui): Attack Lab -> "Jam link" drops every packet at
    the IDS receiver for N seconds -- identical to RF jamming from its viewpoint.
  * In the MAVProxy console:  output list   then   output remove <n>   for the
    127.0.0.1:14550 output, and  output add 127.0.0.1:14550  to restore it.
  * Or pause SITL (Ctrl+Z in its terminal, `fg` to resume)."""
