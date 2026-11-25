"""
Turns raw MAVLink messages into the handful of numbers the detectors use.

Every learned baseline is an EWMA (running mean and variance), so each
message costs O(1) time and memory and no history is ever stored. That is
what lets the detectors compare against this vehicle's own normal
behaviour on a small companion computer.
"""

import math
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

MAV_AUTOPILOT_INVALID = 8  # heartbeats from anything that isn't a flight controller

# Param/mission/log downloads burst hundreds of these per second, so they
# don't count towards the flood rate.
BULK_TRANSFER_TYPES = frozenset({
    "PARAM_VALUE", "MISSION_ITEM", "MISSION_ITEM_INT", "MISSION_COUNT",
    "FILE_TRANSFER_PROTOCOL", "LOG_DATA", "LOG_ENTRY", "BAD_DATA",
})

# Fixes closer together than this turn rounding noise into fake speeds.
MIN_POSITION_DT_S = 0.05


class EwmaStat:
    """Running mean/std in O(1). Higher alpha adapts faster."""
    __slots__ = ("alpha", "mean", "var", "n")

    def __init__(self, alpha: float = 0.05):
        self.alpha = alpha
        self.mean = 0.0
        self.var = 0.0
        self.n = 0

    def update(self, x: float) -> None:
        if self.n == 0:
            self.mean = x
            self.var = 0.0
        else:
            diff = x - self.mean
            incr = self.alpha * diff
            self.mean += incr
            self.var = (1 - self.alpha) * (self.var + diff * incr)
        self.n += 1

    @property
    def std(self) -> float:
        return math.sqrt(self.var) if self.var > 0 else 0.0

    def zscore(self, x: float, min_std: float = 1e-6, min_samples: int = 0) -> float:
        """How unusual `x` is. Returns 0 until `min_samples` values are in;
        `min_std` stops a very quiet baseline from exaggerating small changes."""
        if self.n < min_samples:
            return 0.0
        s = max(self.std, min_std)
        return (x - self.mean) / s if s > 1e-6 else 0.0


def haversine_m(p1, p2) -> float:
    """Great-circle distance in meters between two (lat, lon) points."""
    R = 6371000.0
    lat1, lon1, lat2, lon2 = map(math.radians, [*p1, *p2])
    dlat, dlon = lat2 - lat1, lon2 - lon1
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 2 * R * math.asin(min(1.0, math.sqrt(a)))


def offset_ne_m(p1, p2) -> Tuple[float, float]:
    """(north, east) metres from p1 to p2, flat-earth approximation."""
    north = math.radians(p2[0] - p1[0]) * 6371000.0
    east = math.radians(p2[1] - p1[1]) * 6371000.0 * math.cos(math.radians(p1[0]))
    return north, east


def _valid_fix(lat: float, lon: float) -> bool:
    # ArduPilot reports 0,0 before it has a fix
    return not (lat == 0.0 and lon == 0.0)


@dataclass
class _PositionTrack:
    """Jump tracking for one position source (EKF output or raw GPS)."""
    last: Optional[tuple] = None
    last_t: Optional[float] = None
    residual: EwmaStat = field(default_factory=lambda: EwmaStat(alpha=0.05))

    def step(self, t: float, pos: tuple, vel_ne: Optional[Tuple[float, float]]):
        """Returns (jump_speed, residual_speed) in m/s, or None.

        The residual is how far the fix lands from where the reported
        velocity predicted. Real acceleration keeps it small; a spoofed jump
        doesn't."""
        if self.last is None or self.last_t is None:
            self.last, self.last_t = pos, t
            return None
        dt = t - self.last_t
        if dt < 0 or dt > 10.0:
            # reboot or long gap: start over
            self.last, self.last_t = pos, t
            return None
        if dt < MIN_POSITION_DT_S:
            return None
        dn, de = offset_ne_m(self.last, pos)
        jump = math.hypot(dn, de) / dt
        if vel_ne is not None:
            residual = math.hypot(dn - vel_ne[0] * dt, de - vel_ne[1] * dt) / dt
        else:
            residual = jump
        self.last, self.last_t = pos, t
        return jump, residual


@dataclass
class FeatureExtractor:
    """State updated once per message; `update()` returns only this message's features."""
    heartbeat_ewma_gap: EwmaStat = field(default_factory=lambda: EwmaStat(alpha=0.1))
    msg_rate_ewma: EwmaStat = field(default_factory=lambda: EwmaStat(alpha=0.2))
    rate_window_s: float = 1.0

    vehicle_sysid: Optional[int] = None
    last_heartbeat_time: Optional[float] = None

    fused_track: _PositionTrack = field(default_factory=_PositionTrack)
    raw_track: _PositionTrack = field(default_factory=_PositionTrack)
    last_fused_pos: Optional[tuple] = None
    last_raw_pos: Optional[tuple] = None
    last_raw_pos_time: Optional[float] = None

    last_seq_by_src: Dict[Tuple[int, int], int] = field(default_factory=dict)
    last_baro_alt_msl_m: Optional[float] = None
    last_baro_time: Optional[float] = None
    alt_streams_synced: bool = False
    _last_boot_ms: Optional[int] = None

    _rate_window_start: Optional[float] = None
    _rate_window_count: int = 0
    _seq_streak: Dict[Tuple[int, int], int] = field(default_factory=dict)
    _good_fixes: int = 0
    sats_ewma: EwmaStat = field(default_factory=lambda: EwmaStat(alpha=0.05))

    # ------------------------------------------------------------------
    def _is_vehicle(self, msg: dict) -> bool:
        src = (msg.get("_header") or {}).get("srcSystem")
        return src is None or self.vehicle_sysid is None or src == self.vehicle_sysid

    def update(self, timestamp: float, msg: dict) -> Dict[str, float]:
        features: Dict[str, float] = {}
        mtype = msg.get("mavpackettype")
        header = msg.get("_header") or {}

        # Message rate, counted over 1 s windows so normal UDP bursts average out.
        if self._rate_window_start is None:
            self._rate_window_start = timestamp
        if mtype not in BULK_TRANSFER_TYPES:
            self._rate_window_count += 1

        elapsed = timestamp - self._rate_window_start
        if elapsed >= self.rate_window_s:
            rate = self._rate_window_count / elapsed
            # Score before updating, so a flood can't pull the baseline up to itself.
            # The warm-up and std floor stop a young or very steady baseline over-reacting.
            floor = max(2.0, 0.1 * self.msg_rate_ewma.mean)
            features["msg_rate_zscore"] = self.msg_rate_ewma.zscore(rate, min_std=floor, min_samples=20)
            features["msg_rate_ratio"] = rate / max(1.0, self.msg_rate_ewma.mean)
            features["msg_rate_hz"] = rate
            features["msg_rate_baseline_hz"] = self.msg_rate_ewma.mean
            self.msg_rate_ewma.update(rate)
            self._rate_window_start = timestamp
            self._rate_window_count = 0

        # Sequence numbers per (system, component), followed on every packet.
        src = header.get("srcSystem")
        comp = header.get("srcComponent", 0)
        seq = header.get("seq")
        if src is not None and seq is not None and mtype != "_TICK":
            key = (src, comp)
            prev = self.last_seq_by_src.get(key)
            if prev is not None:
                gap = (seq - prev) % 256
                features["seq_gap"] = gap
                # Gaps only mean something for senders we normally see in full.
                streak = self._seq_streak.get(key, 0)
                features["seq_continuous"] = 1.0 if streak >= 10 else 0.0
                self._seq_streak[key] = streak + 1 if gap == 1 else 0
            self.last_seq_by_src[key] = seq

        if mtype == "HEARTBEAT":
            # Only the flight controller's heartbeat counts, so nobody else's can mask a jam.
            if msg.get("autopilot", 0) != MAV_AUTOPILOT_INVALID:
                if self.vehicle_sysid is None and src is not None:
                    self.vehicle_sysid = src
                if self._is_vehicle(msg):
                    if self.last_heartbeat_time is not None:
                        gap = timestamp - self.last_heartbeat_time
                        self.heartbeat_ewma_gap.update(gap)
                        features["heartbeat_gap_s"] = gap
                    self.last_heartbeat_time = timestamp
                    features["time_since_heartbeat_s"] = 0.0

        elif mtype == "GLOBAL_POSITION_INT" and self._is_vehicle(msg):
            lat, lon = msg.get("lat", 0) / 1e7, msg.get("lon", 0) / 1e7
            if _valid_fix(lat, lon):
                pos = (lat, lon)
                # autopilot clock, not arrival time (UDP jitter would fake speed)
                t = msg["time_boot_ms"] / 1000.0 if msg.get("time_boot_ms") else timestamp
                vel = (msg.get("vx", 0) / 100.0, msg.get("vy", 0) / 100.0)
                r = self.fused_track.step(t, pos, vel)
                if r is not None:
                    jump, residual = r
                    features["position_jump_speed_mps"] = jump
                    features["position_residual_mps"] = residual
                    features["position_jump_zscore"] = self.fused_track.residual.zscore(
                        residual, min_std=1.0, min_samples=20)
                    self.fused_track.residual.update(residual)
                self.last_fused_pos = pos
                if self.last_raw_pos is not None and self.last_raw_pos_time is not None \
                        and timestamp - self.last_raw_pos_time < 2.0:
                    features["gps_ekf_divergence_m"] = haversine_m(pos, self.last_raw_pos)
            features["gps_alt_rel_m"] = msg.get("relative_alt", 0) / 1000.0
            features["gps_alt_msl_m"] = msg.get("alt", 0) / 1000.0
            boot_ms = msg.get("time_boot_ms")
            if boot_ms is not None and self._last_boot_ms is not None and boot_ms < self._last_boot_ms:
                # autopilot rebooted
                self.alt_streams_synced = False
            self._last_boot_ms = boot_ms
            if self.last_baro_alt_msl_m is not None:
                features["baro_alt_msl_m"] = self.last_baro_alt_msl_m
                features["baro_age_s"] = timestamp - self.last_baro_time
                # VFR_HUD reads 0 during boot, so wait until both streams agree once.
                if _valid_fix(lat, lon) and abs(features["gps_alt_msl_m"] - self.last_baro_alt_msl_m) < 2.0:
                    self.alt_streams_synced = True
            features["alt_streams_synced"] = 1.0 if self.alt_streams_synced else 0.0

        elif mtype == "GPS_RAW_INT" and self._is_vehicle(msg):
            fix = msg.get("fix_type", 0)
            features["gps_fix_type"] = fix
            if fix >= 3:
                self._good_fixes += 1
            features["gps_had_fix"] = 1.0 if self._good_fixes >= 10 else 0.0
            sats = msg.get("satellites_visible", 255)
            if sats != 255:
                features["gps_sats"] = sats
                if self.sats_ewma.n >= 10:
                    features["gps_sats_baseline"] = self.sats_ewma.mean
                if fix >= 3:
                    self.sats_ewma.update(sats)
            if msg.get("h_acc"):
                features["gps_h_acc_m"] = msg["h_acc"] / 1000.0
            lat, lon = msg.get("lat", 0) / 1e7, msg.get("lon", 0) / 1e7
            if msg.get("fix_type", 0) >= 3 and _valid_fix(lat, lon):
                pos = (lat, lon)
                t = msg["time_usec"] / 1e6 if msg.get("time_usec") else timestamp
                vel = None
                gs = msg.get("vel", 65535)
                cog = msg.get("cog", 65535)
                if gs != 65535 and cog != 65535:
                    v = gs / 100.0
                    c = math.radians(cog / 100.0)
                    vel = (v * math.cos(c), v * math.sin(c))
                r = self.raw_track.step(t, pos, vel)
                if r is not None:
                    features["gps_raw_jump_speed_mps"] = r[0]
                self.last_raw_pos = pos
                self.last_raw_pos_time = timestamp
                if self.last_fused_pos is not None:
                    features["gps_ekf_divergence_m"] = haversine_m(pos, self.last_fused_pos)

        elif mtype == "VFR_HUD" and self._is_vehicle(msg):
            # Should match GLOBAL_POSITION_INT.alt; a forged stream rarely fakes both.
            self.last_baro_alt_msl_m = msg.get("alt")
            self.last_baro_time = timestamp
            features["baro_alt_msl_m"] = self.last_baro_alt_msl_m

        if self.vehicle_sysid is not None:
            features["vehicle_sysid"] = self.vehicle_sysid

        if self.last_heartbeat_time is not None:
            features.setdefault("time_since_heartbeat_s", timestamp - self.last_heartbeat_time)

        return features

    def tick(self, timestamp: float) -> Dict[str, float]:
        """Features when no message arrived at all, so silence (jamming) is still measured."""
        features: Dict[str, float] = {}
        if self.last_heartbeat_time is not None:
            features["time_since_heartbeat_s"] = timestamp - self.last_heartbeat_time
        return features
