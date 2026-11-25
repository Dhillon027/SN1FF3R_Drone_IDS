"""
The live detection loop: receive -> features -> detectors -> alert log -> black box.

`sn1ff3r run` drives it in the foreground; `sn1ff3r gui` runs it on a
background thread and reads `snapshot()` for the live view. Read timeouts
still run the detectors, so a silent (jammed) link is noticed.
"""

import errno
import threading
import time
from collections import deque
from typing import Any, Callable, Dict, List, Optional

from .config import DetectorConfig
from .features.feature_extractor import FeatureExtractor, MAV_AUTOPILOT_INVALID
from .engine.ids_engine import IDSEngine
from .alerting.logger import SecureLogger
from .alerting.black_box import BlackBoxRecorder

from .detectors.gps_spoof_detector import check_gps_spoof
from .detectors.gps_jamming_detector import check_gps_jamming
from .detectors.dos_detector import check_dos
from .detectors.command_injection_detector import check_command_injection
from .detectors.telemetry_manipulation_detector import check_telemetry_consistency

DETECTORS = [
    check_gps_spoof,
    check_gps_jamming,
    check_dos,
    check_command_injection,
    check_telemetry_consistency,
]  # the parameter integrity check runs on demand: see params.py

GCS_NAMES = {
    "check_gps_spoof": "GPS spoofing",
    "check_gps_jamming": "GPS jamming",
    "check_dos": "link jamming/flood",
    "check_command_injection": "command injection",
    "check_telemetry_consistency": "telemetry tampering",
    "check_integrity": "parameter tampering",
}

HISTORY_S = 180  # seconds of chart history kept for the GUI


class IDSMonitor:
    def __init__(
        self,
        connect: str,
        config: Optional[DetectorConfig] = None,
        alert_log: str = "ids_alerts.jsonl",
        blackbox_dir: Optional[str] = "forensic_snapshots",
        baud: int = 115200,
        on_alert: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_snapshot: Optional[Callable[[str], None]] = None,
        on_status: Optional[Callable[[str], None]] = None,
        track_live_state: bool = False,
        gcs_alerts: bool = True,
        gcs_alert_to: Optional[str] = None,
    ):
        self.connect = connect
        self.baud = baud
        self.config = config or DetectorConfig()
        self.extractor = FeatureExtractor()
        self.engine = IDSEngine(DETECTORS, config=self.config)
        self.alert_logger = SecureLogger(alert_log)
        self.black_box = None
        if blackbox_dir:
            self.black_box = BlackBoxRecorder(
                pre_buffer_size=self.config.blackbox_pre_buffer,
                post_window_s=self.config.blackbox_post_window_s,
                output_dir=blackbox_dir,
            )
        self.on_alert = on_alert
        self.on_snapshot = on_snapshot
        self.on_status = on_status
        # GUI-only bookkeeping; off in headless `sn1ff3r run`
        self.track_live_state = track_live_state
        self.gcs_alerts = gcs_alerts
        self.gcs_alert_to = gcs_alert_to
        self._alert_out = None

        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.master = None
        self.jam_until = 0.0  # simulated receiver-side jamming (GUI test)

        self.status = "starting"
        self.error: Optional[str] = None
        self.started_at = time.time()
        self.msg_count = 0
        self.dropped_by_jam = 0
        self.type_counts: Dict[str, int] = {}
        self.vehicle: Dict[str, Any] = {}
        self.link: Dict[str, Any] = {}
        self.detector_state: Dict[str, Dict[str, Any]] = {
            fn.__name__: {"last_alert": None, "last_reason": None, "hits": 0} for fn in DETECTORS
        }
        self.session_alerts = 0
        self.snapshots_written: List[str] = []
        self.rate_history: deque = deque(maxlen=HISTORY_S)
        self.alt_history: deque = deque(maxlen=HISTORY_S * 2)
        self._last_alt_sample = 0.0

    # ----------------------------------------------------------- control
    def stop(self) -> None:
        self._stop.set()

    def jam(self, seconds: float) -> None:
        """Drop every incoming packet for `seconds` (simulated jamming)."""
        self.jam_until = time.time() + seconds

    def _set_status(self, s: str) -> None:
        self.status = s
        if self.on_status:
            self.on_status(s)

    # -------------------------------------------------------------- loop
    def open(self) -> None:
        """Open the MAVLink link, failing fast with a readable error."""
        from pymavlink import mavutil

        self._set_status(f"connecting to {self.connect}")
        try:
            self.master = mavutil.mavlink_connection(self.connect, baud=self.baud)
        except Exception as e:
            self.error = _connect_hint(self.connect, e)
            self._set_status("error")
            raise ConnectionError(self.error) from e
        if self.gcs_alerts and self.gcs_alert_to:
            self._alert_out = mavutil.mavlink_connection(self.gcs_alert_to)
        self._set_status("waiting for heartbeat")

    def run(self) -> None:
        from pymavlink import mavutil

        if self.master is None:
            self.open()

        while not self._stop.is_set():
            try:
                msg = self.master.recv_match(blocking=True, timeout=0.5)
            except (OSError, ConnectionError) as e:
                self.error = f"{type(e).__name__}: {e}"
                time.sleep(0.5)
                msg = None
            now = time.time()

            if msg is not None and now < self.jam_until:
                self.dropped_by_jam += 1
                msg = None

            if msg is None:
                self._on_silence(now)
                continue
            self._on_message(now, msg, mavutil)

        if self.black_box is not None:
            self._snap(self.black_box.close(time.time()))
        self._set_status("stopped")

    def _on_silence(self, now: float) -> None:
        features = self.extractor.tick(now)
        tick = {"mavpackettype": "_TICK"}
        alerts = self.engine.evaluate(now, tick, features)
        detections = self.engine.last_detections
        self._handle_alerts(alerts, detections, now)
        if self.black_box is not None:
            if detections:
                self._snap(self.black_box.record(now, tick, features, detections))
            else:
                self._snap(self.black_box.poll(now))
        if self.track_live_state:
            self._update_link(now, features)

    def _on_message(self, now: float, msg, mavutil) -> None:
        msg_dict = msg.to_dict()
        msg_dict["_header"] = {
            "srcSystem": msg.get_srcSystem(),
            "srcComponent": msg.get_srcComponent(),
            "seq": msg.get_seq(),
        }
        self.msg_count += 1

        features = self.extractor.update(now, msg_dict)
        alerts = self.engine.evaluate(now, msg_dict, features)
        detections = self.engine.last_detections
        self._handle_alerts(alerts, detections, now)

        if self.black_box is not None:
            self._snap(self.black_box.record(now, msg_dict, features, detections))

        if self.track_live_state:
            mtype = msg_dict.get("mavpackettype", "?")
            self.type_counts[mtype] = self.type_counts.get(mtype, 0) + 1
            self._update_vehicle(now, msg, msg_dict, features, mavutil)
            self._update_link(now, features)
        elif self.status != "live" and msg_dict.get("mavpackettype") == "HEARTBEAT" \
                and self.extractor.vehicle_sysid is not None:
            self._set_status("live")

    def _handle_alerts(self, alerts, detections, now) -> None:
        for d in detections:
            st = self.detector_state.get(d["detector"])
            if st is not None:
                st["hits"] += 1
                st["last_alert"] = now
                st["last_reason"] = d["reason"]
        for alert in alerts:
            self.alert_logger.log(alert)
            self.session_alerts += 1
            if self.gcs_alerts:
                self._send_to_gcs(alert)
            if self.on_alert:
                self.on_alert(alert)

    def _send_to_gcs(self, alert: Dict[str, Any]) -> None:
        name = GCS_NAMES.get(alert["detector"], alert["detector"])
        text = f"SN1FF3R: {name} ({alert['confidence']:.2f})"[:50]
        for link in (self.master, self._alert_out):
            if link is None:
                continue
            try:
                mav = link.mav
                if self.extractor.vehicle_sysid:
                    mav.srcSystem = self.extractor.vehicle_sysid
                mav.srcComponent = 191
                mav.statustext_send(2 if alert["confidence"] >= 0.8 else 4, text.encode())
            except (OSError, ValueError):
                pass

    def _snap(self, path: Optional[str]) -> None:
        if path:
            self.snapshots_written.append(path)
            if self.on_snapshot:
                self.on_snapshot(path)

    # ------------------------------------------------------- live state
    def _update_link(self, now: float, f: Dict[str, float]) -> None:
        with self._lock:
            if "msg_rate_hz" in f:
                self.link["rate_hz"] = f["msg_rate_hz"]
                self.link["baseline_hz"] = f.get("msg_rate_baseline_hz")
                self.link["rate_z"] = f.get("msg_rate_zscore")
                self.rate_history.append((now, f["msg_rate_hz"], f.get("msg_rate_baseline_hz")))
            elif self.jam_until > now or not self.rate_history or now - self.rate_history[-1][0] > 1.5:
                if not self.rate_history or now - self.rate_history[-1][0] >= 1.0:
                    self.rate_history.append((now, 0.0, self.link.get("baseline_hz")))
                    self.link["rate_hz"] = 0.0
            hb = self.extractor.last_heartbeat_time
            self.link["heartbeat_age_s"] = (now - hb) if hb else None

    def _update_vehicle(self, now, msg, d, f, mavutil) -> None:
        mtype = d.get("mavpackettype")
        v = self.vehicle
        with self._lock:
            if mtype == "HEARTBEAT" and d.get("autopilot") != MAV_AUTOPILOT_INVALID \
                    and d["_header"]["srcSystem"] == self.extractor.vehicle_sysid:
                if self.status != "live":
                    self._set_status("live")
                v["sysid"] = d["_header"]["srcSystem"]
                v["type"] = _enum_name(mavutil, "MAV_TYPE", d.get("type"))
                v["autopilot"] = _enum_name(mavutil, "MAV_AUTOPILOT", d.get("autopilot"))
                try:
                    v["mode"] = mavutil.mode_string_v10(msg)
                except Exception:
                    v["mode"] = str(d.get("custom_mode"))
                v["armed"] = bool(d.get("base_mode", 0) & 128)
            elif mtype == "GLOBAL_POSITION_INT" and self.extractor._is_vehicle(d):
                v["lat"] = d.get("lat", 0) / 1e7
                v["lon"] = d.get("lon", 0) / 1e7
                v["alt_msl"] = d.get("alt", 0) / 1000.0
                v["alt_rel"] = d.get("relative_alt", 0) / 1000.0
                v["time_boot_ms"] = d.get("time_boot_ms")
                v["hdg"] = d.get("hdg", 0) / 100.0 if d.get("hdg", 65535) != 65535 else None
                if now - self._last_alt_sample >= 0.5:
                    self._last_alt_sample = now
                    self.alt_history.append((now, v["alt_msl"], v.get("vfr_alt")))
            elif mtype == "VFR_HUD" and self.extractor._is_vehicle(d):
                v["vfr_alt"] = d.get("alt")
                v["groundspeed"] = d.get("groundspeed")
                v["airspeed"] = d.get("airspeed")
                v["climb"] = d.get("climb")
                v["throttle"] = d.get("throttle")
            elif mtype == "GPS_RAW_INT" and self.extractor._is_vehicle(d):
                v["gps_fix"] = d.get("fix_type")
                v["gps_sats"] = d.get("satellites_visible")
                v["gps_raw_lat"] = d.get("lat", 0) / 1e7
                v["gps_raw_lon"] = d.get("lon", 0) / 1e7
                if "gps_ekf_divergence_m" in f:
                    v["gps_ekf_div_m"] = f["gps_ekf_divergence_m"]
            elif mtype == "SYS_STATUS" and self.extractor._is_vehicle(d):
                mv = d.get("voltage_battery", 0)
                v["battery_v"] = mv / 1000.0 if mv and mv != 65535 else None
                rem = d.get("battery_remaining", -1)
                v["battery_pct"] = rem if rem is not None and rem >= 0 else None
            elif mtype == "STATUSTEXT" and self.extractor._is_vehicle(d):
                texts = v.setdefault("statustext", [])
                texts.append({"time": now, "text": d.get("text", ""), "severity": d.get("severity")})
                del texts[:-8]
            if "gps_ekf_divergence_m" in f:
                v["gps_ekf_div_m"] = f["gps_ekf_divergence_m"]

    def snapshot(self) -> Dict[str, Any]:
        """Thread-safe copy of the live state for the GUI."""
        now = time.time()
        with self._lock:
            return {
                "status": self.status,
                "error": self.error,
                "connect": self.connect,
                "uptime_s": now - self.started_at,
                "msg_count": self.msg_count,
                "jammed": now < self.jam_until,
                "jam_remaining_s": max(0.0, self.jam_until - now),
                "dropped_by_jam": self.dropped_by_jam,
                "vehicle": {k: (list(v) if isinstance(v, list) else v) for k, v in self.vehicle.items()},
                "link": dict(self.link),
                "top_types": sorted(self.type_counts.items(), key=lambda kv: -kv[1])[:12],
                "detectors": {k: dict(v) for k, v in self.detector_state.items()},
                "session_alerts": self.session_alerts,
                "blackbox": self.black_box.status() if self.black_box else None,
                "rate_history": list(self.rate_history),
                "alt_history": list(self.alt_history),
                "detector_errors": self.engine.detector_errors,
                "now": now,
            }


def _connect_hint(connect: str, e: Exception) -> str:
    """Turn the common connection failures into something actionable."""
    if isinstance(e, OSError) and e.errno in (errno.EADDRINUSE, errno.EACCES):
        port = connect.rsplit(":", 1)[-1]
        return (f"UDP port {port} is already in use by another program (often MAVProxy itself, "
                f"Mission Planner or QGroundControl, or another sn1ff3r). Give the IDS its own port: "
                f"in the MAVProxy console type  output add 127.0.0.1:14560  and start the IDS with "
                f"--connect udpin:127.0.0.1:14560   (find the other program with: lsof -nP -iUDP:{port})")
    if isinstance(e, (FileNotFoundError, OSError)) and connect.startswith("/dev/"):
        return f"Serial device {connect} not found or not accessible ({e}). Check the cable and --connect."
    return f"Could not open {connect}: {type(e).__name__}: {e}"


def _enum_name(mavutil, enum: str, value) -> Optional[str]:
    try:
        name = mavutil.mavlink.enums[enum][value].name
        return name.replace(enum + "_", "")
    except (KeyError, AttributeError, TypeError):
        return None if value is None else str(value)
