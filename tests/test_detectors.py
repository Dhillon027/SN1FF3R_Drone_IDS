"""
Each detector fires on an obviously bad input and stays quiet on a normal
one, and config profiles change behaviour. No SITL needed.
"""

import time

from drone_ids.config import DetectorConfig, load_config
from drone_ids.features.feature_extractor import FeatureExtractor
from drone_ids.engine.ids_engine import IDSEngine
from drone_ids.detectors.gps_spoof_detector import check_gps_spoof
from drone_ids.detectors.dos_detector import check_dos
from drone_ids.detectors.command_injection_detector import check_command_injection
from drone_ids.detectors.telemetry_manipulation_detector import check_telemetry_consistency


def _pipeline(config=None):
    return FeatureExtractor(), IDSEngine(
        [check_gps_spoof, check_dos, check_command_injection, check_telemetry_consistency],
        config=config or DetectorConfig(),
    )


def test_gps_spoof_hard_cap_fires():
    ext, engine = _pipeline()
    t = time.time()
    m1 = {"mavpackettype": "GLOBAL_POSITION_INT", "lat": int(28.6 * 1e7), "lon": int(77.2 * 1e7),
          "relative_alt": 10000, "alt": 20000}
    f1 = ext.update(t, m1)
    engine.evaluate(t, m1, f1)

    t += 1.0
    m2 = {"mavpackettype": "GLOBAL_POSITION_INT", "lat": int(29.0 * 1e7), "lon": int(78.0 * 1e7),
          "relative_alt": 10000, "alt": 20000}
    f2 = ext.update(t, m2)
    alerts = engine.evaluate(t, m2, f2)

    assert any(a["detector"] == "check_gps_spoof" for a in alerts)


def test_gps_spoof_normal_flight_is_silent():
    ext, engine = _pipeline()
    t = time.time()
    lat = 28.6
    for _ in range(5):
        m = {"mavpackettype": "GLOBAL_POSITION_INT", "lat": int(lat * 1e7), "lon": int(77.2 * 1e7),
             "relative_alt": 10000, "alt": 20000}
        f = ext.update(t, m)
        alerts = engine.evaluate(t, m, f)
        assert alerts == []
        lat += 0.00001  # small, realistic movement
        t += 1.0


def test_command_injection_unauthorized_source_fires():
    ext, engine = _pipeline()
    t = time.time()
    m = {"mavpackettype": "COMMAND_LONG", "_header": {"srcSystem": 99, "seq": 1}}
    f = ext.update(t, m)
    alerts = engine.evaluate(t, m, f)
    assert any(a["detector"] == "check_command_injection" for a in alerts)


def test_command_injection_authorized_source_is_silent():
    ext, engine = _pipeline()
    t = time.time()
    m = {"mavpackettype": "COMMAND_LONG", "_header": {"srcSystem": 255, "seq": 1}}
    f = ext.update(t, m)
    alerts = engine.evaluate(t, m, f)
    assert alerts == []


def test_dos_heartbeat_timeout_fires():
    ext, engine = _pipeline()
    t = time.time()
    m = {"mavpackettype": "HEARTBEAT"}
    f = ext.update(t, m)
    engine.evaluate(t, m, f)

    # jump forward well past the default 3s timeout, with a non-heartbeat message
    t += 10.0
    m2 = {"mavpackettype": "ATTITUDE"}
    f2 = ext.update(t, m2)
    alerts = engine.evaluate(t, m2, f2)
    assert any(a["detector"] == "check_dos" for a in alerts)


def test_telemetry_mismatch_fires():
    ext, engine = _pipeline()
    t = time.time()
    # streams agree first (the detector ignores boot-time disagreement)
    ext.update(t, {"mavpackettype": "VFR_HUD", "alt": 20.0})
    ext.update(t + 0.1, {"mavpackettype": "GLOBAL_POSITION_INT", "lat": int(28.6 * 1e7), "lon": int(77.2 * 1e7),
                         "relative_alt": 10000, "alt": 20000})
    t += 0.3
    vfr = {"mavpackettype": "VFR_HUD", "alt": 20.0}
    ext.update(t, vfr)
    t += 0.5
    gps = {"mavpackettype": "GLOBAL_POSITION_INT", "lat": int(28.6 * 1e7), "lon": int(77.2 * 1e7),
           "relative_alt": 10000, "alt": 60000}  # 60m MSL vs 20m baro -> way outside tolerance
    f = ext.update(t, gps)
    alerts = engine.evaluate(t, gps, f)
    assert any(a["detector"] == "check_telemetry_consistency" for a in alerts)


def test_config_profiles_change_thresholds():
    default = DetectorConfig()
    survey = load_config("configs/survey_multirotor.yaml")
    fixed_wing = load_config("configs/fixed_wing.yaml")

    assert survey.max_plausible_speed_mps < default.max_plausible_speed_mps
    assert fixed_wing.max_plausible_speed_mps > default.max_plausible_speed_mps


def test_config_defaults_when_no_file_given():
    config = load_config(None)
    assert config == DetectorConfig()


def test_dos_no_false_positive_on_bursty_traffic():
    """Regression test: MAVLink over UDP delivers messages in bursts (many
    within the same millisecond) as normal behavior. This must never be
    mistaken for a flood -- see feature_extractor.py's windowed-rate
    comment for the full story of why a naive 1/gap approach failed here."""
    import random
    random.seed(7)
    ext, engine = _pipeline()
    t = time.time()
    alerts_total = 0
    for i in range(4000):
        gap = random.uniform(0.05, 0.1) if i % 15 == 0 else random.uniform(0.00001, 0.0005)
        t += gap
        m = {"mavpackettype": "ATTITUDE"}
        f = ext.update(t, m)
        alerts_total += len(engine.evaluate(t, m, f))
    assert alerts_total == 0


def test_dos_still_catches_a_real_sustained_flood():
    import random
    random.seed(7)
    ext, engine = _pipeline()
    t = time.time()
    # ~40 s of normal bursty traffic: longer than the 20-window warm-up
    for i in range(8000):
        gap = random.uniform(0.05, 0.1) if i % 15 == 0 else random.uniform(0.00001, 0.0005)
        t += gap
        f = ext.update(t, {"mavpackettype": "ATTITUDE"})
        engine.evaluate(t, {"mavpackettype": "ATTITUDE"}, f)

    flood_alerts = 0
    for i in range(10000):  # 2 s at 5 kHz
        t += 0.0002
        m = {"mavpackettype": "HEARTBEAT"}
        f = ext.update(t, m)
        if engine.evaluate(t, m, f):
            flood_alerts += 1
    assert flood_alerts > 0


def _gps_raw(fix=3, sats=12, h_acc=1500):
    return {"mavpackettype": "GPS_RAW_INT", "fix_type": fix, "satellites_visible": sats, "h_acc": h_acc,
            "lat": int(28.6 * 1e7), "lon": int(77.2 * 1e7), "vel": 0, "cog": 0}


def test_gps_jamming_fix_loss_fires():
    from drone_ids.detectors.gps_jamming_detector import check_gps_jamming
    ext = FeatureExtractor()
    engine = IDSEngine([check_gps_jamming], config=DetectorConfig())
    t = time.time()
    for i in range(20):
        t += 0.2
        m = _gps_raw()
        m["time_usec"] = int(t * 1e6)
        assert engine.evaluate(t, m, ext.update(t, m)) == []
    m = _gps_raw(fix=1, sats=0)
    alerts = engine.evaluate(t + 0.2, m, ext.update(t + 0.2, m))
    assert any(a["detector"] == "check_gps_jamming" for a in alerts)


def test_gps_jamming_quiet_before_first_fix():
    from drone_ids.detectors.gps_jamming_detector import check_gps_jamming
    ext = FeatureExtractor()
    engine = IDSEngine([check_gps_jamming], config=DetectorConfig())
    t = time.time()
    for i in range(20):
        t += 0.2
        m = _gps_raw(fix=1, sats=3)
        assert engine.evaluate(t, m, ext.update(t, m)) == []


def test_alert_is_sent_to_ground_station_as_statustext(tmp_path):
    import socket
    from pymavlink import mavutil
    from drone_ids.monitor import IDSMonitor
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    rx = mavutil.mavlink_connection(f"udpin:127.0.0.1:{port}")
    mon = IDSMonitor("unused", alert_log=str(tmp_path / "a.jsonl"), blackbox_dir=None)
    mon.master = mavutil.mavlink_connection(f"udpout:127.0.0.1:{port}")
    mon.extractor.vehicle_sysid = 1
    mon._handle_alerts([{"time": 1.0, "detector": "check_gps_jamming", "confidence": 0.8, "reason": "r"}], [], 1.0)
    msg = rx.recv_match(type="STATUSTEXT", blocking=True, timeout=3)
    assert msg is not None and msg.text.startswith("SN1FF3R: GPS jamming")
    assert msg.get_srcSystem() == 1 and msg.get_srcComponent() == 191
