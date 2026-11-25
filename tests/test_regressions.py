"""
Edge cases seen while testing against ArduPilot SITL: each one checks that a
real-world situation is handled without a false alert or a missed attack.
"""

import json
import random
from pathlib import Path

import pytest

from drone_ids.config import DetectorConfig, load_config
from drone_ids.features.feature_extractor import FeatureExtractor
from drone_ids.engine.ids_engine import IDSEngine
from drone_ids.detectors.gps_spoof_detector import check_gps_spoof
from drone_ids.detectors.dos_detector import check_dos
from drone_ids.detectors.command_injection_detector import check_command_injection
from drone_ids.detectors.telemetry_manipulation_detector import check_telemetry_consistency
from drone_ids.detectors.firmware_integrity_checker import diff_params, hash_params
from drone_ids.alerting.logger import SecureLogger
from drone_ids.alerting.black_box import BlackBoxRecorder, verify_snapshot

DETECTORS = [check_gps_spoof, check_dos, check_command_injection, check_telemetry_consistency]
M_PER_DEG = 111320.0


def pipeline(**cfg):
    return FeatureExtractor(), IDSEngine(DETECTORS, config=DetectorConfig(**cfg))


def gpi(lat, lon, boot_ms=None, vn=0.0, ve=0.0, alt_m=100.0):
    m = {"mavpackettype": "GLOBAL_POSITION_INT", "lat": int(round(lat * 1e7)), "lon": int(round(lon * 1e7)),
         "alt": int(alt_m * 1000), "relative_alt": 20000, "vx": int(vn * 100), "vy": int(ve * 100),
         "_header": {"srcSystem": 1, "srcComponent": 1, "seq": 0}}
    if boot_ms is not None:
        m["time_boot_ms"] = boot_ms
    return m


def feed(ext, eng, t, msg):
    return eng.evaluate(t, msg, ext.update(t, msg))


# ------------------------------------------------------------ GPS spoof --

def test_udp_burst_arrival_is_not_a_position_jump():
    """Two fixes 250 ms apart on the autopilot clock arriving 5 ms apart
    over UDP must not read as 250 m/s."""
    ext, eng = pipeline()
    feed(ext, eng, 0.0, gpi(28.6, 77.2, boot_ms=1000, vn=5))
    alerts = feed(ext, eng, 0.005, gpi(28.6 + 1.25 / M_PER_DEG, 77.2, boot_ms=1250, vn=5))
    assert alerts == []


def test_hover_then_cruise_is_not_spoofing():
    """A quiet hover baseline made the plain speed z-score explode on the
    first normal cruise leg."""
    random.seed(1)
    ext, eng = pipeline()
    lat, t, boot, hits = 28.6, 0.0, 1000, []
    for _ in range(240):
        lat += random.uniform(-1, 1) * 0.02 / M_PER_DEG
        t += 0.25; boot += 250
        hits += feed(ext, eng, t, gpi(lat, 77.2, boot_ms=boot))
    for _ in range(40):  # accelerate to 8 m/s north with matching velocity
        lat += 8 * 0.25 / M_PER_DEG
        t += 0.25; boot += 250
        hits += feed(ext, eng, t, gpi(lat, 77.2, boot_ms=boot, vn=8))
    assert hits == []


def test_no_fix_zero_position_is_ignored():
    ext, eng = pipeline()
    feed(ext, eng, 0, gpi(0, 0, boot_ms=1000))
    assert feed(ext, eng, 1, gpi(28.6, 77.2, boot_ms=2000)) == []


def test_raw_gps_divergence_from_ekf_fires():
    """What an SITL GPS glitch looks like: the raw fix moves, the EKF doesn't."""
    ext, eng = pipeline()
    feed(ext, eng, 0.0, gpi(28.6, 77.2, boot_ms=1000))
    raw = {"mavpackettype": "GPS_RAW_INT", "fix_type": 3, "lat": int((28.6 + 0.001) * 1e7),
           "lon": int(77.2 * 1e7), "time_usec": 1_100_000, "vel": 0, "cog": 0,
           "_header": {"srcSystem": 1, "srcComponent": 1, "seq": 1}}
    alerts = feed(ext, eng, 0.1, raw)
    assert any("disagrees with EKF" in a["reason"] for a in alerts)


def test_raw_gps_jump_hard_cap_fires():
    ext, eng = pipeline()
    base = {"mavpackettype": "GPS_RAW_INT", "fix_type": 3, "vel": 0, "cog": 0, "lon": int(77.2 * 1e7),
            "_header": {"srcSystem": 1, "srcComponent": 1, "seq": 1}}
    feed(ext, eng, 0.0, {**base, "lat": int(28.6 * 1e7), "time_usec": 1_000_000})
    alerts = feed(ext, eng, 0.2, {**base, "lat": int(28.601 * 1e7), "time_usec": 1_200_000})
    assert any(a["detector"] == "check_gps_spoof" and "Raw GPS fix jumped" in a["reason"] for a in alerts)


# ------------------------------------------------------------------ DoS --

def test_attacker_heartbeats_cannot_mask_vehicle_silence():
    ext, eng = pipeline(alert_cooldown_s=0)
    ext.update(0, {"mavpackettype": "HEARTBEAT", "autopilot": 3, "_header": {"srcSystem": 1}})
    hits = []
    for t in range(1, 10):
        hits += feed(ext, eng, t, {"mavpackettype": "HEARTBEAT", "autopilot": 8, "_header": {"srcSystem": 255}})
    assert any(a["detector"] == "check_dos" for a in hits)


def test_total_silence_is_detected_via_tick():
    """Total silence still reaches the detectors."""
    ext, eng = pipeline()
    ext.update(0, {"mavpackettype": "HEARTBEAT", "autopilot": 3, "_header": {"srcSystem": 1}})
    alerts = eng.evaluate(5.0, {"mavpackettype": "_TICK"}, ext.tick(5.0))
    assert any(a["detector"] == "check_dos" for a in alerts)


def test_stream_rate_startup_ramp_is_not_a_flood():
    """GCS connects and requests streams: ~3 Hz -> ~80 Hz a few seconds in."""
    ext, eng = pipeline()
    t, hits = 0.0, []
    for rate, secs in ((3, 8), (80, 30), (160, 20)):  # ramp, then a 2x stream-rate change
        for _ in range(rate * secs):
            t += 1.0 / rate
            hits += feed(ext, eng, t, {"mavpackettype": "ATTITUDE"})
    assert hits == []


def test_param_download_burst_is_not_a_flood():
    ext, eng = pipeline()
    t, hits = 0.0, []
    for _ in range(80 * 30):
        t += 1 / 80
        feed(ext, eng, t, {"mavpackettype": "ATTITUDE"})
    for i in range(1400):  # full param table in ~2 s, plus normal telemetry
        t += 1 / 700
        hits += feed(ext, eng, t, {"mavpackettype": "PARAM_VALUE" if i % 9 else "ATTITUDE"})
    assert hits == []


# ----------------------------------------------------- command injection --

def test_legit_gcs_commands_with_seq_gaps_are_silent():
    """The IDS only sees a routed subset of the GCS's packets, so gaps
    between its commands are normal."""
    ext, eng = pipeline()
    hits = []
    for s in (10, 40, 90, 91):
        hits += feed(ext, eng, s, {"mavpackettype": "COMMAND_LONG", "command": 400,
                                   "_header": {"srcSystem": 255, "srcComponent": 190, "seq": s}})
    assert hits == []


def test_seq_gap_on_a_continuous_stream_fires():
    ext, eng = pipeline(alert_cooldown_s=0)
    for s in range(20):
        feed(ext, eng, s * 0.1, {"mavpackettype": "HEARTBEAT", "autopilot": 8,
                                 "_header": {"srcSystem": 255, "srcComponent": 190, "seq": s}})
    alerts = feed(ext, eng, 3.0, {"mavpackettype": "COMMAND_LONG", "command": 176,
                                  "_header": {"srcSystem": 255, "srcComponent": 190, "seq": 60}})
    assert any("sequence gap" in a["reason"] for a in alerts)


def test_vehicle_own_commands_are_authorized():
    ext, eng = pipeline()
    ext.update(0, {"mavpackettype": "HEARTBEAT", "autopilot": 3, "_header": {"srcSystem": 7, "seq": 0}})
    assert feed(ext, eng, 1, {"mavpackettype": "COMMAND_LONG", "command": 2000,
                              "_header": {"srcSystem": 7, "srcComponent": 1, "seq": 1}}) == []


# ------------------------------------------------------------ telemetry --

def test_boot_time_vfr_zero_is_not_tampering():
    ext, eng = pipeline()
    ext.update(0, {"mavpackettype": "VFR_HUD", "alt": 0.0})
    assert feed(ext, eng, 0.1, gpi(28.6, 77.2, boot_ms=1000, alt_m=584.0)) == []


def test_stale_vfr_hud_is_not_used():
    ext, eng = pipeline()
    ext.update(0, {"mavpackettype": "VFR_HUD", "alt": 100.0})
    feed(ext, eng, 0.1, gpi(28.6, 77.2, boot_ms=1000, alt_m=100.0))  # agree -> synced
    assert feed(ext, eng, 30.0, gpi(28.6, 77.2, boot_ms=30000, alt_m=300.0)) == []


# --------------------------------------------------------------- engine --

def test_sustained_condition_is_rate_limited_but_counted():
    ext, eng = pipeline(alert_cooldown_s=3.0)
    ext.update(0, {"mavpackettype": "VFR_HUD", "alt": 20.0})
    feed(ext, eng, 0.05, gpi(28.6, 77.2, boot_ms=1000, alt_m=20.0))
    logged = []
    for i in range(1, 41):  # 10 s of forged altitude at 4 Hz
        t = i * 0.25
        ext.update(t - 0.01, {"mavpackettype": "VFR_HUD", "alt": 20.0})
        logged += feed(ext, eng, t, gpi(28.6, 77.2, boot_ms=1000 + i * 250, alt_m=200.0))
    assert 3 <= len(logged) <= 4
    assert sum(a["repeats"] for a in logged) + len(logged) >= 36


def test_broken_detector_does_not_stop_the_others():
    def broken(msg, features, config):
        raise KeyError("boom")
    eng = IDSEngine([broken, check_command_injection])
    alerts = eng.evaluate(0, {"mavpackettype": "COMMAND_LONG", "_header": {"srcSystem": 99, "seq": 1}}, {})
    assert [a["detector"] for a in alerts] == ["check_command_injection"]
    assert eng.detector_errors == 1


# ------------------------------------------------------ forensic output --

def test_black_box_closes_incident_during_silence(tmp_path):
    bb = BlackBoxRecorder(pre_buffer_size=5, post_window_s=1.0, output_dir=str(tmp_path))
    bb.record(0.0, {"mavpackettype": "COMMAND_LONG"}, {}, [{"detector": "x", "confidence": 1, "reason": "r"}])
    assert bb.poll(0.5) is None
    path = bb.poll(1.5)
    assert path and verify_snapshot(path)
    assert not list(tmp_path.glob("*_before_partial.json"))


def test_snapshot_with_edited_packet_fails_verification(tmp_path):
    bb = BlackBoxRecorder(pre_buffer_size=5, post_window_s=1.0, output_dir=str(tmp_path))
    bb.record(0.0, {"mavpackettype": "HEARTBEAT"}, {}, [])
    bb.record(0.1, {"mavpackettype": "COMMAND_LONG", "_header": {"srcSystem": 99}}, {},
              [{"detector": "x", "confidence": 1, "reason": "r"}])
    path = bb.poll(2.0)
    data = json.loads(Path(path).read_text())
    data["during_and_after"][0]["msg"]["_header"]["srcSystem"] = 255
    Path(path).write_text(json.dumps(data))
    assert verify_snapshot(path) is False


def test_alert_log_verify_on_missing_file_and_tamper(tmp_path):
    p = tmp_path / "a.jsonl"
    assert SecureLogger(str(p)).verify_chain() is True
    lg = SecureLogger(str(p))
    for i in range(3):
        lg.log({"time": i, "detector": "d", "confidence": 0.9, "reason": f"r{i}"})
    lines = p.read_text().splitlines()
    lines[1] = lines[1].replace("r1", "r1-edited")
    p.write_text("\n".join(lines) + "\n")
    assert SecureLogger(str(p)).verify_chain() is False


def test_gui_alert_store_flags_chain_break(tmp_path):
    from drone_ids.gui.server import AlertStore
    p = tmp_path / "a.jsonl"
    lg = SecureLogger(str(p))
    for i in range(4):
        lg.log({"time": i, "detector": "d", "confidence": 0.9, "reason": f"r{i}"})
    store = AlertStore(p)
    assert store.summary()["chain_ok"] is True
    lines = p.read_text().splitlines()
    del lines[2]
    p.write_text("\n".join(lines) + "\n")  # shrinks -> store re-reads from scratch
    s = store.since(0, 0)
    assert s["chain_ok"] is False and s["broken_at"] == 2


# --------------------------------------------------------------- config --

def test_unknown_config_key_is_a_clear_error(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("max_plausable_speed_mps: 10\n")  # typo
    with pytest.raises(ValueError, match="max_plausable_speed_mps"):
        load_config(str(p))


def test_param_integrity_ignores_volatile_params_and_names_changes():
    ex = DetectorConfig().param_integrity_exclude
    base = {"RTL_ALT": 1500.0, "STAT_RUNTIME": 10.0, "BARO1_GND_PRESS": 101325.0}
    now = {"RTL_ALT": 1500.0, "STAT_RUNTIME": 99.0, "BARO1_GND_PRESS": 100990.0}
    assert hash_params(base, ex) == hash_params(now, ex)
    now["RTL_ALT"] = 4000.0
    assert diff_params(base, now, ex) == [("RTL_ALT", 1500.0, 4000.0)]


def test_learned_hover_throttle_is_not_tampering():
    """Seen live in SITL: MOT_THST_HOVER drifted between baseline and check."""
    ex = DetectorConfig().param_integrity_exclude
    assert diff_params({"MOT_THST_HOVER": 0.3764366, "FENCE_ENABLE": 0.0},
                       {"MOT_THST_HOVER": 0.3764393, "FENCE_ENABLE": 1.0}, ex) == [("FENCE_ENABLE", 0.0, 1.0)]


def test_open_incident_is_written_on_shutdown(tmp_path):
    bb = BlackBoxRecorder(pre_buffer_size=5, post_window_s=60.0, output_dir=str(tmp_path))
    bb.record(0.0, {"mavpackettype": "COMMAND_LONG"}, {}, [{"detector": "x", "confidence": 1, "reason": "r"}])
    path = bb.close(1.0)
    assert path and verify_snapshot(path)
    assert not list(tmp_path.glob("*_before_partial.json"))


def test_boot_zero_altitudes_do_not_count_as_agreement():
    ext, eng = pipeline()
    ext.update(0, {"mavpackettype": "VFR_HUD", "alt": 0.0})
    feed(ext, eng, 0.1, gpi(0, 0, boot_ms=500, alt_m=0.0))
    assert feed(ext, eng, 0.3, gpi(28.6, 77.2, boot_ms=700, alt_m=584.0)) == []
