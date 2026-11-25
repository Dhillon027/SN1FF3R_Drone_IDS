"""
Smoke tests: imports, config loading, and each detector's basic behaviour.
"""

import time

from drone_ids.config import load_config, DetectorConfig
from drone_ids.features.feature_extractor import FeatureExtractor
from drone_ids.engine.ids_engine import IDSEngine
from drone_ids.detectors.gps_spoof_detector import check_gps_spoof
from drone_ids.detectors.dos_detector import check_dos
from drone_ids.detectors.command_injection_detector import check_command_injection
from drone_ids.detectors.telemetry_manipulation_detector import check_telemetry_consistency
from drone_ids.alerting.logger import SecureLogger
from drone_ids.alerting.black_box import BlackBoxRecorder, verify_snapshot


def make_engine(config=None):
    detectors = [check_gps_spoof, check_dos, check_command_injection, check_telemetry_consistency]
    return FeatureExtractor(), IDSEngine(detectors, config=config)


def test_default_config_loads():
    c = load_config(None)
    assert isinstance(c, DetectorConfig)
    assert c.max_plausible_speed_mps == 40.0


def test_vehicle_profile_overrides_thresholds():
    c = load_config("configs/survey_multirotor.yaml")
    assert c.max_plausible_speed_mps == 15.0
    default = load_config(None)
    assert c.max_plausible_speed_mps != default.max_plausible_speed_mps


def test_no_false_positive_on_normal_traffic():
    ext, engine = make_engine()
    t = time.time()
    for i in range(20):
        msg = {"mavpackettype": "HEARTBEAT"}
        f = ext.update(t, msg)
        assert engine.evaluate(t, msg, f) == []
        t += 1.0


def test_gps_spoof_hard_cap_fires():
    ext, engine = make_engine()
    t = time.time()
    msg1 = {"mavpackettype": "GLOBAL_POSITION_INT", "lat": int(28.6 * 1e7), "lon": int(77.2 * 1e7),
            "relative_alt": 10000, "alt": 20000}
    f1 = ext.update(t, msg1)
    engine.evaluate(t, msg1, f1)
    t += 1.0

    # ~11 km jump in one second -- physically impossible
    msg2 = {"mavpackettype": "GLOBAL_POSITION_INT", "lat": int(28.7 * 1e7), "lon": int(77.2 * 1e7),
            "relative_alt": 10000, "alt": 20000}
    f2 = ext.update(t, msg2)
    alerts = engine.evaluate(t, msg2, f2)
    assert any(a["detector"] == "check_gps_spoof" for a in alerts)


def test_command_injection_unauthorized_source():
    ext, engine = make_engine()
    t = time.time()
    msg = {"mavpackettype": "COMMAND_LONG", "_header": {"srcSystem": 99, "seq": 1}}
    f = ext.update(t, msg)
    alerts = engine.evaluate(t, msg, f)
    assert any(a["detector"] == "check_command_injection" for a in alerts)


def test_config_changes_detector_sensitivity():
    """The same jump should NOT fire under the default profile but SHOULD
    fire under the tighter survey_multirotor profile."""
    for config_path, should_fire in [(None, False), ("configs/survey_multirotor.yaml", True)]:
        config = load_config(config_path)
        ext, engine = make_engine(config=config)
        t = time.time()
        msg1 = {"mavpackettype": "GLOBAL_POSITION_INT", "lat": int(28.6000 * 1e7), "lon": int(77.2 * 1e7),
                "relative_alt": 10000, "alt": 20000}
        f1 = ext.update(t, msg1)
        engine.evaluate(t, msg1, f1)
        t += 1.0
        # ~22 m/s jump: under default 40 m/s cap, over survey's 15 m/s cap
        msg2 = {"mavpackettype": "GLOBAL_POSITION_INT", "lat": int(28.6002 * 1e7), "lon": int(77.2 * 1e7),
                "relative_alt": 10000, "alt": 20000}
        f2 = ext.update(t, msg2)
        alerts = engine.evaluate(t, msg2, f2)
        fired = any(a["detector"] == "check_gps_spoof" for a in alerts)
        assert fired == should_fire, f"config={config_path}: expected fired={should_fire}, got {fired}"


def test_alert_log_chain_verifies(tmp_path):
    path = tmp_path / "alerts.jsonl"
    logger = SecureLogger(str(path))
    logger.log({"time": 1.0, "detector": "test", "confidence": 0.9, "reason": "unit test"})
    logger.log({"time": 2.0, "detector": "test", "confidence": 0.9, "reason": "unit test 2"})
    assert logger.verify_chain() is True


def test_black_box_incident_capture_and_verify(tmp_path):
    bb = BlackBoxRecorder(pre_buffer_size=5, post_window_s=1.0, output_dir=str(tmp_path))
    t = time.time()
    for i in range(5):
        bb.record(t, {"mavpackettype": "HEARTBEAT"}, {}, [])
        t += 0.2
    path = bb.record(t, {"mavpackettype": "COMMAND_LONG"}, {},
                      [{"detector": "check_command_injection", "confidence": 0.85, "reason": "test"}])
    t += 2.0
    final_path = bb.record(t, {"mavpackettype": "HEARTBEAT"}, {}, [])
    assert final_path is not None
    assert verify_snapshot(final_path) is True
