"""
Runs every detector on each message.

`evaluate()` returns the alerts to log. If the same detector keeps firing
within `alert_cooldown_s`, the extra hits are counted in the next alert's
`repeats` instead of flooding the log. `last_detections` keeps every hit
unfiltered for the black box.
"""

import logging
from typing import Callable, List, Tuple, Dict, Any, Optional

from ..config import DetectorConfig

Detector = Callable[[dict, dict, DetectorConfig], Tuple[bool, float, str]]

log = logging.getLogger(__name__)


class IDSEngine:
    def __init__(
        self,
        detectors: List[Detector],
        config: Optional[DetectorConfig] = None,
        min_confidence: Optional[float] = None,
    ):
        self.detectors = detectors
        self.config = config or DetectorConfig()
        self.min_confidence = min_confidence if min_confidence is not None else self.config.min_confidence
        self.last_detections: List[Dict[str, Any]] = []
        self._last_emit: Dict[str, float] = {}
        self._suppressed: Dict[str, int] = {}
        self.detector_errors = 0

    def evaluate(self, timestamp: float, msg: dict, features: dict) -> List[Dict[str, Any]]:
        detections = []
        for detect_fn in self.detectors:
            try:
                is_attack, confidence, reason = detect_fn(msg, features, self.config)
            except Exception:  # a broken detector shouldn't stop the others
                self.detector_errors += 1
                log.exception("detector %s raised on %s", detect_fn.__name__, msg.get("mavpackettype"))
                continue
            if is_attack and confidence >= self.min_confidence:
                hdr = msg.get("_header") or {}
                detections.append({
                    "time": timestamp,
                    "detector": detect_fn.__name__,
                    "confidence": confidence,
                    "reason": reason,
                    "msg_type": msg.get("mavpackettype"),
                    "src_system": hdr.get("srcSystem"),
                    "src_component": hdr.get("srcComponent"),
                })
        self.last_detections = detections

        cooldown = self.config.alert_cooldown_s
        alerts = []
        for d in detections:
            name = d["detector"]
            last = self._last_emit.get(name)
            if cooldown > 0 and last is not None and timestamp - last < cooldown:
                self._suppressed[name] = self._suppressed.get(name, 0) + 1
                continue
            d = dict(d)
            d["repeats"] = self._suppressed.pop(name, 0)
            self._last_emit[name] = timestamp
            alerts.append(d)
        return alerts
