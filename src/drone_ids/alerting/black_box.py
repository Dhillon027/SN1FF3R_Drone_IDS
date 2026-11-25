"""
Forensic "black box" recorder.

Keeps the last N messages in a ring buffer (no disk I/O, no hashing). When a
detector fires, that buffer becomes the "before" part of an incident and
everything after it is captured until things have been quiet for
`post_window_s`. The incident is then written once, as a single SHA-256
sealed JSON file. Disk writes only happen when something is detected.
"""

import json
import hashlib
import os
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class BlackBoxRecorder:
    """Call `record()` once per message; starting and saving incidents is automatic."""

    def __init__(
        self,
        pre_buffer_size: int = 200,
        post_window_s: float = 5.0,
        output_dir: str = "forensic_snapshots",
    ):
        """
        pre_buffer_size: messages of context kept from before an incident.
        post_window_s: quiet time after the last alert before the incident
            is saved; a new alert pushes it back, so one attack stays one file.
        output_dir: where incident files go.
        """
        self.pre_buffer_size = pre_buffer_size
        self.post_window_s = post_window_s
        self.output_dir = Path(output_dir)

        self._pre_buffer: deque = deque(maxlen=pre_buffer_size)

        self._recording = False
        self._incident_id: Optional[str] = None
        self._incident_start: Optional[float] = None
        self._before_snapshot: List[Tuple] = []
        self._incident_log: List[Tuple] = []
        self._incident_alerts: List[Dict[str, Any]] = []
        self._last_alert_time: Optional[float] = None
        self._clock: Optional[float] = None

    @property
    def recording(self) -> bool:
        """True while an incident is being captured."""
        return self._recording

    def record(
        self,
        timestamp: float,
        msg: dict,
        features: dict,
        alerts: List[Dict[str, Any]],
    ) -> Optional[str]:
        """Returns the file path if an incident was saved on this call."""
        self._clock = timestamp
        entry = (timestamp, msg, features)

        if not self._recording:
            if alerts:
                self._activate(timestamp, entry, alerts)
            else:
                self._pre_buffer.append(entry)
            return None

        self._incident_log.append(entry)
        if alerts:
            self._incident_alerts.extend(alerts)
            self._last_alert_time = timestamp
        elif (timestamp - self._last_alert_time) >= self.post_window_s:
            return self._flush(timestamp)
        return None

    def poll(self, timestamp: float) -> Optional[str]:
        """Save a finished incident even when no messages are arriving."""
        if self._recording and (timestamp - self._last_alert_time) >= self.post_window_s:
            return self._flush(timestamp)
        return None

    def close(self, timestamp: float) -> Optional[str]:
        """On shutdown, save any incident that is still open."""
        if self._recording:
            return self._flush(timestamp)
        return None

    def status(self) -> Dict[str, Any]:
        """Summary for the GUI."""
        return {
            "recording": self._recording,
            "incident_id": self._incident_id,
            "incident_start": self._incident_start,
            "alerts": len(self._incident_alerts),
            "before_count": len(self._before_snapshot),
            "during_count": len(self._incident_log),
            "pre_buffer_fill": len(self._pre_buffer),
            "pre_buffer_size": self.pre_buffer_size,
            "closes_in_s": (max(0.0, self.post_window_s - (self._clock - self._last_alert_time))
                            if self._recording and self._clock is not None else None),
        }

    def _activate(self, timestamp: float, triggering_entry: Tuple, alerts: List[Dict[str, Any]]) -> None:
        self._recording = True
        self._incident_id = f"incident_{int(timestamp * 1000)}"
        self._incident_start = timestamp
        self._before_snapshot = list(self._pre_buffer)
        self._incident_log = [triggering_entry]
        self._incident_alerts = list(alerts)
        self._last_alert_time = timestamp
        # write the "before" part straight away in case we lose power mid-incident
        self._write_before_safety_snapshot()

    def _write_before_safety_snapshot(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.output_dir / f"{self._incident_id}_before_partial.json"
        payload = {
            "incident_id": self._incident_id,
            "triggered_at": self._incident_start,
            "trigger_alerts": self._incident_alerts,
            "before": [self._serialize(e) for e in self._before_snapshot],
            "before_count": len(self._before_snapshot),
            "note": "Partial safety snapshot written at incident start. "
                    "Superseded by the full incident file if the incident "
                    "closes normally -- this file is the fallback in case "
                    "it doesn't (e.g. a crash mid-incident).",
        }
        canonical = json.dumps(payload, sort_keys=True, default=str)
        payload["sha256"] = hashlib.sha256(canonical.encode()).hexdigest()
        with open(path, "w") as f:
            json.dump(payload, f, default=str)
            f.flush()
            os.fsync(f.fileno())

    def _flush(self, closed_at: float) -> str:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.output_dir / f"{self._incident_id}.json"

        payload = {
            "incident_id": self._incident_id,
            "triggered_at": self._incident_start,
            "closed_at": closed_at,
            "trigger_alerts": self._incident_alerts,
            "before": [self._serialize(e) for e in self._before_snapshot],
            "during_and_after": [self._serialize(e) for e in self._incident_log],
            "before_count": len(self._before_snapshot),
            "during_and_after_count": len(self._incident_log),
        }
        canonical = json.dumps(payload, sort_keys=True, default=str)
        payload["sha256"] = hashlib.sha256(canonical.encode()).hexdigest()

        with open(path, "w") as f:
            json.dump(payload, f, default=str)
            f.flush()
            os.fsync(f.fileno())

        # the full file replaces the partial one
        partial_path = self.output_dir / f"{self._incident_id}_before_partial.json"
        partial_path.unlink(missing_ok=True)

        self._reset()
        return str(path)

    def _reset(self) -> None:
        self._recording = False
        self._incident_id = None
        self._incident_start = None
        self._before_snapshot = []
        self._incident_log = []
        self._incident_alerts = []
        self._last_alert_time = None
        self._pre_buffer.clear()

    @staticmethod
    def _serialize(entry: Tuple) -> Dict[str, Any]:
        timestamp, msg, features = entry
        return {"time": timestamp, "msg": msg, "features": features}


def verify_snapshot(path: str) -> bool:
    """True if the incident file is unchanged since it was written."""
    with open(path, "r") as f:
        payload = json.load(f)
    stored_hash = payload.pop("sha256", None)
    if stored_hash is None:
        return False
    recomputed = hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode()
    ).hexdigest()
    return stored_hash == recomputed
