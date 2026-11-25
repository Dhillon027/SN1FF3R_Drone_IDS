"""
The browser GUI, served with the Python standard library only so it works offline.

Live mode (`sn1ff3r gui`) runs the detector in-process and offers the
attack lab. Viewer mode (`sn1ff3r dashboard`) only reads the alert log and
incident files. Either way, what's shown is what's on disk.
"""

import json
import re
import threading
import time
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

from ..alerting.logger import verify_entry
from ..alerting.black_box import verify_snapshot

STATIC = Path(__file__).parent / "static"
MAX_ALERTS_KEPT = 5000
MAX_TIMELINE = 4000
SAFE_ID = re.compile(r"^[A-Za-z0-9_\-]+$")


# ------------------------------------------------------------- alerts ----

class AlertStore:
    """Reads only new lines of the alert log each poll and checks the hash chain as it goes."""

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self._reset()

    def _reset(self):
        self.offset = 0
        self.prev = "0" * 64
        self.chain_ok = True
        self.broken_at: Optional[int] = None
        self.alerts: List[Dict[str, Any]] = []
        self.total = 0
        self.generation = getattr(self, "generation", 0) + 1
        self.first_index = 0  # index of alerts[0] in the full log

    def refresh(self):
        with self.lock:
            if not self.path.exists():
                if self.offset:
                    self._reset()
                return
            size = self.path.stat().st_size
            if size < self.offset:  # truncated / rotated
                self._reset()
            if size == self.offset:
                return
            with open(self.path, "rb") as f:
                f.seek(self.offset)
                chunk = f.read()
            end = chunk.rfind(b"\n")
            if end < 0:
                return  # partial line still being written
            self.offset += end + 1
            for raw in chunk[:end].splitlines():
                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    entry = {"detector": "?", "reason": "unreadable log line", "confidence": 0}
                if self.chain_ok:
                    h = verify_entry(line, self.prev)
                    if h is None:
                        self.chain_ok = False
                        self.broken_at = self.total
                    else:
                        self.prev = h
                entry["_index"] = self.total
                entry["_chain_ok"] = self.chain_ok
                self.total += 1
                self.alerts.append(entry)
            if len(self.alerts) > MAX_ALERTS_KEPT:
                drop = len(self.alerts) - MAX_ALERTS_KEPT
                del self.alerts[:drop]
                self.first_index += drop

    def since(self, idx: int, gen: int):
        self.refresh()
        with self.lock:
            if gen != self.generation:
                idx = 0
            start = max(0, idx - self.first_index)
            return {
                "generation": self.generation,
                "total": self.total,
                "chain_ok": self.chain_ok,
                "broken_at": self.broken_at,
                "alerts": [_public_alert(a) for a in self.alerts[start:]],
            }

    def summary(self):
        self.refresh()
        with self.lock:
            counts: Dict[str, int] = {}
            for a in self.alerts:
                d = a.get("detector", "?")
                counts[d] = counts.get(d, 0) + 1
            last = _public_alert(self.alerts[-1]) if self.alerts else None
            return {"total": self.total, "chain_ok": self.chain_ok, "broken_at": self.broken_at,
                    "by_detector": counts, "last": last,
                    "recent": [_public_alert(a) for a in self.alerts[-6:]][::-1]}


def _public_alert(a):
    return {
        "index": a.get("_index"),
        "time": a.get("time"),
        "logged_at": a.get("logged_at"),
        "detector": a.get("detector"),
        "confidence": a.get("confidence"),
        "reason": a.get("reason"),
        "msg_type": a.get("msg_type"),
        "src_system": a.get("src_system"),
        "src_component": a.get("src_component"),
        "repeats": a.get("repeats") or 0,
        "hash": a.get("hash"),
        "prev_hash": a.get("prev_hash"),
        "chain_ok": a.get("_chain_ok", True),
    }


# ----------------------------------------------------------- black box ---

class SnapshotStore:
    """Lists and opens incident files, caching parsed ones."""

    def __init__(self, directory: Optional[Path]):
        self.dir = directory
        self._cache: Dict[str, Any] = {}
        self.lock = threading.Lock()

    def _load(self, path: Path):
        st = path.stat()
        key = str(path)
        c = self._cache.get(key)
        if c and c[0] == (st.st_mtime, st.st_size):
            return c[1], c[2]
        try:
            with open(path) as f:
                data = json.load(f)
            ok = verify_snapshot(str(path))
        except (OSError, json.JSONDecodeError):
            data, ok = None, False
        self._cache[key] = ((st.st_mtime, st.st_size), data, ok)
        return data, ok

    def list(self):
        for _ in range(3):
            try:
                return self._list()
            except FileNotFoundError:
                continue
        return []

    def _list(self):
        if self.dir is None or not self.dir.exists():
            return []
        out = []
        with self.lock:
            for p in sorted(self.dir.glob("incident_*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
                data, ok = self._load(p)
                if data is None:
                    out.append({"id": p.stem, "file": p.name, "verified": False, "unreadable": True})
                    continue
                alerts = data.get("trigger_alerts") or []
                detectors: Dict[str, int] = {}
                for a in alerts:
                    detectors[a.get("detector", "?")] = detectors.get(a.get("detector", "?"), 0) + 1
                start, end = data.get("triggered_at"), data.get("closed_at")
                out.append({
                    "id": p.stem,
                    "file": p.name,
                    "partial": p.stem.endswith("_before_partial"),
                    "triggered_at": start,
                    "closed_at": end,
                    "duration_s": (end - start) if (start and end) else None,
                    "alert_count": len(alerts),
                    "detectors": detectors,
                    "max_confidence": max((a.get("confidence", 0) for a in alerts), default=0),
                    "before_count": data.get("before_count"),
                    "during_count": data.get("during_and_after_count"),
                    "size_bytes": p.stat().st_size,
                    "sha256": data.get("sha256"),
                    "verified": ok,
                })
        return out

    def path_for(self, sid: str) -> Optional[Path]:
        if self.dir is None or not SAFE_ID.match(sid):
            return None
        p = (self.dir / f"{sid}.json").resolve()
        if p.parent != self.dir.resolve() or not p.exists():
            return None
        return p

    def detail(self, sid: str):
        p = self.path_for(sid)
        if p is None:
            return None
        try:
            with self.lock:
                data, ok = self._load(p)
        except FileNotFoundError:
            return None
        if data is None:
            return {"id": sid, "unreadable": True}
        t0 = data.get("triggered_at") or 0
        timeline = []
        type_counts: Dict[str, Dict[str, int]] = {"before": {}, "during": {}}
        for phase, key in (("before", "before"), ("during", "during_and_after")):
            for e in data.get(key) or []:
                m = e.get("msg") or {}
                mt = m.get("mavpackettype", "?")
                type_counts[phase][mt] = type_counts[phase].get(mt, 0) + 1
                timeline.append({"phase": phase, "t": e.get("time"), "rel": (e.get("time") or 0) - t0,
                                 "type": mt, "src": (m.get("_header") or {}).get("srcSystem"),
                                 "msg": {k: v for k, v in m.items() if k not in ("mavpackettype",)},
                                 "features": e.get("features") or {}})
        alert_times = {}
        for a in data.get("trigger_alerts") or []:
            alert_times.setdefault(a.get("time"), []).append(a.get("detector"))
        for row in timeline:
            if row["t"] in alert_times and row["phase"] == "during":
                row["alerts"] = alert_times[row["t"]]
        truncated = len(timeline) > MAX_TIMELINE
        if truncated:
            before = [r for r in timeline if r["phase"] == "before"][-MAX_TIMELINE // 4:]
            during = [r for r in timeline if r["phase"] == "during"][:MAX_TIMELINE - len(before)]
            timeline = before + during
        return {
            "id": sid,
            "verified": ok,
            "partial": sid.endswith("_before_partial"),
            "note": data.get("note"),
            "triggered_at": data.get("triggered_at"),
            "closed_at": data.get("closed_at"),
            "sha256": data.get("sha256"),
            "trigger_alerts": data.get("trigger_alerts") or [],
            "before_count": data.get("before_count"),
            "during_count": data.get("during_and_after_count"),
            "type_counts": type_counts,
            "timeline": timeline,
            "timeline_truncated": truncated,
        }


# ------------------------------------------------------------- attacks ---

class AttackLab:
    """Runs test attacks in the background and keeps a log of what was run."""

    def __init__(self, monitor, sitl_port: int):
        from ..sim import attack_injectors as inj
        self.inj = inj
        self.monitor = monitor
        self.sitl_port = sitl_port
        self.ids_target = inj.parse_udp_target(monitor.connect) if monitor else None
        self.log: List[Dict[str, Any]] = []
        self.running: Dict[str, float] = {}
        self.lock = threading.Lock()
        self.sitl_lock = threading.Lock()
        self._sitl = None
        self.param_progress = None
        self.last_param_check = None
        self.stop_gps = threading.Event()

    def _log(self, text: str, level: str = "info"):
        with self.lock:
            self.log.append({"time": time.time(), "text": text, "level": level})
            del self.log[:-200]

    def sitl(self):
        if self._sitl is None:
            self._sitl = self.inj.connect(self.sitl_port, timeout=8.0, log=self._log)
        return self._sitl

    def capabilities(self):
        return {
            "live": self.monitor is not None,
            "inject": self.ids_target is not None,
            "ids_target": f"{self.ids_target[0]}:{self.ids_target[1]}" if self.ids_target else None,
            "sitl_port": self.sitl_port,
        }

    def state(self):
        with self.lock:
            return {"log": list(self.log[-60:])[::-1], "running": dict(self.running),
                    "param_progress": self.param_progress, "last_param_check": self.last_param_check,
                    **self.capabilities()}

    def launch(self, kind: str, opts: Dict[str, Any]):
        if self.monitor is None:
            raise ValueError("Attack Lab needs live mode (sn1ff3r gui), not the log viewer")
        with self.lock:
            if kind in self.running:
                raise ValueError(f"{kind} is already running")
            self.running[kind] = time.time()
        threading.Thread(target=self._run, args=(kind, opts), daemon=True).start()

    def _run(self, kind, opts):
        inj = self.inj
        try:
            if kind == "gps_spoof":
                self.stop_gps.clear()
                with self.sitl_lock:
                    inj.inject_gps_spoof(self.sitl(), offset_deg=_num(opts, "offset_deg", 0.001, 0.00005, 0.05),
                                         duration_s=_num(opts, "duration_s", 15, 2, 120), log=self._log,
                                         stop=self.stop_gps.is_set)
            elif kind == "jam":
                secs = _num(opts, "duration_s", 8, 1, 120)
                self.monitor.jam(secs)
                self._log(f"[jam] receiver dropping all packets for {secs:g}s")
                time.sleep(secs)
                self._log(f"[jam] link restored ({self.monitor.dropped_by_jam} packets dropped so far)")
            elif kind in ("command_injection", "dos", "telemetry_forgery"):
                if self.ids_target is None:
                    raise RuntimeError("IDS is not on a UDP listener (--connect udpin:...), can't inject")
                host, port = self.ids_target
                if kind == "command_injection":
                    inj.inject_command_injection(host, port, src_sysid=int(_num(opts, "src_sysid", 99, 1, 254)),
                                                 target_sysid=self.monitor.extractor.vehicle_sysid or 1,
                                                 log=self._log)
                elif kind == "dos":
                    inj.flood_dos(host, port, seconds=_num(opts, "duration_s", 3, 1, 30),
                                  rate_hz=_num(opts, "rate_hz", 1500, 100, 5000), log=self._log)
                else:
                    if "lat" not in self.monitor.vehicle or not self.monitor.extractor.vehicle_sysid:
                        raise RuntimeError("No vehicle position yet -- wait for GLOBAL_POSITION_INT")

                    def latest():
                        v = self.monitor.snapshot()["vehicle"]
                        return v["lat"], v["lon"], v["alt_msl"], v["alt_rel"], v.get("time_boot_ms") or 0
                    inj.forge_telemetry(host, port, self.monitor.extractor.vehicle_sysid, latest,
                                        offset_m=_num(opts, "offset_m", 150, 20, 5000), log=self._log)
            elif kind in ("param_baseline", "param_check"):
                self._params(kind, opts)
            else:
                raise ValueError(f"unknown attack {kind}")
        except Exception as e:
            self._log(f"[{kind}] failed: {e}", "error")
            if not isinstance(e, (TimeoutError, RuntimeError, ValueError)):
                traceback.print_exc()
        finally:
            with self.lock:
                self.running.pop(kind, None)

    def _params(self, kind, opts):
        from .. import params as P
        path = opts.get("_baseline_path")
        cfg = self.monitor.config
        with self.sitl_lock:
            m = self.sitl()
            self._log("[params] downloading parameter table...")

            def prog(n, total):
                self.param_progress = {"received": n, "total": total}
            try:
                current = P.fetch_params(m, progress=prog)
            finally:
                self.param_progress = None
        if kind == "param_baseline":
            d = P.save_baseline(path, current, cfg.param_integrity_exclude, sysid=m.target_system)
            self._log(f"[params] baseline of {d['count']} params saved to {path}")
            self.last_param_check = None
        else:
            if not Path(path).exists():
                raise RuntimeError("No baseline yet -- capture one first")
            r = P.compare_to_baseline(path, current, cfg.param_integrity_exclude)
            r["time"] = time.time()
            self.last_param_check = r
            if r["ok"]:
                self._log(f"[params] integrity OK -- {r['checked']} params match the baseline")
            else:
                names = ", ".join(c["name"] for c in r["changes"][:6])
                self._log(f"[params] INTEGRITY MISMATCH: {len(r['changes'])} changed ({names})", "error")
                self.monitor.alert_logger.log({
                    "time": time.time(), "detector": "check_integrity", "confidence": 1.0,
                    "reason": f"Parameter table differs from baseline: {len(r['changes'])} changed ({names})",
                    "msg_type": "PARAM_VALUE", "repeats": 0,
                })


def _num(opts, key, default, lo, hi):
    try:
        v = float(opts.get(key, default))
    except (TypeError, ValueError):
        v = default
    return min(hi, max(lo, v))


# ---------------------------------------------------------------- HTTP ---

def make_handler(ctx):
    class Handler(BaseHTTPRequestHandler):
        server_version = "sn1ff3r"

        def log_message(self, *a):
            pass

        def _json(self, obj, code=200):
            body = json.dumps(obj, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _file(self, path: Path, ctype: str, download: Optional[str] = None):
            body = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            if download:
                self.send_header("Content-Disposition", f'attachment; filename="{download}"')
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            try:
                if u.path in ("/", "/index.html"):
                    return self._file(STATIC / "index.html", "text/html; charset=utf-8")
                if u.path == "/api/state":
                    return self._json({
                        "mode": "live" if ctx["monitor"] else "viewer",
                        "monitor": ctx["monitor"].snapshot() if ctx["monitor"] else None,
                        "alerts": ctx["alerts"].summary(),
                        "attacks": ctx["lab"].state(),
                        "files": {"alert_log": str(ctx["alerts"].path),
                                  "blackbox_dir": str(ctx["snaps"].dir) if ctx["snaps"].dir else None,
                                  "config": ctx.get("config_path")},
                        "snapshot_count": len(ctx["snaps"].list()),
                        "server_time": time.time(),
                    })
                if u.path == "/api/alerts":
                    return self._json(ctx["alerts"].since(int(q.get("since", ["0"])[0]),
                                                          int(q.get("gen", ["0"])[0])))
                if u.path == "/api/blackbox":
                    mon = ctx["monitor"]
                    return self._json({"snapshots": ctx["snaps"].list(),
                                       "live": mon.black_box.status() if mon and mon.black_box else None})
                m = re.match(r"^/api/blackbox/([A-Za-z0-9_\-]+)(/raw)?$", u.path)
                if m:
                    if m.group(2):
                        p = ctx["snaps"].path_for(m.group(1))
                        if p is None:
                            return self._json({"error": "not found"}, 404)
                        return self._file(p, "application/json", download=p.name)
                    d = ctx["snaps"].detail(m.group(1))
                    return self._json(d if d else {"error": "not found"}, 200 if d else 404)
                self._json({"error": "not found"}, 404)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_POST(self):
            # the custom header can't be sent cross-site, so other web pages can't trigger this
            if self.headers.get("X-SN1FF3R") != "1" or \
                    not (self.headers.get("Content-Type") or "").startswith("application/json"):
                return self._json({"error": "forbidden"}, HTTPStatus.FORBIDDEN)
            try:
                n = min(int(self.headers.get("Content-Length") or 0), 10000)
                body = json.loads(self.rfile.read(n) or b"{}")
            except (ValueError, json.JSONDecodeError):
                return self._json({"error": "bad request"}, 400)
            u = urlparse(self.path)
            lab = ctx["lab"]
            try:
                if u.path == "/api/attack":
                    if ctx["monitor"] is None:
                        raise ValueError("Attack Lab needs live mode (sn1ff3r gui), not the log viewer")
                    if not ctx["allow_attacks"]:
                        raise ValueError("Attack Lab is disabled (--no-attacks)")
                    kind = str(body.get("kind"))
                    opts = body.get("options") or {}
                    if kind in ("param_baseline", "param_check"):
                        opts["_baseline_path"] = ctx["param_baseline"]
                    lab.launch(kind, opts)
                    return self._json({"ok": True})
                if u.path == "/api/attack/stop":
                    lab.stop_gps.set()
                    if ctx["monitor"]:
                        ctx["monitor"].jam_until = 0.0
                    return self._json({"ok": True})
            except ValueError as e:
                return self._json({"error": str(e)}, 400)
            self._json({"error": "not found"}, 404)

    return Handler


def serve(monitor=None, alert_log="ids_alerts.jsonl", blackbox_dir="forensic_snapshots",
          host="127.0.0.1", port=8000, sitl_port=14551, allow_attacks=True,
          param_baseline="param_baseline.json", config_path=None, open_browser=False):
    ctx = {
        "monitor": monitor,
        "alerts": AlertStore(Path(alert_log)),
        "snaps": SnapshotStore(Path(blackbox_dir) if blackbox_dir else None),
        "lab": AttackLab(monitor, sitl_port),
        "allow_attacks": allow_attacks and monitor is not None,
        "param_baseline": param_baseline,
        "config_path": config_path,
    }
    httpd = ThreadingHTTPServer((host, port), make_handler(ctx))
    httpd.daemon_threads = True
    url = f"http://{'127.0.0.1' if host in ('0.0.0.0', '') else host}:{port}"
    print(f"SN1FF3R GUI at {url}  ({'live' if monitor else 'viewer'} mode)")
    print("Press Ctrl+C to stop.")
    if open_browser:
        import webbrowser
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()
