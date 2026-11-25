#!/usr/bin/env python3
"""
The `sn1ff3r` command.

    run        detection only, for the companion computer
    gui        detection + browser GUI + attack lab, for SITL testing
    dashboard  the GUI read-only, over existing log files
    attack     fire a test attack at SITL and a running IDS
    params     save or check a parameter-integrity baseline
    verify     check that an alert log or incident file hasn't been altered
"""

import argparse
import signal
import sys
import threading
import time

from .config import load_config
from .alerting.logger import SecureLogger
from .alerting.black_box import verify_snapshot


def _load_config(args):
    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError, RuntimeError) as e:
        sys.exit(f"Config error: {e}")
    if getattr(args, "min_confidence", None) is not None:
        config.min_confidence = args.min_confidence
    return config


def _monitor(args, config, **callbacks):
    from .monitor import IDSMonitor
    return IDSMonitor(
        args.connect, config=config, alert_log=args.alert_log,
        blackbox_dir=None if args.no_blackbox else args.blackbox_dir,
        baud=args.baud, gcs_alerts=not args.no_gcs_alerts, gcs_alert_to=args.gcs_alert_to, **callbacks)


# ---------------------------------------------------------------- run ----

def cmd_run(args: argparse.Namespace) -> None:
    config = _load_config(args)
    if args.config:
        print(f"Using config: {args.config}")

    def on_alert(a):
        rep = f" (+{a['repeats']} repeats)" if a.get("repeats") else ""
        print(f"[ALERT] {a['detector']} conf={a['confidence']:.2f} — {a['reason']}{rep}", flush=True)

    def on_status(s):
        print(f"[IDS] {s}", flush=True)

    mon = _monitor(args, config, on_alert=on_alert, on_status=on_status,
                   on_snapshot=lambda p: print(f"[BLACKBOX] Incident closed — forensic snapshot written to {p}", flush=True))
    # systemd stops us with SIGTERM: save any open incident, then exit
    signal.signal(signal.SIGTERM, lambda *_: mon.stop())
    try:
        mon.open()
    except ConnectionError as e:
        sys.exit(f"\nCannot start: {e}")
    try:
        mon.run()
    except KeyboardInterrupt:
        mon.stop()
        if mon.black_box is not None:
            mon._snap(mon.black_box.close(time.time()))
        print("\nStopped.")
    except Exception as e:
        sys.exit(f"IDS stopped: {e}")


# ---------------------------------------------------------------- gui ----

def cmd_gui(args: argparse.Namespace) -> None:
    from .gui.server import serve
    config = _load_config(args)

    def on_alert(a):
        print(f"[ALERT] {a['detector']} conf={a['confidence']:.2f} — {a['reason']}", flush=True)

    mon = _monitor(args, config, on_alert=on_alert, track_live_state=True,
                   on_status=lambda s: print(f"[IDS] {s}", flush=True))
    # open the link first so a busy port fails clearly
    try:
        mon.open()
    except ConnectionError as e:
        sys.exit(f"\nCannot start: {e}")

    def run_monitor():
        try:
            mon.run()
        except Exception as e:
            print(f"[IDS] stopped: {e}", flush=True)
    threading.Thread(target=run_monitor, daemon=True, name="ids-monitor").start()

    try:
        serve(monitor=mon, alert_log=args.alert_log,
              blackbox_dir=None if args.no_blackbox else args.blackbox_dir,
              host=args.host, port=args.port, sitl_port=args.sitl_port,
              allow_attacks=not args.no_attacks, param_baseline=args.param_baseline,
              config_path=args.config, open_browser=not args.no_browser)
    finally:
        mon.stop()


# ---------------------------------------------------------- dashboard ----

def cmd_dashboard(args: argparse.Namespace) -> None:
    from .gui.server import serve
    serve(monitor=None, alert_log=args.alert_log, blackbox_dir=args.blackbox_dir,
          host=args.host, port=args.port, open_browser=not args.no_browser)


# -------------------------------------------------------------- attack ---

def cmd_attack(args: argparse.Namespace) -> None:
    from .sim import attack_injectors as inj
    host, port = args.ids_host, args.ids_port
    try:
        if args.attack == "gps_spoof":
            m = inj.connect(port=args.sitl_port)
            inj.inject_gps_spoof(m, offset_deg=args.offset_deg, duration_s=args.duration or 15.0)
        elif args.attack == "command_injection":
            inj.inject_command_injection(host, port)
        elif args.attack == "dos":
            inj.flood_dos(host, port, seconds=args.duration or 3.0)
        elif args.attack == "telemetry_forgery":
            m = inj.connect(port=args.sitl_port)
            inj.forge_telemetry(host, port, m.target_system, lambda: inj.read_vehicle_position(m))
        elif args.attack == "dos_silence":
            print(inj.JAM_HELP)
    except (TimeoutError, RuntimeError) as e:
        sys.exit(str(e))
    except KeyboardInterrupt:
        print("\nInterrupted.")


# -------------------------------------------------------------- params ---

def cmd_params(args: argparse.Namespace) -> None:
    from .sim.attack_injectors import connect
    from . import params as P
    config = _load_config(args)
    try:
        m = connect(port=args.sitl_port) if args.connect is None else _plain_connect(args.connect)
        print("Downloading parameter table...")
        cur = P.fetch_params(m, progress=lambda n, t: print(f"\r  {n}/{t}", end="", flush=True))
        print()
    except TimeoutError as e:
        sys.exit(str(e))
    if args.action == "baseline":
        d = P.save_baseline(args.file, cur, config.param_integrity_exclude, sysid=m.target_system)
        print(f"Baseline of {d['count']} params saved to {args.file} (hash {d['hash'][:16]}…)")
        return
    r = P.compare_to_baseline(args.file, cur, config.param_integrity_exclude)
    if r["ok"]:
        print(f"OK — {r['checked']} params match the baseline")
        return
    print(f"MISMATCH — {len(r['changes'])} parameter(s) differ from the baseline:")
    for c in r["changes"]:
        print(f"  {c['name']:<18} {c['baseline']!s:>14} -> {c['current']!s}")
    sys.exit(1)


def _plain_connect(dev):
    from pymavlink import mavutil
    m = mavutil.mavlink_connection(dev)
    if m.wait_heartbeat(timeout=10) is None:
        raise TimeoutError(f"No heartbeat on {dev}")
    return m


# -------------------------------------------------------------- verify ---

def cmd_verify(args: argparse.Namespace) -> None:
    from pathlib import Path
    if not Path(args.path).is_file():
        sys.exit(f"No such file: {args.path}")
    try:
        if args.kind == "log":
            ok = SecureLogger(args.path).verify_chain()
        else:
            ok = verify_snapshot(args.path)
    except (OSError, ValueError) as e:
        sys.exit(f"Could not read {args.path}: {e}")
    print("VALID — no tampering detected" if ok else "INVALID — chain broken or file altered")
    sys.exit(0 if ok else 1)


# ------------------------------------------------------------- parser ----

def _link_args(p):
    p.add_argument("--connect", "-c", default="udpin:127.0.0.1:14550",
                   help="MAVLink connection string (udpin:host:port, /dev/ttyUSB0, tcp:host:port)")
    p.add_argument("--baud", type=int, default=115200, help="Serial baud rate")
    p.add_argument("--config", default=None, help="Path to a YAML config file (see configs/)")
    p.add_argument("--alert-log", default="ids_alerts.jsonl")
    p.add_argument("--min-confidence", type=float, default=None)
    p.add_argument("--no-blackbox", action="store_true")
    p.add_argument("--blackbox-dir", default="forensic_snapshots")
    p.add_argument("--no-gcs-alerts", action="store_true", help="Don't send alerts to the ground station as STATUSTEXT")
    p.add_argument("--gcs-alert-to", default=None, help="Also send alerts here, e.g. udpout:127.0.0.1:14550 (SITL with MAVProxy)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sn1ff3r", description="MAVLink drone intrusion detection system")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="Run the live detection loop (headless)")
    _link_args(p_run)
    p_run.set_defaults(func=cmd_run)

    p_gui = sub.add_parser("gui", help="Live detection + operator GUI + SITL Attack Lab")
    _link_args(p_gui)
    p_gui.add_argument("--host", default="127.0.0.1", help="GUI bind address (0.0.0.0 = reachable on the LAN)")
    p_gui.add_argument("--port", type=int, default=8000, help="GUI port")
    p_gui.add_argument("--sitl-port", type=int, default=14551, help="Second MAVProxy output used for GPS spoof / params")
    p_gui.add_argument("--param-baseline", default="param_baseline.json")
    p_gui.add_argument("--no-attacks", action="store_true", help="Hide the Attack Lab (monitoring only)")
    p_gui.add_argument("--no-browser", action="store_true", help="Don't open a browser tab")
    p_gui.set_defaults(func=cmd_gui)

    p_dash = sub.add_parser("dashboard", help="Open the GUI read-only over existing log files")
    p_dash.add_argument("--alert-log", default="ids_alerts.jsonl")
    p_dash.add_argument("--blackbox-dir", default="forensic_snapshots")
    p_dash.add_argument("--host", default="127.0.0.1")
    p_dash.add_argument("--port", type=int, default=8000)
    p_dash.add_argument("--no-browser", action="store_true")
    p_dash.set_defaults(func=cmd_dashboard)

    p_atk = sub.add_parser("attack", help="Fire a test attack against a running SITL + IDS")
    p_atk.add_argument("attack", choices=["gps_spoof", "command_injection", "dos", "telemetry_forgery", "dos_silence"])
    p_atk.add_argument("--sitl-port", type=int, default=14551)
    p_atk.add_argument("--ids-host", default="127.0.0.1")
    p_atk.add_argument("--ids-port", type=int, default=14550)
    p_atk.add_argument("--duration", type=float, default=None, help="Seconds (gps_spoof: 15, dos: 3)")
    p_atk.add_argument("--offset-deg", type=float, default=0.001, help="gps_spoof offset in degrees (~111 m per 0.001)")
    p_atk.set_defaults(func=cmd_attack)

    p_par = sub.add_parser("params", help="Capture or check a parameter-table integrity baseline")
    p_par.add_argument("action", choices=["baseline", "check"])
    p_par.add_argument("--file", default="param_baseline.json")
    p_par.add_argument("--sitl-port", type=int, default=14551)
    p_par.add_argument("--connect", default=None, help="Use this link instead of udpin:127.0.0.1:<sitl-port>")
    p_par.add_argument("--config", default=None)
    p_par.set_defaults(func=cmd_params)

    p_ver = sub.add_parser("verify", help="Check an alert log or forensic snapshot's tamper-evident chain")
    p_ver.add_argument("kind", choices=["log", "snapshot"])
    p_ver.add_argument("path")
    p_ver.set_defaults(func=cmd_verify)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
