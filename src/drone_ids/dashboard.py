#!/usr/bin/env python3
"""
Read-only viewer: the GUI without a MAVLink link, reading the alert log and
incident files written by `sn1ff3r run`.
"""

import argparse

from .gui.server import serve


def main(argv=None):
    parser = argparse.ArgumentParser(description="SN1FF3R log viewer (GUI in viewer mode)")
    parser.add_argument("--log", "--alert-log", dest="alert_log", default="ids_alerts.jsonl")
    parser.add_argument("--blackbox-dir", default="forensic_snapshots")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    serve(monitor=None, alert_log=args.alert_log, blackbox_dir=args.blackbox_dir,
          host=args.host, port=args.port)


if __name__ == "__main__":
    main()
