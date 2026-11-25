# SN1FF3R

**Submission:** Security of drones IDS_TM-08314C14F81

A lightweight, real-time intrusion detection system for MAVLink drones. It runs on the
drone's companion computer (Raspberry Pi / Jetson class), watches the telemetry stream
from the flight controller, and raises alerts for:

- **GPS spoofing:** impossible position jumps, raw GPS disagreeing with the EKF estimate
- **GPS jamming:** fix lost, satellite count collapsing, position accuracy degrading
- **Link jamming / flooding:** the vehicle's heartbeat going silent, message-rate floods
- **Command injection:** commands from untrusted system IDs, replayed packets
- **Telemetry tampering:** altitude reports that contradict each other
- **Parameter tampering:** flight-controller settings changed from a trusted baseline

It only watches and alerts; it never blocks or changes what the drone does. Each alert
is shown to the pilot in the ground station (Mission Planner / QGroundControl) as a
short `SN1FF3R: ...` message, written to a tamper-evident log, and each incident is saved by
a "flight recorder" as a sealed file with the messages from before, during and after the
attack.

See `docs/TECHNICAL_OVERVIEW.md` for how it works and the test results.

---

## Quick start

Requires Python 3.8 or newer.

```bash
git clone https://github.com/<your-username>/sn1ff3r.git
cd sn1ff3r
python3 -m venv .venv
.venv/bin/pip install -e .
```

Try it against ArduPilot SITL. Terminal 1:

```bash
sim_vehicle.py -v ArduCopter --console --map --out=udp:127.0.0.1:14560 --out=udp:127.0.0.1:14551
```

Terminal 2 (from the project folder). This opens the GUI at http://127.0.0.1:8000:

```bash
.venv/bin/sn1ff3r gui --connect udpin:127.0.0.1:14560
```

`INSTALL.md` has the full walkthrough, deployment on a companion computer, and
troubleshooting.

---

## Commands

The installed command is `sn1ff3r`.

| Command | What it does |
|---|---|
| `sn1ff3r run --connect <link>` | Detection only, no GUI. This is what runs on the drone |
| `sn1ff3r gui --connect <link>` | Detection + browser GUI + attack lab, for SITL testing |
| `sn1ff3r dashboard` | The GUI read-only, over existing log files |
| `sn1ff3r attack <name>` | Fire a test attack (`gps_spoof`, `command_injection`, `dos`, `telemetry_forgery`) |
| `sn1ff3r params baseline` / `check` | Save / check the flight controller's parameter baseline |
| `sn1ff3r verify log <file>` / `snapshot <file>` | Prove a log or incident file hasn't been altered |

`<link>` is any MAVLink connection string: `udpin:127.0.0.1:14560` for SITL, or
`/dev/ttyAMA0 --baud 921600` for a flight controller on a serial port. Add
`--config configs/<profile>.yaml` for per-airframe thresholds. Alerts are sent to the
ground station by default (`--no-gcs-alerts` turns this off; `--gcs-alert-to
udpout:127.0.0.1:14550` also sends them straight to a ground station, which is needed in
SITL through MAVProxy). Run `sn1ff3r <command> --help` for all options.

---

## The GUI

| Section | What it shows |
|---|---|
| **Overview** | Overall status, each check's state, live message-rate and altitude charts, connection and drone info |
| **Alerts** | Every alert, searchable and filterable, with a per-entry tamper check and CSV export |
| **Flight recorder** | Each incident file: seal status, what was noticed, and a message-by-message timeline |
| **Attack lab** | One-click simulated attacks for SITL, and the parameter integrity check |

---

## Project layout

```
sn1ff3r/
├── README.md                     this file
├── INSTALL.md                    installation, SITL walkthrough, deployment, troubleshooting
├── docs/TECHNICAL_OVERVIEW.md    architecture, detection method, test results, performance
├── pyproject.toml                package definition (installs the `sn1ff3r` command)
├── configs/                      per-airframe thresholds: default, survey_multirotor, fixed_wing
├── deploy/sn1ff3r.service      systemd unit for running on the companion computer
├── tests/                        automated tests (pytest)
└── src/drone_ids/
    ├── cli.py                    the `sn1ff3r` command
    ├── monitor.py                main loop: receive → features → detectors → log → recorder
    ├── config.py                 thresholds and YAML loading
    ├── features/                 turns messages into numbers, with learned baselines
    ├── detectors/                GPS spoofing and jamming, DoS, command injection, telemetry, parameters
    ├── engine/                   runs the detectors, rate-limits repeated alerts
    ├── alerting/                 hash-chained alert log and flight recorder
    ├── params.py                 parameter download and baseline comparison
    ├── gui/                      browser GUI (standard library only, works offline)
    └── sim/                      simulated attacks for SITL testing
```

---

## Tests

```bash
.venv/bin/pip install -e ".[test]"
.venv/bin/pytest tests/
```

---

## License

MIT, see `LICENSE`. Dependencies: `pymavlink` (LGPL-3.0) and `PyYAML` (MIT).
