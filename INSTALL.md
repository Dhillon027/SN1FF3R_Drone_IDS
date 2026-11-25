# Installing and running SN1FF3R

## 1. Install

Requires Python 3.8 or newer. From inside the project folder:

```bash
cd sn1ff3r
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/sn1ff3r --help
```

This installs the `sn1ff3r` command into `.venv`. Its only dependencies are
`pymavlink` and `pyyaml`. The commands below assume you're in the project folder; if
you activate the environment (`source .venv/bin/activate`), you can drop the `.venv/bin/`
prefix.

## 2. Simulating with ArduPilot SITL

**Terminal 1: the simulator.** Start it with two extra MAVProxy outputs: **14560** for
the IDS (its own port, so it never competes with MAVProxy, Mission Planner or
QGroundControl for 14550) and **14551** for the attack lab's GPS and parameter tools.

```bash
sim_vehicle.py -v ArduCopter --console --map --out=udp:127.0.0.1:14560 --out=udp:127.0.0.1:14551
```

If SITL is already running, type these in its MAVProxy console instead:
`output add 127.0.0.1:14560` and `output add 127.0.0.1:14551`.

**Terminal 2: the IDS with its GUI.** This opens http://127.0.0.1:8000.

```bash
cd sn1ff3r
.venv/bin/sn1ff3r gui --connect udpin:127.0.0.1:14560 --gcs-alert-to udpout:127.0.0.1:14550
```

`--gcs-alert-to` makes each alert pop up as an `SN1FF3R: ...` message in Mission Planner or
QGroundControl listening on 14550. It's only needed in SITL, where MAVProxy doesn't pass
the IDS's messages back to the ground station; on the drone, ArduPilot does that itself.

**Take off** from the MAVProxy console (Terminal 1):

```
mode guided
arm throttle
takeoff 20
```

Wait about 30 seconds so the IDS can learn the normal message rate, then open the
**Attack lab** in the GUI. Each test says which check should notice it:

| Test | How it's produced | Should be noticed by |
|---|---|---|
| Fake the GPS position | Shifts SITL's simulated GPS (`SIM_GPS1_GLTCH_X/Y`) for N seconds, then restores it | GPS Spoofing |
| Block the radio link | The IDS ignores all incoming packets for N seconds | Link Jamming / Flooding |
| Flood the link | An untrusted system floods the IDS's port with heartbeats | Link Jamming / Flooding |
| Send a rogue command | `COMMAND_LONG` from untrusted system ID 99 | Command Injection |
| Fake the altitude | Position reports impersonating the vehicle, altitude +150 m | Telemetry Tampering |
| Check the drone's settings | Save a trusted copy, change a setting (`param set FENCE_ENABLE 1`), check | Settings Integrity |
| GPS jamming | In the MAVProxy console: `param set SIM_GPS1_JAM 1`, then `param set SIM_GPS1_JAM 0` to stop (ArduPilot's own jamming simulation) | GPS Jamming |

Only the GPS test touches SITL, and only its simulator-only `SIM_*` parameters. The
other tests send packets to the IDS's port and never reach the autopilot.

The same tests from the command line, against a running `sn1ff3r run` or `gui`:

```bash
.venv/bin/sn1ff3r attack gps_spoof
.venv/bin/sn1ff3r attack command_injection --ids-port 14560
.venv/bin/sn1ff3r attack dos --ids-port 14560
.venv/bin/sn1ff3r attack telemetry_forgery --ids-port 14560
.venv/bin/sn1ff3r params baseline
.venv/bin/sn1ff3r params check
```

**Output files** (written to the folder you start the IDS from):

- `ids_alerts.jsonl`: the alert log
- `forensic_snapshots/`: one sealed file per incident

To check nothing has been altered:

```bash
.venv/bin/sn1ff3r verify log ids_alerts.jsonl
.venv/bin/sn1ff3r verify snapshot forensic_snapshots/<incident file>.json
```

To start fresh, stop the IDS and move or delete those two. Don't edit single lines of
the alert log: it's hash-chained, so that shows up as tampering.

## 3. Running on the drone's companion computer

On the vehicle, use `sn1ff3r run`, not `gui`. It skips all GUI work.

**Offline install.** Companion computers are usually offline in the field. Build the
package on a machine with internet access:

```bash
.venv/bin/pip install build
.venv/bin/python -m build
.venv/bin/pip download pymavlink pyyaml -d dist/
```

This creates `dist/sn1ff3r-1.1.0-py3-none-any.whl` plus the dependency
wheels. Copy `dist/` and `configs/` to the companion computer, into a folder without
spaces such as `/home/pi/sn1ff3r`, then install there:

```bash
cd /home/pi/sn1ff3r
python3 -m venv .venv
.venv/bin/pip install --no-index --find-links=dist/ sn1ff3r
```

**Connect to the flight controller.** Use its serial port, e.g. a Raspberry Pi wired to
TELEM2. On the flight controller set `SERIAL2_PROTOCOL = 2` (MAVLink 2) and turn on
telemetry streams for that port at about 4 Hz: `SR2_*` on older firmware, `MAVn_*` on
newer firmware (n counts the MAVLink ports from 1, so TELEM2 is usually `MAV3_*`). The
IDS only listens, so it never asks for them itself. Alerts
go back over the same port and ArduPilot forwards them to the ground station.

```bash
.venv/bin/sn1ff3r run --connect /dev/ttyAMA0 --baud 921600 --config configs/default.yaml
```

**Run as a service**, so it starts on boot and restarts after a crash:

```bash
sudo cp deploy/sn1ff3r.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sn1ff3r
journalctl -u sn1ff3r -f
```

Edit the `ExecStart` line in `deploy/sn1ff3r.service` first so it matches your serial
port and config file. When the service is stopped, it saves any incident that is still
being recorded before exiting.

**Viewing alerts from the ground.** On the companion computer, run
`sn1ff3r dashboard --host 0.0.0.0` and open `http://<companion-ip>:8000` from a laptop
on the same network. This is read-only.

## 4. Per-airframe settings

All thresholds live in `configs/*.yaml`. Anything not listed keeps its default.

| Profile | For |
|---|---|
| `default.yaml` | General multirotors |
| `survey_multirotor.yaml` | Slow mapping drones (tighter speed limit) |
| `fixed_wing.yaml` | Planes (higher speed limit, looser altitude tolerance) |

The trusted ground-station system IDs are set with `authorized_source_ids`. A typo in a
key name is reported as an error rather than silently ignored.

## 5. Troubleshooting

| Problem | Fix |
|---|---|
| `Cannot start: UDP port ... is already in use` | Another program has that port (`lsof -nP -iUDP:14560` shows which). Use another port on both sides: `output add 127.0.0.1:<port>` in MAVProxy and `--connect udpin:127.0.0.1:<port>` |
| GUI stays on "Waiting to hear from the drone" | MAVProxy isn't sending to the IDS's port. Type `output list` in MAVProxy to check |
| GPS test says "No heartbeat on udp port 14551" | Add the second output: `output add 127.0.0.1:14551` |
| `sim_vehicle.py: command not found` | Activate the Python environment you installed ArduPilot's tools into |
| Flood test isn't noticed | Wait ~30 s after connecting before testing; the IDS needs to learn the normal rate first |
