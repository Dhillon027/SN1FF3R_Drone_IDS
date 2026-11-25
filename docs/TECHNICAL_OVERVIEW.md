# SN1FF3R: technical overview

## 1. Purpose and scope

SN1FF3R is an onboard intrusion detection system for MAVLink drones
running ArduPilot. It runs on the companion computer, reads the MAVLink stream from the
flight controller, and reports attacks as they happen. It is **passive**: it never
blocks, alters or sends commands to the vehicle. The only thing it sends is a short
`STATUSTEXT` alert that the ground station displays to the pilot.

**Target platforms**
- ArduPilot vehicles (tested with ArduCopter SITL, 4.8.0-dev)
- MAVLink 1 and 2
- Linux companion computers: Raspberry Pi, Jetson and similar
- The flight controller link can be serial (UART) or UDP/TCP

## 2. Threats covered

| Threat | Category | What the attacker does | How it shows up in MAVLink |
|---|---|---|---|
| GPS spoofing | Navigation | Feeds the GPS receiver false signals | `GPS_RAW_INT` jumps or drifts away from the EKF estimate in `GLOBAL_POSITION_INT` |
| GPS jamming | Navigation | Drowns out the GPS signal | `GPS_RAW_INT` loses its fix, satellite count collapses, horizontal accuracy degrades |
| RF jamming | Communication | Blocks the radio link | The vehicle's `HEARTBEAT` stops arriving |
| Message flooding | Communication | Floods the link with junk packets | Message rate far above the learned normal rate |
| Command injection | Command & control | Sends commands as an unknown ground station | `COMMAND_LONG` / `SET_MODE` / `PARAM_SET` etc. from an untrusted system ID, or a repeated sequence number (replay) |
| Telemetry tampering | Telemetry | Rewrites or forges telemetry in transit | `GLOBAL_POSITION_INT.alt` and `VFR_HUD.alt` disagree |
| Parameter tampering | Firmware / system | Changes flight-controller settings | Parameter table differs from a trusted baseline |

## 3. Architecture

```
 Flight controller (ArduPilot)
          │  MAVLink over serial or UDP
          ▼
 ┌─────────────────────────── sn1ff3r run ────────────────────────────┐
 │  monitor.py            receives each message (and "silence" ticks)  │
 │        │                                                             │
 │  feature_extractor.py  turns it into numbers: rates, speeds,        │
 │        │               heartbeat age, altitude difference, sequence  │
 │        │               gaps, all compared with learned baselines     │
 │  detectors/            5 per-message checks, each returning          │
 │        │               (attack?, confidence, reason)                 │
 │  ids_engine.py         runs them, folds repeat alerts into a count   │
 │        │                                                             │
 │  ├── logger.py         ids_alerts.jsonl: hash-chained alert log      │
 │  └── black_box.py      forensic_snapshots/: one sealed file per      │
 │                        incident (before, during and after)           │
 └──────────────────────────────────────────────────────────────────────┘
          │
 GUI / dashboard (optional, ground side): reads the same files
 params check (on demand): compares the parameter table with a baseline
```

**Data sources used**

| Message | Used for |
|---|---|
| `HEARTBEAT` | Link liveness (vehicle only), vehicle ID, mode, armed state |
| `GLOBAL_POSITION_INT` | EKF position, velocity and altitude |
| `GPS_RAW_INT` | Raw receiver fix, fix type, satellites, horizontal accuracy, ground speed and course |
| `VFR_HUD` | Second altitude report for cross-checking |
| `COMMAND_LONG`, `COMMAND_INT`, `SET_MODE`, `SET_POSITION_TARGET_*`, `MISSION_SET_CURRENT`, `PARAM_SET` | Command source and sequence checks |
| All messages | Message rate, per-sender sequence numbers |
| `PARAM_VALUE` (on demand) | Parameter integrity |

## 4. Detection method

The key idea is that each check **learns what's normal for this vehicle** instead of
relying only on fixed thresholds. Each learned signal keeps just a running mean and
variance (an exponential moving average, EWMA), updated in constant time with no stored
history:

```
diff = x − mean
mean = mean + α·diff
var  = (1 − α)·(var + α·diff²)
z    = (x − mean) / max(std, floor)      # scored before updating
```

Scoring a value before adding it to the baseline stops an attack from pulling the
baseline towards itself. A warm-up period and a minimum standard deviation stop a young
or very quiet baseline from over-reacting. Hard physical limits sit alongside the learned
baselines, so obvious attacks are caught immediately with no learning needed.

| Check | Rule | Default threshold | Confidence |
|---|---|---|---|
| **GPS Spoofing** | Raw GPS fix or EKF position moves faster than physically possible | 40 m/s | 0.90 |
| | Raw GPS fix and EKF position disagree | 30 m | 0.80 |
| | Learned baseline of the *position residual* (how far each fix lands from where the reported velocity predicted) | z > 4, after 20 samples, std ≥ 1 m/s | 0.60 |
| **GPS Jamming**  | GPS fix lost | fix type < 3D | 0.80 |
| | Satellite count drops below its learned level | ≥ 6 fewer | 0.70 |
| | Reported horizontal accuracy degrades | > 50 m | 0.60 |
| **Link Jamming / Flooding** | No heartbeat from the flight controller (also checked when no packets arrive at all) | 3 s | 0.85 |
| | Message rate vs learned baseline: must be unusual *and* several times normal | z > 5 and ≥ 3×, after 20 s | 0.70 |
| **Command Injection** | Command from a system ID not on the trusted list (vehicle's own ID always trusted) | trusted: 255 | 0.85 |
| | Sequence number repeats the previous one (replay) | — | 0.60 |
| | Sequence gap on a sender normally seen in full | > 5 | 0.50 |
| **Telemetry Tampering** | `GLOBAL_POSITION_INT` and `VFR_HUD` altitude disagree (once they have agreed after boot, and `VFR_HUD` is fresh) | 15 m | 0.75 |
| **Settings Integrity** | Parameter values differ from a trusted baseline (self-changing parameters excluded) | any change | 1.00 |

Why the GPS baseline learns the *residual* rather than raw speed: a drone that has been
hovering has a near-zero speed baseline, so its first normal flight leg would look
extreme. A drone that genuinely speeds up also reports the higher velocity, so its
residual stays small. A spoofed position jump doesn't come with a matching velocity.

**Avoiding false alarms in practice**
- Uses the autopilot's own timestamps, not packet arrival times (UDP delivers in bursts)
- Ignores position 0,0 (no fix yet) and the boot period before the altitude reports agree
- Leaves bulk downloads (parameters, missions, logs) out of the message rate
- Only the flight controller's heartbeat counts as proof the link is alive
- Judges sequence gaps only for senders whose full stream the IDS normally sees

All thresholds are in `configs/*.yaml`, with profiles for general multirotors, slow
survey multirotors and fixed-wing aircraft.

## 5. Logging and forensics

**Alert log** (`ids_alerts.jsonl`). Each alert records the time, check, confidence,
reason, message type and sender. Every line includes the SHA-256 hash of the previous
line, so editing, deleting or reordering an old alert breaks the chain. The GUI and
`sn1ff3r verify log` both check it. If one check keeps firing during a sustained
attack, repeats within 3 s are folded into a `repeats` count instead of new lines.

**Flight recorder** (`forensic_snapshots/`). The last 200 messages are kept in memory.
When any check fires, those become the "before" part of an incident, and everything
after is captured until 5 s pass with no new detection. The incident is then written
once, as a single SHA-256 sealed JSON file with every message and the numbers each check
saw. The "before" part is also written immediately when an incident starts, in case
power is lost mid-incident. Stopping the service saves any open incident.

**Alerts to the pilot.** Every logged alert is also sent as a MAVLink `STATUSTEXT`
(e.g. `SN1FF3R: GPS jamming (0.80)`) from the companion computer (component 191).
ArduPilot forwards it to the ground station, so it appears in Mission Planner or
QGroundControl. `--gcs-alert-to` can also send it straight to a ground station, which is
used in SITL where MAVProxy doesn't relay it back. Verified in SITL: a STATUSTEXT sent by
the IDS on the autopilot's serial port was delivered to the ground-station link.

**GUI.** Overview, Alerts, Flight recorder and Attack lab. It uses only the Python
standard library, so it works offline. It can run in live mode (`sn1ff3r gui`) or
read-only mode (`sn1ff3r dashboard`).

## 6. Validation performed

**Environment:** ArduCopter 4.8.0-dev SITL on macOS (Apple Silicon), MAVProxy outputs to
the IDS. The quadcopter was armed in GUIDED mode at 20 m, flying a 60 m square pattern.
Telemetry rate was about 113 messages/s.

The attack rows are functional checks, one to three runs per scenario, not a
statistical evaluation. The false-positive row is a longer campaign.

| Test | Scenario | Result |
|---|---|---|
| **False positives** | 6 SITL drones × ~30 min = **3.1 flight-hours** of benign flying with the headless `sn1ff3r run`: random wind (1–7.8 m/s), 31 take-offs and landings, 270 waypoint legs at 2–12 m/s and 10–60 m, 173 mode changes (GUIDED/LOITER/BRAKE/LAND), 36 full parameter downloads, 20 stream-rate changes | **0 alerts, 0 incidents.** Rough estimate: fewer than ~1 false alert per flight-hour (95% upper bound from 0 in 3.1 h). IDS CPU averaged 0.75% of one core |
| Benign flight | 75 s of normal flight, no attacks | 0 alerts |
| Benign replay | 30 s of recorded SITL traffic replayed 30× through the detectors (101,850 messages) | 0 alerts |
| GPS spoofing | SITL GPS shifted by 0.001° (~111 m) for 12 s | Detected: raw fix jump (716 m/s), raw vs EKF divergence (~145 m), EKF position jump |
| Command injection | `COMMAND_LONG` DO_SET_MODE from system ID 99 | Detected: "Unauthorized COMMAND_LONG cmd=176 from system ID 99" |
| Message flood | ~1,500 heartbeats/s for 3 s | Detected: 1,614 msg/s vs 115 msg/s learned baseline |
| RF jamming | All packets dropped at the receiver for 8 s | Detected after 3.0 s of heartbeat silence |
| GPS jamming | ArduPilot's own jamming simulation (`SIM_GPS1_JAM = 1`) for 15 s, while flying | Detected 0.27 s after it started ("GPS fix lost"), then "accuracy degraded to 83–281 m"; alert shown at the ground-station port as `SN1FF3R: GPS jamming (0.80)` |
| Telemetry forgery | Forged position reports with altitude +150 m | Detected: 754.1 m vs 604.1 m (Δ150 m) |
| Parameter tampering | `FENCE_ENABLE` changed after a baseline of 1,427 parameters | Detected: `FENCE_ENABLE` 0 → 1 reported |
| Evidence integrity | All incident files and the alert log checked with `sn1ff3r verify` | All verified; editing a file is detected (automated tests) |
| Shutdown | Service stopped (SIGTERM) mid-incident | Open incident saved and verified |

The automated test suite (`pytest tests/`) covers each check firing and staying quiet,
config loading, tamper detection on both evidence types, and the false-alarm edge cases
above. It needs no simulator.

## 7. Performance

Measured on the same recorded SITL traffic (113 messages/s), Apple Silicon, Python 3.10:

| Metric | Value |
|---|---|
| Detection work per message (5 checks) | ~1.86 µs |
| Detection + flight recorder per message | ~2.07 µs |
| Whole `sn1ff3r run` process, CPU | ~0.75% of one core (including MAVLink decoding; average over 3.1 flight-hours) |
| Memory | ~38 MB (mostly the pymavlink library) |
| Flight recorder buffer (200 messages) | ~250 KB (~1.3 KB per message) |
| Disk during normal flight | none |
| Per alert | ~0.45 KB |
| Per incident file | 0.35–1.7 MB |

**Estimates for companion computers** (not measured; Python runs roughly 4–6× slower on
a Raspberry Pi 4 than the machine above):

| Board | Estimated CPU at 100–150 msg/s |
|---|---|
| Raspberry Pi 4 / 5 | ~3–5% of one core |
| Jetson Nano / Orin | ~2–4% of one core |
| Raspberry Pi Zero 2 W | ~10–15% of one core |

## 8. Known limitations

- **Slow GPS drift** that the EKF follows gradually may not cross the jump or divergence
  limits.
- **Spoofed trusted IDs:** a command sent with the trusted ground-station ID (255) passes
  the allow-list. MAVLink 2 message signing on the vehicle closes this gap.
- **Partial jamming** that still lets occasional heartbeats through, and floods below 3×
  the normal rate, are not flagged, by design, to avoid false alarms.
- **Mission tampering** (uploading a new mission) is not monitored.
- **Telemetry forgery from boot:** the altitude cross-check starts only once the two
  reports have agreed, so forgery present from the very start is not caught.
- **Log chain:** it proves old alerts weren't changed unless every later entry was
  rewritten too. It isn't a digital signature, so copy logs off the vehicle regularly.
- **Visibility:** the IDS only sees traffic that reaches the companion computer.
