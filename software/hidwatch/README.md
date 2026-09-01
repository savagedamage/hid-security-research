# hidwatch

**Defensive HID observability and behavioral risk analysis.**

`hidwatch` makes the behavior of HID (keyboard / input) devices *observable* so
that keystroke injection, device impersonation, and descriptor anomalies can be
detected. It is part of the [hid-security-research](../../README.md) project.

> **Status: alpha (v0.1.0).** Implemented: report-descriptor parser, behavioral
> analyzer + explainable risk scoring, synthetic fixtures, correct read-only
> Linux sysfs enumeration, polling-based attach/detach/change monitoring, and a
> CLI. Planned: live report metrics (hidraw/usbmon), optional udev event delivery,
> privacy-safe recording, and richer wireless signals. See
> `../../ROADMAP.md`.

## Design principles

- **Observability before enforcement.** Visibility first; blocking later.
- **Non-destructive.** Reads only (sysfs/hidraw); never writes to devices, never
  flashes firmware, never toggles the USB `authorized` flag.
- **No network calls in the core library.** The tool that watches for
  exfiltration must not itself exfiltrate. (Enforced by zero runtime deps.)
- **Explainable.** Every risk verdict lists concrete reasons. No black boxes.
- **Works without hardware.** Runs against synthetic fixtures in CI/containers;
  never fabricates device data (no hardware → empty result, not invented data).

## Install

```bash
cd software/hidwatch
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"     # dev extras: pytest, ruff, mypy
```

If your toolchain can't build the editable install, you can run directly:

```bash
PYTHONPATH=src python -m hidwatch.cli --help
```

## Usage

```bash
hidwatch list                          # enumerate HID/USB devices (read-only)
hidwatch monitor                       # watch HID attach/detach/change events
hidwatch monitor --all --interval 0.5 # include all USB devices
hidwatch inspect --demo benign-keyboard
hidwatch inspect --demo badusb-flashdrive
hidwatch analyze --demo badusb-flashdrive     # simulated scripted injection
hidwatch analyze lab/fixtures/impossible-typing-rate.json
hidwatch descriptor 05010906A101...           # parse a raw report descriptor
hidwatch policy                                # show tunable thresholds
```

Example (`analyze --demo badusb-flashdrive`) output:

```
Device:        USB Flash Drive
  Transport:   usb
  VID:PID:     1234:5678
  Interfaces:  2
    - class=0x08 ... [class 0x08] Mass Storage
    - class=0x03 sub=0x01 proto=0x01 [keyboard] HID Boot Keyboard
Risk:          CRITICAL
Reasons:
  - [HIGH] device declared as 'storage' exposes a keyboard interface (classic BadUSB pattern)
  - [CRITICAL] impossible typing rate: 120 keystrokes/sec
  - ...
```

## Architecture

```
  backends/linux_sysfs.py   descriptor.py         analyzer.py
  (read-only enumeration)   (safe HID parser)     (behavior + risk scoring)
          \                      |                      /
           \                     |                     /
                          models.py  +  policy.py
                                 |
                               cli.py
```

- `descriptor.py` — a **defensive** HID report-descriptor parser that treats all
  input as hostile (bounds every read, rejects absurd sizes, never crashes on
  malformed input). Doubles as the reference parser argued for in
  `../../docs/future-research.md` §2.
- `analyzer.py` — multi-signal detection (enumeration/identity, descriptor,
  behavior) producing an explainable `RiskReport`.
- `policy.py` — tunable thresholds and allow-lists (barcode scanners / macro pads
  legitimately type fast; see `../../docs/detection.md` §5).
- `fixtures.py` — synthetic benign/suspicious scenarios and a JSON scenario
  loader for `../../lab/fixtures/`.
- `backends/linux_sysfs.py` — dependency-free, read-only inventory and lifecycle
  monitoring. It correctly associates Linux's sibling device/interface entries
  (`1-1` and `1-1:1.0`) and diffs snapshots by topology name. Polling is the
  portable fallback; a future udev source can implement the same event model.

## Limitations (read `../../docs/detection.md` §4)

- A capable malicious keyboard can forge human typing rhythm (Malboard).
- Independent-radio exfiltration is invisible to host software.
- In-kernel parser exploitation may occur before user-space can react.
- Perfectly human-paced injection blurs into legitimate input.

`hidwatch` reduces risk and increases visibility; it is not a complete defense.

## Tests

```bash
pytest                     # unit + fixture-corpus tests
ruff check . && mypy src   # lint + types
```
