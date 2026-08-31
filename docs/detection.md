# Detection

What HID threats can actually be detected, how, and — honestly — what cannot.
This page defines the signals that `hidwatch` implements and grounds the risk
scoring.

Last reviewed: 2026-08-31

---

## 1. Detection philosophy

1. **Observability before enforcement.** You cannot control what you cannot see.
   The first deliverable is *visibility*, not blocking.
2. **Non-destructive by default.** Detection uses read-only sources (sysfs,
   udev events, hidraw reads); it never writes to devices.
3. **Multi-signal.** No single indicator is reliable (see §4 on Malboard).
   Combine device-attribute, enumeration-timing, and behavioral signals.
4. **State the blind spots.** Some threats are simply not host-observable; we say
   so rather than implying full coverage.

## 2. Detectable signals (implemented / planned in hidwatch)

### 2.1 Device / enumeration signals
- **Unexpected interfaces** — a device exposing a HID-keyboard interface it
  shouldn't (e.g. a "flash drive" that is also a keyboard). Strong indicator.
- **Identity anomalies** — VID/PID/serial that change across reconnects; missing
  serial; VID/PID inconsistent with reported product.
- **Re-enumeration / reconnect bursts** — a device repeatedly detaching and
  reattaching, or changing its interface set at runtime.
- **Descriptor anomalies** — report descriptors that are malformed, declare
  implausible report sizes/counts, or don't match the device class.

### 2.2 Behavioral signals (the core of injection detection)
- **Keystroke rate** — sustained rates far above human capability (e.g. >~20–25
  keystrokes/sec sustained, or hundreds of chars with zero human jitter) suggest
  scripted injection. Human fast typing ≈ 8–12 keystrokes/sec in bursts.
- **Time-since-attach to first input** — input arriving within milliseconds of
  enumeration means no human was involved.
- **Report rate** — reports/sec wildly beyond the device's declared/typical
  cadence.
- **Modifier / command-pattern activity** — bursts consistent with automated
  command entry (e.g. GUI/Super key + run dialog patterns). Heuristic, not proof.
- **Impossible timing regularity** — inter-keystroke intervals with
  machine-perfect uniformity (low variance) unlike human typing.

### 2.3 Wireless signals (partial)
- New Bluetooth/BLE HID connections/pairings from unknown addresses.
- Pairing events not user-initiated.
- A new wireless keyboard immediately followed by input.

## 3. From signals to risk (the hidwatch scoring model)

`hidwatch` computes a **risk level** (LOW / MEDIUM / HIGH / CRITICAL) by
combining weighted signals into reasons, e.g.:

- Unexpected keyboard interface on a storage device → **HIGH** ("device presents
  an undeclared keyboard interface").
- Sustained keystroke rate > threshold with near-zero jitter → **HIGH/CRITICAL**
  ("impossible typing rate: 190 cps, jitter 0.4 ms").
- Input < 50 ms after enumeration → **MEDIUM/HIGH** ("input began 12 ms after
  attach; no human interaction window").
- Malformed/over-large descriptor → **MEDIUM** ("report descriptor declares
  report count 4096").

The model is transparent and **explains every score with reasons** — a security
tool that says "HIGH" without saying why is not useful. Thresholds live in
policy (`hidwatch policy`) so they are tunable, and the scoring is
unit-tested against the synthetic fixtures in `lab/fixtures/`.

Design rule: **default to explainable heuristics, not opaque ML.** ML-based
anomaly detection is a possible later stage (`ROADMAP.md` Stage 4) but must never
be a black box in a security control.

## 4. What detection cannot do (limitations — read this)

- **A capable malicious keyboard can forge human typing rhythm.** *Malboard*
  (`data/cves/research-malboard-2018.yaml`) defeated keystroke-dynamics
  detectors. Therefore rhythm alone is insufficient; we combine it with
  enumeration/timing/identity signals, and we do not claim rhythm-based detection
  is robust against a determined adversary.
- **Independent-radio exfiltration is invisible to the host.** O.MG/COTTONMOUTH
  class (DEVICE→NETWORK) leaves via its own radio; host software cannot see it.
  Requires physical/RF methods.
- **In-kernel exploitation** of a parser bug may crash/compromise before
  user-space monitoring can react. Descriptor *validation upstream* (a firewall)
  helps more than *observation* here.
- **Firmware identity** is not host-verifiable for commodity devices.
- **Perfectly slow, human-paced injection** blurs into legitimate input;
  behavioral detection has an inherent floor. This is a fundamental limitation,
  not a bug to be fixed.

## 5. False positives are a real cost

Legitimate devices produce injection-like patterns:
- **Barcode scanners** and **QR readers** "type" fast bursts as HID keyboards.
- **Macro keyboards / hotkeys / text expanders** emit rapid scripted sequences.
- **Password managers** with auto-type inject characters.
- **KVM switches / virtualization** cause re-enumeration.

`hidwatch` must support **allow-listing and per-device baselining** (learn a
device's normal profile) so these don't drown real signals. The fixtures corpus
(`lab/fixtures/`) deliberately includes barcode-scanner and macro-keyboard
benign cases to test false-positive resistance.

## 6. Cross-references

- `software/hidwatch/` — implementation.
- `lab/fixtures/` — benign and suspicious synthetic corpus.
- `mitigation.md` — what to do once detected.
- `data/cves/research-malboard-2018.yaml` — the detection-evasion caveat.
