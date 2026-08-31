# HID Attack Surface Catalog

A consolidated, cross-referenced catalog of the HID attack surface. This page is
the "map" that ties together the threat model, the taxonomy, and the dataset.

Last reviewed: 2026-08-31

- Threats organized by direction: `../THREAT_MODEL.md`
- Machine-readable taxonomy: `../data/attack-taxonomy/taxonomy.yaml`
- Verified examples: `../data/cves/`

---

## 1. The surface at a glance

```
                     ┌──────────────────────────────────────────────┐
   PHYSICAL/SUPPLY   │  device provenance, tampering, implants       │  HID-08,13
   ─────────────────►│                                              │
                     │  ┌────────────┐        transport            │
   RADIO (BT/BLE/RF) │  │  DEVICE    │  USB / BR-EDR / BLE / 2.4GHz │  HID-01,02,06,07
   ─────────────────►│  │ MCU+fw+radio│ ───────────────────────────►│  HID-11,12 (out)
                     │  └────────────┘                              │
                     │         │ descriptor + reports               │
                     │         ▼                                    │
                     │  HOST HID/USB/BT parser & drivers            │  HID-04,05,15
                     │         │ input events                       │
                     │         ▼                                    │
                     │  OS input subsystem → focused app            │  HID-02 (effect)
                     │  companion software (often privileged)       │  HID-09
                     └──────────────────────────────────────────────┘
```

## 2. Surface catalog (by component)

### 2.1 Device identity / descriptors
- **What's exposed:** VID/PID/serial/class, interface set, HID descriptor length.
- **Attacks:** impersonation, VID/PID spoofing, unexpected interfaces
  (HID-01). Composite abuse.
- **Verified:** BadUSB, Rubber Ducky, O.MG, CVE-2026-43140 (fake device).
- **Observable?** Yes — attach/enumeration events, interface classes
  (`hidwatch inspect`).

### 2.2 Report descriptor (the parser surface)
- **What's exposed:** fully attacker-chosen item stream the host must parse.
- **Attacks:** malicious descriptors → OOB (HID-04, HID-05).
- **Verified:** CVE-2014-3184, CVE-2025-38103, CVE-2025-39806, CVE-2025-55096,
  CVE-2025-68656.
- **Observable?** Partially — descriptor can be captured and validated
  (`hidwatch` descriptor checks); exploitation itself is in-kernel.

### 2.3 Runtime reports & timing
- **What's exposed:** report contents, conformance to descriptor, timing.
- **Attacks:** keystroke injection (HID-02), malformed reports → driver bugs
  (HID-05).
- **Verified:** CVE-2020-0465, CVE-2026-43140; Rubber Ducky/BadUSB for timing.
- **Observable?** Yes — report rate, keystroke rate, time-since-attach are the
  core `hidwatch monitor` signals.

### 2.4 Wireless transport (BT/BLE/2.4GHz)
- **What's exposed:** pairing, key negotiation, stack parsing, role handling.
- **Attacks:** unauthorized input (HID-06), pairing abuse (HID-07), stack RCE
  (HID-15).
- **Verified:** CVE-2023-45866, CVE-2019-9506 (KNOB), CVE-2020-0022, CVE-2017-14315,
  CVE-2020-0556, MouseJack, CVE-2016-6257.
- **Observable?** Partially — connection/pairing events are visible; a wired HID
  firewall cannot see a wireless injection into the host.

### 2.5 Firmware / bootloader / debug
- **What's exposed:** update path, signature checks, rollback protection, debug
  ports.
- **Attacks:** malicious firmware (HID-03), update abuse (HID-10), debug abuse
  (HID-14).
- **Verified:** BadUSB, CVE-2024-0230, CVE-2016-6257.
- **Observable?** Rarely from the host — no standard attestation. Motivates
  trusted-keyboard design.

### 2.6 Secondary radio / network channel
- **What's exposed:** an independent egress path.
- **Attacks:** exfiltration/C2 (HID-11), telemetry (HID-12).
- **Verified:** NSA ANT COTTONMOUTH, O.MG cable.
- **Observable?** Not from the host if the radio is independent — the hardest
  gap; needs physical/RF inspection.

### 2.7 Companion software
- **What's exposed:** privileged drivers/services, auto-update channels, cloud.
- **Attacks:** vulnerable/over-privileged software, BYOVD, insecure updates,
  telemetry (HID-09).
- **Verified:** industry pattern (peripheral driver LPEs, BYOVD); labeled
  `reported`/`documented` per case.
- **Observable?** Yes, with host security tooling (privilege, network, drivers) —
  but outside `hidwatch`'s HID-observation scope; noted as a distinct workstream.

## 3. Coverage matrix: what defenses see what

| Surface | OS authz (USBGuard) | hidwatch (behavior) | HID firewall (wired) | Trusted keyboard | Physical/RF |
| --- | --- | --- | --- | --- | --- |
| Identity/descriptors | ✅ block | ✅ observe | ✅ enforce | ✅ attest | — |
| Descriptor parser | partial | ✅ validate | ✅ normalize | n/a | — |
| Reports/timing | ✗ | ✅ | ✅ enforce | n/a | — |
| Wireless transport | ✗ | partial | ✗ (wired only) | ✅ (pairing UX) | ✅ |
| Firmware/debug | ✗ | ✗ | partial | ✅ | ✅ |
| Secondary radio | ✗ | ✗ | ✗ | ✅ (no radio) | ✅ |
| Companion software | ✗ | ✗ | ✗ | ✅ (none) | — |

Reading this matrix is the fastest way to understand **why the project needs
multiple layers**: no single control covers the surface, and the two hardest
columns (secondary radio, firmware) are exactly where the highest-impact,
lowest-observability threats live.

## 4. Cross-references

- `../THREAT_MODEL.md`, `../data/attack-taxonomy/taxonomy.yaml`,
  `../data/cves/INDEX.md`.
- `detection.md`, `mitigation.md` — turning this map into action.
