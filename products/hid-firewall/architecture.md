# HID Security Gateway ("HID Firewall") — Architecture

A detailed design for a defensive intermediary that sits between a HID peripheral
and the host, inspects and logs HID behavior, enforces policy, and can block
suspicious activity.

- **Status:** design document (no hardware prototype yet — honestly labeled)
- **Last reviewed:** 2026-08-31
- **Related:** `../../docs/detection.md`, `../../docs/attack-surface.md`,
  `../../software/hidwatch/` (the software analog of the gateway's analysis core)

```
      ┌──────────┐        ┌─────────────────────────┐        ┌──────────┐
      │ KEYBOARD │  USB   │   HID SECURITY GATEWAY  │  USB   │ COMPUTER │
      │  (HID)   │───────▶│  inspect · policy · log │───────▶│  (host)  │
      └──────────┘        └─────────────────────────┘        └──────────┘
                             device-side      host-side
                             (acts as host)   (acts as device/proxy)
```

---

## 1. Concept

The gateway is a **USB host on the device side** and a **USB device (proxy) on
the host side**. It fully re-presents the downstream peripheral to the upstream
host, which means it can:

- enumerate and inspect the real device,
- decide what identity/descriptors/reports to forward,
- observe and rate-limit runtime reports,
- log everything for forensics,
- and, crucially, **normalize or reject** hostile descriptors before the host's
  (historically fragile) parser ever sees them.

This is the hardware embodiment of "add a real boundary where HID provides only a
label" (`../../docs/hid-fundamentals.md` §5).

---

## 2. Capabilities and feasibility (be honest)

Each capability is rated by where it can realistically live:
**SW** = host software only · **HW** = inline hardware · **HW+SW** = hardware
data path with a software control/analysis plane.

| Capability | Feasible as | Notes / limits |
| --- | --- | --- |
| Device identification (VID/PID/serial/iface) | SW, HW+SW | Attributes are spoofable; identification ≠ authentication. |
| HID descriptor inspection | SW, HW+SW | The safe parser (`hidwatch.descriptor`) runs here. |
| Descriptor **normalization** (rewrite to a safe canonical form) | HW+SW | Strong value: shields the host parser. Requires careful re-presentation; some quirky devices may break. |
| Report parsing & protocol validation | SW, HW+SW | Reject reports inconsistent with the (normalized) descriptor. |
| Policy enforcement (allow/block/quarantine) | HW (to truly block), SW (advisory) | Only inline HW can physically prevent bytes from reaching the host. |
| Behavioral analysis / anomaly detection | SW, HW+SW | Same model as `hidwatch`; needs a control plane. |
| Rate limiting | HW+SW | Inline HW can throttle/drop injected bursts. |
| Device authorization (human-in-the-loop) | HW+SW | e.g. a physical button to approve a new keyboard. |
| Quarantine (attach but withhold from host) | HW | Hold enumeration until approved. |
| Logging / forensic evidence | SW, HW+SW | Tamper-evident log ideally on the gateway. |
| Firmware identity of the gateway itself | HW | Secure boot on the gateway (see secure-keyboard research). |
| **Cryptographic attestation of the downstream device** | **mostly infeasible today** | Commodity HID devices don't support attestation; the gateway can attest *itself* and the *channel*, but cannot make a dumb keyboard prove its firmware. |
| Blocking an **independent radio** in the peripheral | **infeasible** | A secondary radio (O.MG/COTTONMOUTH) bypasses the wire entirely; a wired gateway cannot see or stop it. Stated plainly. |
| Stopping **wireless (BT/BLE) injection into the host** | **infeasible for a wired gateway** | The gateway is on the USB path; a BLE injection reaches the host's own radio, not through the gateway. |

### The two honest limits worth repeating

1. **A wired HID firewall cannot defend the wireless path.** BT/BLE injection
   (CVE-2023-45866 class) goes to the host's own radio. Defending that needs a
   host-side control or a trusted keyboard, not an inline USB device.
2. **It cannot detect an independent radio** inside the peripheral. DEVICE→NETWORK
   via a hidden radio is out of band by definition.

A gateway that claimed otherwise would be security theater. Its real, defensible
value is on the **wired DEVICE→HOST** path: descriptor shielding, injection rate
limiting, authorization, and forensic logging.

---

## 3. Reference architecture (HW+SW)

```
                DOWNSTREAM (device side)                UPSTREAM (host side)
   ┌───────────────────────────────────────┐   ┌──────────────────────────────┐
   │ USB Host controller  ──► Enumerator    │   │ USB Device controller (proxy)│
   │                         Descriptor      │   │  presents normalized identity│
   │                         capture         │   │  + validated report stream   │
   └───────────────┬───────────────────────┘   └───────────────▲──────────────┘
                   │                                            │
             ┌─────▼────────────────  DATA PLANE  ──────────────┴─────┐
             │  Safe descriptor parser + normalizer                   │
             │  Report validator (conformance to normalized desc)     │
             │  Rate limiter / dropper                                │
             └─────┬─────────────────────────────────────────────────┘
                   │ events/metrics (one-way to control plane)
             ┌─────▼─────────────  CONTROL PLANE  ────────────────────┐
             │  Behavioral analyzer (hidwatch core)                   │
             │  Policy engine (allow/block/quarantine/authorize)      │
             │  Tamper-evident logger                                 │
             │  Local UI (LED/button/e-ink) — NO network by default   │
             └───────────────────────────────────────────────────────┘
```

Design constraints (mirroring the software's principles):
- **No default network connectivity.** A device meant to catch exfiltration must
  not add an exfiltration channel. Any connectivity is opt-in and physically
  indicatable.
- **Fail-safe policy is configurable.** "Fail closed" (block on uncertainty) for
  high-assurance; "fail open" (log-only) for availability-sensitive use. Default
  should be explicit and documented.
- **The data path must be simple and auditable.** Complexity in the inline path
  is itself risk (it parses hostile input in the critical path).

---

## 4. Realistic implementation tiers

| Tier | What it is | Buildable now? |
| --- | --- | --- |
| **T0 — Software monitor** | `hidwatch` on the host: observe + score, no blocking. | ✅ Implemented (v0.1.0). |
| **T1 — Software authorizer** | Integrate with USBGuard/OS authorization: hold new devices for approval, scored by `hidwatch`. | ✅ Feasible with existing OS primitives. |
| **T2 — Inline logger/monitor** | A USB proxy (e.g. Raspberry Pi with USB gadget mode, or a Cynthion/LUNA-class board) that passes through and logs, no blocking yet. | ✅ Feasible with off-the-shelf hardware. |
| **T3 — Inline enforcer** | T2 + descriptor normalization + rate limiting + block/quarantine + button authorization. | ⚠️ Feasible but engineering-heavy; latency and device-compatibility are the hard parts. |
| **T4 — Attesting gateway** | T3 + gateway secure boot + tamper-evident logs + (aspirational) downstream attestation for devices that support it. | ⚠️ Partly; downstream attestation blocked by ecosystem. |

The roadmap (`../../ROADMAP.md`) sequences these as Stages 5–6.

---

## 5. Hard problems

- **Latency & compatibility.** Inline proxying must not add perceptible input
  latency and must not break quirky-but-legitimate devices. This is the main
  engineering risk of T3+.
- **Descriptor normalization correctness.** Rewriting descriptors to a safe
  canonical form without breaking real devices is subtle; needs the fixture
  corpus and broad device testing.
- **Distinguishing injection from fast legitimate input** — same false-positive
  problem as `hidwatch` (`../../docs/detection.md` §5), now with blocking
  consequences. Blocking a real barcode scanner in a warehouse is a real cost.
- **Physical trust of the gateway itself.** The gateway becomes a high-value
  target; it needs its own secure boot / tamper evidence.

---

## 6. Prototype plan (pointer)

See `hardware/prototypes/README.md` for the concrete bring-up plan (USB gadget
proxy on commodity hardware, reusing `hidwatch` as the analysis core, starting at
Tier T2 log-only before any blocking).

## 7. Cross-references

- `../../software/hidwatch/` — the analysis core, already working.
- `hardware/architecture/secure-keyboard.md` — device-side assurance (the other
  half of the solution).
- `../../docs/attack-surface.md` §3 — the coverage matrix this gateway fills in.
