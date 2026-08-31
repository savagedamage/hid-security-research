# Bluetooth HID (BR/EDR "Classic")

How keyboards and mice work over Bluetooth Classic (BR/EDR) using the HID
Profile (HIDP), and the security-relevant weaknesses of that path.

Last reviewed: 2026-08-31

Primary sources:
- Bluetooth SIG, *Human Interface Device Profile (HID) 1.1* / Core Spec —
  https://www.bluetooth.com/specifications/specs/
- BlueZ project — https://www.bluez.org/ and
  https://git.kernel.org/pub/scm/bluetooth/bluez.git/
- Bluetooth SIG security overview —
  https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/

See also the BLE (Low Energy) path in `ble-hid.md`; they are different stacks.

---

## 1. The stack

```
  Application / OS input subsystem
        ^
   HID Profile (HIDP)        <- interprets HID reports (same report model as USB)
        ^
   L2CAP  (two PSMs: HID Control 0x11, HID Interrupt 0x13)
        ^
   Baseband / Link Manager   <- pairing, encryption, key management
        ^
   Bluetooth radio (BR/EDR, 2.4 GHz)
```

Crucially, **HID over Bluetooth reuses the USB-HID report model**: the same
report descriptors, usages, and report packets described in
`hid-fundamentals.md`. So all the *parser* attack surface from USB HID also
applies once reports reach the host HID layer — plus Bluetooth adds its own
pairing, encryption, and stack-memory-safety attack surface underneath.

---

## 2. Pairing and its weaknesses

Bluetooth "trust" between two devices is established by **pairing** and
persisted by **bonding** (stored link keys). Association models:

- **Numeric Comparison** — both show a number; user confirms match (MITM-
  resistant).
- **Passkey Entry** — user types a code shown on the other device.
- **Just Works** — no user verification. Provides **encryption but not
  authentication** → vulnerable to man-in-the-middle. Common on devices without
  a display/keypad, which ironically includes many input peripherals.
- **Out Of Band** — keys exchanged via another channel (e.g. NFC).

### Documented pairing/key weaknesses (see `data/cves/`)

- **KNOB (CVE-2019-9506)** — an adjacent attacker influences **encryption key
  length** negotiation down to as little as 1 byte of entropy, then brute-forces
  it to decrypt and inject. Affects the spec itself (≤ 5.1) and many
  implementations. Directly threatens keyboard confidentiality/integrity.
- **Apple Magic Keyboard (CVE-2024-0230)** — a session-management issue let an
  attacker with physical access recover the pairing key and monitor traffic;
  fixed in firmware 2.0.6. A rare *keyboard-firmware* CVE.

---

## 3. Host-stack memory safety (the BlueBorne class)

Merely running a Bluetooth stack — a prerequisite for any Bluetooth keyboard —
exposes the host to remotely reachable parsing bugs:

- **CVE-2017-14315 (BlueBorne, iOS LEAP)** — heap overflow → full device
  control via the Bluetooth stack's high privilege; bypasses BT access control.
- **CVE-2020-0022 (BlueFrag, Android)** — OOB write in packet reassembly → RCE
  over Bluetooth with **no user interaction**.

These are not HID bugs per se, but they are part of the **attack surface a
Bluetooth keyboard forces you to accept**. A wired keyboard does not require you
to run a remotely reachable BR/EDR stack.

---

## 4. Authorization flaws specific to HID

The most important class for this project is **input being accepted without the
user authorizing the device**:

- **CVE-2020-0556** — improper access control in BlueZ's HID/HOGP subsystem;
  unauthenticated adjacent user → privilege escalation / DoS.
- **CVE-2020-24490** — buffer restriction issue in BlueZ (advertising report
  handling) → DoS via adjacent access.
- **CVE-2023-45866** — the flagship: a BlueZ HID **host** accepts keyboard
  reports from an **unauthenticated peripheral**, enabling keystroke injection
  with no user interaction. The underlying "force-pair an emulated keyboard"
  technique (Marc Newlin / SkySafe, 2023) affected multiple OS stacks. NVD notes
  the CVE-2020-0556 fix may already cover BlueZ in some configs. See
  `data/cves/cve-2023-45866.yaml`.

The common thread: the **HID role and the user-authorization decision are
decoupled**. A device can be in a position to send keystrokes before, or without,
the human ever agreeing to trust it.

---

## 5. Why Bluetooth HID is a bigger attack surface than USB HID

| Dimension | USB HID | Bluetooth HID |
| --- | --- | --- |
| Proximity needed | physical port access | RF range (meters) |
| Identity | device descriptors (spoofable) | BD_ADDR + pairing (spoofable/forceable) |
| Extra attack surface | USB stack + HID parser | + pairing/crypto + BR/EDR stack memory safety |
| No-interaction injection | needs plugged device | demonstrated wirelessly (CVE-2023-45866) |
| Detectability from host | device attach visible | pairing/connection events visible, but forced/silent pairings are subtle |

**Takeaway:** Bluetooth HID inherits *all* of USB HID's report/descriptor parser
risk and adds pairing weaknesses and a remotely reachable stack. For sensitive
environments, wired or radio-disabled input meaningfully reduces surface.

---

## 6. Detection & mitigation

Detection (host-observable):
- Unexpected HID (keyboard) connections/pairings from unknown BD_ADDRs.
- Pairing events not initiated by the user.
- A new Bluetooth keyboard immediately followed by a burst of input.

Mitigation:
- Patch the stack (KNOB, BlueBorne, CVE-2023-45866 fixes).
- Disable Bluetooth when unused; avoid staying connectable/discoverable.
- Require authenticated pairing; avoid Just Works for input devices.
- Prefer wired input in high-assurance settings.

---

## 7. Cross-references

- `docs/ble-hid.md` — the BLE / HID-over-GATT path (different stack).
- `docs/hid-fundamentals.md` — the shared report model.
- `THREAT_MODEL.md` §3.2 — Bluetooth transport threats.
- `data/cves/` — CVE-2019-9506, CVE-2020-0022, CVE-2017-14315, CVE-2020-0556,
  CVE-2020-24490, CVE-2023-45866, CVE-2024-0230.
