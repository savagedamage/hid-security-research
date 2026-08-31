# HID Fundamentals

How Human Interface Devices actually work, and — crucially — **where the
security boundaries really are**. This page is the conceptual foundation for the
transport-specific pages (`usb-hid.md`, `bluetooth-hid.md`, `ble-hid.md`) and
for the threat model.

Last reviewed: 2026-08-31

Primary sources:
- USB-IF, *Device Class Definition for HID 1.11* —
  https://www.usb.org/document-library/device-class-definition-hid-111
- USB-IF, *HID Usage Tables 1.5* —
  https://usb.org/document-library/hid-usage-tables-15
- Linux kernel HID documentation —
  https://docs.kernel.org/hid/index.html

---

## 1. What "HID" means

**HID (Human Interface Device)** is a device *class* — a standardized contract
for how a peripheral describes itself and exchanges data with a host. It was
defined by the USB Implementers Forum for USB, and the same core concepts
(report descriptors, reports, usages) were reused for Bluetooth (the HID Profile
on BR/EDR, and HID-over-GATT on BLE).

The design goals of HID were:

1. **Self-description.** A device tells the host what data it will send and what
   that data *means*, via a **report descriptor**. The host does not need a
   device-specific driver — one generic HID driver handles all conformant
   devices.
2. **Extensibility.** New kinds of controls (media keys, VR controllers, sensors)
   can be added by defining new **usages** without changing the protocol.
3. **Low overhead.** Suitable for tiny microcontrollers.

The security-relevant consequence of goal #1: **the device is the authority on
what it is and what it sends.** The host builds its entire understanding of the
device from bytes the device supplies. That is the root of the HID trust
problem.

---

## 2. The three layers of HID

```
  +-------------------------------------------------------------+
  |  USAGES         (semantic meaning: "this bit is Left Shift") |  HID Usage Tables
  +-------------------------------------------------------------+
  |  REPORT DESCRIPTOR  (structure: field sizes, counts, types) |  parsed by host
  +-------------------------------------------------------------+
  |  REPORTS            (actual data packets at runtime)        |  input/output/feature
  +-------------------------------------------------------------+
```

### 2.1 Usages and Usage Pages

A **usage** is a 32-bit semantic tag = (Usage Page << 16) | Usage ID. Examples:

| Usage Page | Meaning | Example usages |
| --- | --- | --- |
| 0x01 Generic Desktop | pointers, axes | 0x02 Mouse, 0x06 Keyboard, 0x30 X, 0x31 Y |
| 0x07 Keyboard/Keypad | key codes | 0x04 'a', 0x28 Enter, 0xE1 Left Shift |
| 0x08 LEDs | keyboard LEDs | 0x01 Num Lock, 0x02 Caps Lock |
| 0x0C Consumer | media / consumer control | 0xB0 Play, 0xE9 Volume Up, 0x223 AC Home |
| 0xFF00–0xFFFF Vendor-defined | proprietary | anything the vendor wants |

Security note: **Usage Page 0x0C (Consumer Control)** is why a "keyboard" can
send media keys and even launch a browser to a URL (AC Home / AL functions).
**Vendor-defined usage pages** are opaque tunnels — a device can move arbitrary
data to matching companion software this way. Both are attack-relevant.

### 2.2 The report descriptor

The **report descriptor** is a compact, self-describing byte array of
*items*. Each item is a tag + size + data. Main items (`Input`, `Output`,
`Feature`, `Collection`) declare fields; global/local items (`Usage Page`,
`Report Size`, `Report Count`, `Logical Min/Max`, `Report ID`, …) set the
context for those fields.

The host's **HID parser** walks this byte array to learn the exact bit layout of
every report the device will send. **This parser is a classic attack surface**:
it consumes fully attacker-controlled input, historically in C, in the kernel.
Nearly every "malicious HID descriptor" CVE in our dataset (CVE-2014-3184,
CVE-2025-38103, CVE-2025-39806, CVE-2025-55096) lives here.

Example: a **boot keyboard** report descriptor declares an 8-byte input report:

```
byte 0: modifier bitmap  (bit0 LeftCtrl, bit1 LeftShift, ... bit7 RightGUI)
byte 1: reserved (0x00)
byte 2..7: up to six simultaneously-pressed key codes (Usage Page 0x07)
```

### 2.3 Reports

At runtime the device exchanges **reports**:

- **Input report** — device → host (a keypress, mouse movement).
- **Output report** — host → device (set keyboard LEDs).
- **Feature report** — bidirectional config/state, not part of the normal data
  stream (often used by companion software to configure the device).

If multiple report *formats* share an endpoint, each is prefixed with a
**Report ID** byte. Reports must conform to the declared descriptor — but a
malicious device can send reports that *don't*, which is how report-parsing bugs
(CVE-2020-0465, CVE-2026-43140) get triggered. **Robust hosts must not assume
reports match the descriptor.**

---

## 3. Keyboards specifically

A standard USB keyboard:

- Presents an **Interface** with class = HID (0x03), and for boot keyboards,
  subclass = Boot (0x01), protocol = Keyboard (0x01).
- Provides a report descriptor (either the boot-keyboard layout or a richer one).
- Sends 8-byte input reports on key state changes.
- Receives 1-byte output reports for the LEDs.

Two protocol modes:

- **Boot protocol** — a fixed, simple format the BIOS/firmware can use *before*
  the OS HID driver loads. Any device claiming boot-keyboard support can inject
  input very early in the boot process.
- **Report protocol** — the full, descriptor-defined format used once the OS is
  running.

**Consumer-control** and **vendor** collections are frequently bundled into the
same physical keyboard as *additional* top-level collections or interfaces —
this is how one device legitimately exposes keys, media controls, and a config
channel, and also how a malicious device hides an extra capability.

---

## 4. Composite devices — one plug, many functions

A single physical USB device can expose **multiple interfaces** (a *composite*
device), each bound to a different driver. A legitimate example: a keyboard that
presents (a) a boot-keyboard HID interface, (b) a consumer-control HID
interface, and (c) a vendor interface for its configurator.

Security consequence: **"it's just a keyboard" is never verifiable from the
outside.** A device can present a keyboard interface *and* a mass-storage
interface *and* a network interface. BadUSB and the O.MG cable exploit exactly
this. Detecting *unexpected interfaces* is a core `hidwatch` capability.

---

## 5. Where the security boundaries actually are

This is the key takeaway of the whole page.

```
   DEVICE (untrusted computer)          |         HOST (trusts the device)
   ------------------------------------ | ------------------------------------
   firmware chooses:                    |  (B1) transport accepts descriptors
     - descriptors (VID/PID/class)      | ----> unauthenticated, unverified
     - report descriptor bytes          |  (B2) HID parser interprets bytes
     - report contents & timing         | ----> memory-safety-critical
     - number/type of interfaces        |  (B3) driver binds, delivers input
     - whether to re-enumerate          |  (B4) OS treats input as user intent
                                        |  (B5) companion sw acts on feature reports
```

- **B1 (transport trust):** VID/PID/serial/class are asserted by the device and
  accepted without authentication. *This is not a boundary that stops a
  determined device; it is a label.*
- **B2 (parser):** the only place the host really *processes* untrusted device
  data structurally. Must be memory-safe and defensive. Historically it wasn't.
- **B3/B4 (driver + OS):** once bound, input flows to the focused application as
  genuine user intent. There is no per-keystroke provenance.
- **B5 (companion software):** feature reports and vendor interfaces connect the
  device to often-privileged host software (see `COMPANION_TO_HOST`).

**No layer verifies device authenticity.** The entire model is "the device is
whatever it says it is." Every defensive idea in this project — monitoring
(`hidwatch`), authorization (USBGuard), a HID firewall, cryptographic
attestation — is an attempt to add a real boundary where the standard provides
only a label.

---

## 6. Why this is hard to "just fix"

- Injection (a device typing) abuses **intended** behavior; no patch removes a
  keyboard's ability to type.
- VID/PID authentication would require an ecosystem-wide identity/PKI scheme that
  does not exist for commodity HID.
- Report/descriptor parsers can be hardened and fuzzed, but bugs keep appearing
  (see the 2025–2026 kernel CVEs in our dataset) — the surface is large and
  device-driven.

This is precisely why the project pursues **observability first** (you cannot
control what you cannot see) before enforcement.

---

## 7. Cross-references

- `docs/usb-hid.md` — USB enumeration and descriptors in detail.
- `docs/bluetooth-hid.md`, `docs/ble-hid.md` — wireless HID.
- `docs/host-trust-model.md` — the OS side of the boundary.
- `docs/attack-surface.md` — consolidated attack-surface catalog.
- `THREAT_MODEL.md` — threats organized by direction.
