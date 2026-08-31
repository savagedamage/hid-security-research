# Glossary

Definitions of terms and controlled vocabularies used throughout this project.
Where a term has a formal definition from a standards body, that source is cited.

Last reviewed: 2026-08-31

---

## Evidence vocabulary (how strongly is a claim supported?)

This project labels claims about device/attack behavior with one of the
following. Contributors must not blur these together.

| Label | Meaning |
| --- | --- |
| **observed** | We (or a cited party) directly saw the behavior on real hardware, with reproducible evidence (capture, log, photo of setup). |
| **documented** | A primary source (advisory, CVE, spec, vendor doc) states it as fact. |
| **demonstrated** | A working proof-of-concept exists and was shown publicly (e.g. conference demo, published PoC code). |
| **reported** | A credible secondary source reports it, but we have not seen primary evidence. |
| **inferred** | A reasonable technical deduction from known facts, not directly evidenced. Must be flagged as such. |
| **theoretical** | Plausible given how the technology works, but no known demonstration or incident. |

## Entry-type vocabulary (what *kind* of thing is a dataset entry?)

| Type | Meaning |
| --- | --- |
| **CVE** | Has an assigned CVE ID in the CVE List / NVD. |
| **academic-research** | Peer-reviewed or preprint academic work. |
| **proof-of-concept** | Public PoC / tool / demo, not necessarily a CVE. |
| **documented-incident** | A real-world incident reported by a credible source. |
| **security-product** | A commercial or open-source defensive product (for competitive/landscape analysis). |
| **theoretical-threat** | A threat we can reason about but which has no public demonstration. |

## Confidence

`high` — multiple primary sources agree; `medium` — one primary source or
partial corroboration; `low` — single weak source, disputed, or largely
inferred.

---

## HID and USB terms

- **HID (Human Interface Device)** — A USB/Bluetooth device class for
  human-input peripherals (keyboards, mice, game controllers, etc.). Defined by
  the USB-IF *Device Class Definition for HID 1.11*.
  Source: https://www.usb.org/document-library/device-class-definition-hid-111
- **Report Descriptor** — A structured, self-describing byte array a HID device
  provides to declare the format of its reports (which bits mean which
  keys/axes/buttons). The host HID parser interprets it. A malformed or hostile
  report descriptor is a classic HID attack surface.
- **Report** — The actual data packet a device sends (input report) or receives
  (output/feature report). For a boot-protocol keyboard, an input report is
  8 bytes: modifier byte, reserved byte, and up to 6 keycodes.
- **Boot Protocol** — A simplified fixed HID report format for keyboards and
  mice that a BIOS/host can use before the full HID driver loads. Boot keyboards
  use the fixed 8-byte report above.
- **Usage / Usage Page** — Numeric codes in the report descriptor that give
  semantic meaning to fields (e.g. Usage Page 0x07 = Keyboard/Keypad, Usage Page
  0x0C = Consumer Control for media keys). Defined in the *HID Usage Tables*.
  Source: https://usb.org/document-library/hid-usage-tables-15
- **Composite device** — A single physical USB device exposing multiple
  interfaces/functions (e.g. a keyboard that also presents a mouse and a vendor
  interface). Relevant because a "keyboard" can silently include an extra HID
  or mass-storage interface.
- **Enumeration** — The process by which the host queries a newly attached USB
  device for its descriptors and assigns it a driver. Re-enumeration (a device
  disconnecting and reappearing, possibly with a different identity) is a
  behavioral signal of interest.
- **VID / PID** — Vendor ID / Product ID, 16-bit identifiers in the USB device
  descriptor. Trivially spoofable in firmware; not an authentication mechanism.

## Bluetooth terms

- **BR/EDR** — Bluetooth "Classic" (Basic Rate / Enhanced Data Rate). Keyboards
  historically use the Classic HID Profile (HIDP over L2CAP).
- **BLE (Bluetooth Low Energy)** — Modern low-power Bluetooth. HID over BLE uses
  the **HID over GATT Profile (HOGP)**.
- **HOGP / HID-over-GATT** — Bluetooth SIG profile for HID on BLE, built on the
  HID Service (HIDS) GATT service.
- **Central / Peripheral** — BLE roles. The host is usually the Central; the
  keyboard is the Peripheral. Note: the *GAP* role and the *HID* role can be
  decoupled, which is the crux of CVE-2023-45866.
- **Pairing / Bonding** — Establishing (pairing) and persisting (bonding) keys
  between two Bluetooth devices. Weak or "Just Works" pairing is a recurring
  problem for input devices.
- **Just Works** — An association model with no user-verified authentication;
  provides encryption but not authentication (vulnerable to MITM).

## Firmware / hardware terms

- **MCU** — Microcontroller unit; the processor inside a keyboard running its
  firmware.
- **Bootloader** — Early firmware responsible for loading/updating the main
  firmware; often the component that (should) verify firmware signatures.
- **Secure Boot** — Boot process where each stage cryptographically verifies the
  next before executing it, anchored in a hardware root of trust.
- **Measured Boot** — Boot process that *records* (measures) hashes of each
  stage into protected storage (e.g. a TPM/PCR) for later attestation, rather
  than blocking on verification.
- **Root of Trust (RoT)** — The hardware/firmware component that is inherently
  trusted and anchors all other trust decisions (e.g. immutable boot ROM +
  fused public key).
- **Attestation** — A device proving properties about itself (identity,
  firmware measurement) to a verifier, typically via signatures over a
  challenge.
- **Anti-rollback** — Preventing installation of older (vulnerable) firmware,
  usually via a monotonic version counter in fuses.

## Attack-direction taxonomy (used throughout the threat model)

- **DEVICE → HOST** — The peripheral attacks the computer (injection, malformed
  descriptors, parser exploits). The dominant HID threat class.
- **HOST → DEVICE** — The computer (or malware on it) attacks the peripheral
  (malicious firmware flashing, config abuse).
- **DEVICE → NETWORK** — The peripheral or its radio reaches network/other
  devices (rogue radio, exfiltration via a secondary channel).
- **COMPANION SOFTWARE → HOST** — The vendor's configuration/driver/RGB/macro
  software (often privileged, auto-updating, cloud-connected) attacks or
  weakens the host.
