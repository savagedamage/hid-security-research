# Firmware Security

The device side of the HID trust problem: MCUs, bootloaders, firmware updates,
and debug interfaces. This is where a benign-looking peripheral becomes (or is
prevented from becoming) a persistent threat.

Last reviewed: 2026-08-31

Primary sources:
- NIST SP 800-193, *Platform Firmware Resiliency Guidelines* —
  https://doi.org/10.6028/NIST.SP.800-193
- NIST SP 800-147 / 800-155 (BIOS protection / integrity measurement) —
  https://csrc.nist.gov/publications
- SR Labs BadUSB — https://srlabs.de/bites/usb-peripherals-turn/

---

## 1. What's inside a keyboard

A typical keyboard contains:

- An **MCU** (microcontroller) running firmware — scans the key matrix, builds
  HID reports, drives the USB/Bluetooth interface.
- **Non-volatile storage** (flash/EEPROM) for firmware and configuration
  (macros, RGB profiles, key remaps).
- Optionally a **radio** (Bluetooth/BLE/proprietary 2.4 GHz) and its own
  firmware.
- Optionally a **bootloader** and a **firmware-update** path (DFU over USB,
  vendor tool, or OTA).
- Often **debug pads** (SWD/JTAG/UART) on the PCB.

Each of these is an asset and an attack surface.

## 2. The firmware trust chain (and where it breaks)

Ideal chain: immutable boot ROM → verifies bootloader → verifies application
firmware, each stage anchored in a hardware **root of trust**. Reality for
commodity keyboards:

| Property | Commodity reality | Consequence |
| --- | --- | --- |
| Signed firmware | often absent | any firmware can be flashed (BadUSB precondition) |
| Secure boot | rare | no verification that running firmware is authentic |
| Anti-rollback | rare | downgrade to a vulnerable version (HID-10) |
| Locked debug ports | often unlocked | firmware extraction/replacement via SWD/JTAG/DFU (HID-14) |
| Measured boot / attestation | essentially never | host cannot verify device firmware identity |

The single most important firmware fact for HID security: **most consumer input
devices accept unsigned firmware and ship with accessible debug interfaces.**
That is what makes BadUSB (`data/cves/poc-badusb-2014.yaml`) a class of attack
rather than a one-off.

## 3. Firmware update abuse (HID-10)

Failure modes we catalog:

- **Unsigned images** — device flashes whatever it's given.
- **Weak/absent signature verification** — signature present but not enforced,
  or verifiable with a leaked/hardcoded key.
- **No anti-rollback** — attacker installs an older, vulnerable firmware to
  re-open a fixed hole (a monotonic version counter in fuses prevents this).
- **Compromised update server / channel** — one server compromise → many
  malicious devices (supply-chain amplification; see `supply-chain.md`).
- **Downgrade of the *host* companion updater** — see `COMPANION_TO_HOST`.

## 4. Debug interfaces (HID-14)

SWD/JTAG/UART/DFU are invaluable for development and dangerous in production if
left open:

- **Firmware extraction** → reverse engineering, key recovery.
- **Firmware replacement** → turn the device malicious (HOST→DEVICE, then the
  device acts DEVICE→HOST persistently).
- **Runtime control** → halt/patch the MCU.

Defense: disable/lock debug in production (read-out protection / debug
authentication), and treat any exposed debug pad as a supply-chain and
evil-maid risk.

## 5. Why firmware attacks are strategically valuable to attackers

A firmware implant:

- **Survives OS reinstall** and disk wipe — it lives in the peripheral.
- **Is invisible to host AV/EDR** if it uses a secondary radio (see
  `data/cves/incident-nsa-ant-cottonmouth.yaml`, `poc-omg-cable.yaml`).
- **Converts a one-time host compromise into persistence** (HOST→DEVICE flashing
  → durable DEVICE→HOST capability).

This is why the "secure keyboard" research (`hardware/`,
`products/trusted-keyboard/`) focuses on secure boot, signed/attested firmware,
anti-rollback, and locked debug: they attack the *precondition* of the whole
malicious-firmware class.

## 6. What a defender can realistically verify today

Honestly: **very little, from the host, for commodity devices.** There is no
standard HID firmware attestation. Practical measures:

- Track firmware **versions** where the vendor exposes them (patch known device
  CVEs like CVE-2024-0230).
- Prefer devices with documented secure-boot/signed-firmware (rare in consumer,
  more common in high-assurance).
- Physically control custody of sensitive keyboards (tamper evidence).
- Monitor **behavior** (`hidwatch`) since firmware identity is unavailable.

## 7. Cross-references

- `docs/supply-chain.md` — how malicious firmware/hardware gets in at scale.
- `hardware/architecture/secure-keyboard.md` — the trustworthy-device design.
- `data/cves/` — BadUSB, O.MG, NSA ANT, CVE-2024-0230, CVE-2016-6257.
- `THREAT_MODEL.md` §4 — firmware & supply-chain threats.
