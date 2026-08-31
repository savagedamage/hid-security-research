# Host Trust Model

The operating-system side of the HID boundary: how hosts decide to trust input
devices, what mechanisms exist to constrain them, and the limits of each.

Last reviewed: 2026-08-31

Primary sources:
- Linux USB authorization —
  https://docs.kernel.org/usb/authorization.html
- Linux input/HID subsystem — https://docs.kernel.org/hid/index.html
- USBGuard — https://usbguard.github.io/
- Microsoft device installation restrictions —
  https://learn.microsoft.com/windows/security/
- Apple Platform Security — https://support.apple.com/guide/security/

---

## 1. The default posture: trust on attach

By default, across major OSes, **attaching an input device is authorization to
use it.** The host enumerates it, binds a driver, and delivers its input to the
focused application as genuine user intent. There is:

- **No device authentication** (VID/PID/serial are labels, not proof).
- **No per-keystroke provenance** (an injected keystroke and a human one are
  identical by the time an app sees them).
- **No standard firmware attestation** for HID devices.

This is the "label, not boundary" problem from `hid-fundamentals.md` §5,
expressed from the OS side.

## 2. Mechanisms hosts *do* provide

| Mechanism | Platform | What it constrains | Limit |
| --- | --- | --- | --- |
| USB `authorized` flag / `authorized_default=0` | Linux | whether a device/interface is usable | attribute-based; spoofable |
| USBGuard policy | Linux | allow/block by VID/PID/serial/interface | attribute-based; no behavior |
| Device installation restrictions | Windows | which device classes/IDs may install | attribute-based |
| Removable-device / BadUSB-style controls | Windows (managed) | new HID / removable storage | attribute-based |
| "Allow accessory to connect" prompt | iOS/iPadOS, macOS | user consent for new USB accessory | one-time consent, not continuous |
| Bluetooth pairing consent | all | new BT/BLE device pairing | bypassable via forced/silent pairing bugs (CVE-2023-45866) |
| Lockdown / restricted modes | mobile | limits accessory capabilities in high-risk states | coarse-grained |

These are **real and useful** — deploying USBGuard or Windows device policy
meaningfully raises the bar against opportunistic BadUSB. But every one of them
decides on **device-declared attributes**, none observes **behavior**, and the
Bluetooth consent step has been bypassed in practice.

## 3. The trust decisions, enumerated

1. **Should this device exist?** (authorization) — USBGuard / OS policy.
2. **Is it what it claims?** (identity) — *no real answer today* for commodity
   HID; attributes are spoofable.
3. **Is its descriptor safe to parse?** (parser robustness) — kernel HID parser;
   historically buggy (see dataset).
4. **Is its behavior legitimate?** (behavioral) — *largely unaddressed by the
   OS*; this is the gap `hidwatch` and a HID firewall target.
5. **Should its companion software run privileged?** — general host security,
   often ignored for peripherals (COMPANION→HOST).

The project's software strategy maps directly onto this list: OSes handle #1 and
partly #3; we add **#4 (behavioral visibility)** first, then enforcement.

## 4. Boot-time and pre-OS trust

Boot-protocol keyboards are trusted by firmware/BIOS **before** OS protections
load. Full-disk-encryption passphrases, BIOS passwords, and boot menus are all
enterable by any device claiming to be a boot keyboard. Pre-OS input is a
smaller but real surface (threat DH-6) that host-level controls cannot mitigate.

## 5. Mobile vs desktop nuances

- **Mobile OSes** (Android/iOS) tend to gate USB accessories more aggressively
  (consent prompts, restricted modes) but expose large **Bluetooth** surfaces
  (CVE-2020-0022, CVE-2023-45866) because wireless input is the norm.
- **Desktop OSes** historically trust USB freely; managed environments can lock
  this down, unmanaged ones rarely do.

## 6. Design implication for this project

Because the host cannot answer "is this device what it claims?" and does not
observe behavior, the highest-leverage additions are:

1. **Behavioral observability** (`hidwatch`) — make HID behavior visible.
2. **Policy enforcement** at a point the host controls (a HID firewall, or
   OS-integrated policy).
3. **Real device identity/attestation** (trusted-keyboard research) — the only
   way to actually answer trust decision #2.

## 7. Cross-references

- `docs/usb-hid.md` §4 — host-side USB defenses in detail.
- `docs/detection.md`, `docs/mitigation.md`.
- `products/hid-firewall/architecture.md` — enforcement at the boundary.
- `data/cves/product-usbguard.yaml`.
