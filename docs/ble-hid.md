# BLE HID: HID over GATT Profile (HOGP)

How keyboards, mice, and other HID devices work over **Bluetooth Low Energy**,
and why role decoupling makes this path uniquely prone to unauthorized keystroke
injection.

Last reviewed: 2026-08-31

Primary sources:
- Bluetooth SIG, *HID over GATT Profile (HOGP) 1.0* and *HID Service (HIDS)* —
  https://www.bluetooth.com/specifications/specs/
- Bluetooth SIG, *Core Specification* (GAP/GATT/SMP) —
  https://www.bluetooth.com/specifications/specs/
- Marc Newlin / SkySafe, CVE-2023-45866 notes —
  https://github.com/skysafe/redteam-notebook/blob/main/CVE-2023-45866.md

BLE is a **different stack** from Bluetooth Classic (`bluetooth-hid.md`), even
though both are "Bluetooth." Modern low-power keyboards commonly use BLE/HOGP.

---

## 1. The stack

```
  OS input subsystem
      ^
  HOGP  (HID over GATT Profile)     <- maps GATT characteristics to HID reports
      ^
  HID Service (HIDS) over GATT      <- Report Map (== HID report descriptor),
      ^                                Report characteristics (input/output/feature)
  ATT / GATT                        <- attribute protocol
      ^
  SMP (Security Manager Protocol)   <- pairing, keys, bonding
      ^
  GAP (Generic Access Profile)      <- roles: Central / Peripheral, advertising
      ^
  BLE Link Layer / radio
```

Key mapping to remember:

- The **Report Map characteristic** in the HID Service **is** a HID report
  descriptor — the same byte format as USB (`hid-fundamentals.md` §2.2). So the
  **host HID parser attack surface applies to BLE too.**
- **Report characteristics** carry the actual input/output/feature reports.

---

## 2. GAP roles vs HID roles — the crux of BLE HID risk

BLE separates several role concepts that are **not** locked together:

- **GAP role:** Central (usually the host) vs Peripheral (usually the keyboard).
- **HID role:** HID Host vs HID Device.
- **Security state:** paired/bonded vs not; authenticated vs Just Works.

A **HID Device (Peripheral)** can, under flawed host logic, get its **HID input
reports accepted by the Host without the Central-side user authorizing that
device**. That decoupling — "you can be positioned to send keystrokes before the
human agrees to trust you" — is the mechanism behind **CVE-2023-45866** and the
broader unauthenticated-Bluetooth-keyboard-injection family.

This is why the taxonomy has a dedicated class **HID-06 (Bluetooth Unauthorized
Input)**: it is a recurring, structural problem, not a one-off bug.

---

## 3. Pairing in BLE (SMP)

- **LE Legacy Pairing** — older; the "Just Works" variant is not MITM-resistant,
  and legacy pairing has known key-derivation weaknesses.
- **LE Secure Connections** — uses ECDH (P-256); stronger, MITM-resistant when
  an authenticated method (Numeric Comparison / Passkey / OOB) is used.
- **Just Works** — again, encryption without authentication. Extremely common on
  input devices lacking a display, and a persistent weak point.

For a keyboard, "Just Works" means the encrypted channel is not proof of *who*
you're talking to — enabling spoofing/MITM (taxonomy HID-07).

---

## 4. Why BLE HID is uniquely dangerous

1. **Cheap, low-power radios** make spoofed peripherals trivial to build.
2. **Advertising + connectable hosts** mean a host may accept connections with
   little friction.
3. **Role decoupling** (§2) allows input acceptance ahead of/without user
   authorization.
4. **Silent or minimal pairing UX** on some platforms means the user may not
   notice a keyboard being added.
5. **Same parser risk** as USB HID via the Report Map.

Combined: **proximate, low-interaction keystroke injection** — the worst-case
property for an input transport. This is the single strongest argument in the
threat model for treating wireless HID as higher-risk than wired.

---

## 5. Detection & mitigation

Detection (host-observable):
- New HOGP/HID Service connections from unknown addresses.
- Pairing/bonding events the user did not initiate.
- Report Map (descriptor) anomalies — same descriptor validation as USB.
- Input immediately following a new BLE HID connection.

Mitigation:
- Patch host stacks (CVE-2023-45866 and platform equivalents from Dec 2023).
- Require **authenticated** LE Secure Connections pairing for input devices;
  avoid Just Works.
- Do not remain connectable/advertising-acceptant in hostile RF environments.
- Prefer wired input where the threat model warrants it.
- A HID firewall on the wired side cannot see a BLE injection into the host
  directly — this is a limitation worth stating plainly (see
  `products/hid-firewall/architecture.md` §limitations).

---

## 6. A note on address privacy

BLE supports **Resolvable Private Addresses (RPA)** to reduce tracking. This is
a privacy feature, not an authentication feature — it does not stop a spoofed
keyboard from being *accepted*; it only changes how addresses are observed.
Don't conflate address privacy with device trust.

---

## 7. Cross-references

- `docs/bluetooth-hid.md` — the BR/EDR path (different stack).
- `docs/hid-fundamentals.md` — the shared report/descriptor model.
- `THREAT_MODEL.md` §3.3 — BLE transport threats.
- `data/cves/cve-2023-45866.yaml` — flagship HOGP unauthorized-input CVE.
