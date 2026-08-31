# HID Threat Model

A structured threat model for keyboards and other Human Interface Devices (HID),
covering USB, Bluetooth BR/EDR, and Bluetooth Low Energy transports, plus the
firmware, companion-software, and supply-chain layers around them.

- **Status:** living document
- **Last reviewed:** 2026-08-31
- **Scope:** input peripherals (keyboards, mice, game controllers, barcode
  scanners, presenters, composite devices) and the host/software that trusts
  them.
- **Methodology:** informal STRIDE-influenced analysis organized primarily by
  **attack direction** and **transport**, cross-referenced to the attack
  taxonomy in `data/attack-taxonomy/taxonomy.yaml`.

> **Evidence discipline.** Threats below are tagged with the evidence
> vocabulary from `GLOSSARY.md` (`documented`, `demonstrated`, `reported`,
> `inferred`, `theoretical`). Concrete public examples are cited to
> `data/cves/`. Where a threat is only theoretical, it is labeled as such.

---

## 0. Why HID is a security boundary

Operating systems treat input devices as **trusted sources of user intent**.
A keystroke from a keyboard is, by design, indistinguishable from a keystroke a
human meant to type. This creates a foundational asymmetry:

- The **host trusts the device** to describe itself honestly (via descriptors)
  and to report only genuine human input.
- The device is, in reality, a **computer**: it has an MCU, firmware, often a
  radio, sometimes an update mechanism, and frequently privileged companion
  software on the host.
- None of the trust the host extends is **verified**. VID/PID are not
  authenticated. There is no standard attestation of firmware. "It's a keyboard"
  is asserted by the device, not proven.

The security-relevant consequence: **anything that can present itself as a
keyboard can type**, and typing is a general-purpose control channel over the
host (open a shell, download a payload, change settings). This is the root of
the entire HID threat landscape.

---

## 1. Assets, actors, and trust boundaries

### 1.1 Assets we want to protect

| Asset | Why it matters |
| --- | --- |
| Host integrity/confidentiality | Injected input can run arbitrary commands as the logged-in user. |
| User keystrokes | Contain passwords, messages, secrets. |
| Host HID/USB/Bluetooth stack memory safety | Parser/driver bugs → kernel compromise. |
| Device firmware integrity | A trustworthy device must stay trustworthy across updates. |
| Pairing/bonding keys | Compromise enables spoofing/decryption. |
| User attention / consent | Many attacks rely on the user not noticing an extra device or a pairing. |

### 1.2 Threat actors (illustrative)

| Actor | Capability | Typical goal |
| --- | --- | --- |
| Opportunistic physical attacker | Brief physical access ("evil maid", drop attack) | Plant a BadUSB / rogue device |
| Supply-chain attacker | Influence over manufacturing/distribution/updates | Implant at scale, pre-compromise |
| Proximate radio attacker | Within Bluetooth range | Spoof/inject over BT/BLE |
| Malware already on host | Code execution on host | Attack device firmware / companion SW; use device as pivot |
| Malicious/compromised vendor | Controls firmware + companion software + cloud | Telemetry, backdoors, forced updates |

### 1.3 Trust boundaries (where trust is extended without verification)

```
                         (T1) physical / supply chain
                                     |
   +----------------+   (T2) wire/radio   +----------------+   (T3) syscall/driver
   |   HID DEVICE   |==================== |   HOST STACK   |======================> OS / apps
   | MCU + firmware |   USB / BT / BLE    | USB+HID+BT stk |   input events
   +----------------+                     +----------------+
          |                                      ^
          | (T4) radio / secondary channel        | (T5) companion software (often privileged)
          v                                      |
      NETWORK / other devices  <----------------- vendor app / driver / cloud updater
```

- **T1** — Device provenance. Trusted implicitly; rarely verified.
- **T2** — The transport. VID/PID/descriptors are asserted, not authenticated.
- **T3** — Host parsing/driver layer. Must treat device data as hostile but
  historically has not (see parser CVEs).
- **T4** — Any radio or secondary channel on the device.
- **T5** — Companion software: frequently runs with high privilege, auto-updates
  from the internet, and is a large, often-overlooked attack surface.

---

## 2. Attack directions (the primary organizing axis)

This project insists on distinguishing four directions because they have
different attackers, mitigations, and detectability.

### 2.1 DEVICE → HOST  *(the dominant class)*

The peripheral attacks the computer. Sub-classes:

| # | Threat | Evidence | Example / reference |
| --- | --- | --- | --- |
| DH-1 | **Keystroke injection** — a device types commands the user never intended. | demonstrated | BadUSB (Nohl & Lell, 2014); USB Rubber Ducky (commercial). `data/cves/` → `poc-badusb-2014`, `poc-rubber-ducky` |
| DH-2 | **Device impersonation** — a device (or repurposed one) claims to be a keyboard to gain the input channel. | demonstrated | BadUSB reprogramming a USB controller to add a HID interface. |
| DH-3 | **Malicious HID descriptor** — a hostile report descriptor triggers host-side parser bugs. | documented | CVE-2014-3184 (Linux `report_fixup` OOB); CVE-2025-38103 (`usbhid_parse` OOB). |
| DH-4 | **Malformed HID reports** — reports that violate the declared descriptor, hitting driver bounds bugs. | documented | CVE-2020-0465 (`hid-multitouch` OOB write, Android). |
| DH-5 | **Unexpected/extra interfaces** — a "keyboard" that also exposes a second HID, mass storage, or vendor interface. | demonstrated | Composite BadUSB devices; O.MG cable class. |
| DH-6 | **Boot-protocol / early-boot input** — input accepted before full OS protections load. | inferred | Boot keyboards are trusted by firmware/BIOS; pre-OS injection surface. |
| DH-7 | **VID/PID spoofing to satisfy allow-lists** — defeating naive device allow-listing. | documented | VID/PID are unauthenticated firmware fields. |

**Key insight:** DH-1/DH-2 need *no software vulnerability at all* — they abuse
the host working exactly as designed. DH-3/DH-4 exploit implementation bugs.
Defenses differ accordingly (policy/behavioral vs. patching).

### 2.2 HOST → DEVICE

Malware (or a malicious/authorized host tool) attacks the peripheral.

| # | Threat | Evidence | Example / reference |
| --- | --- | --- | --- |
| HD-1 | **Malicious firmware flashing** — host writes attacker firmware to the device (unsigned/weak update). | demonstrated | BadUSB relies on reflashable, unsigned USB controller firmware. |
| HD-2 | **Firmware downgrade / rollback** — install an older, vulnerable firmware to re-open a fixed hole. | theoretical→documented | Anti-rollback is often absent; downgrade is a general firmware-update weakness. |
| HD-3 | **Config/EEPROM abuse** — reprogram device settings (e.g. macros) to weaponize a benign device. | inferred | Macro keyboards store host-writable key sequences. |
| HD-4 | **Debug-interface abuse from host** — use exposed JTAG/SWD/DFU to take over the MCU. | documented | Many consumer MCUs ship with debug ports unlocked. |

**Why it matters:** HOST → DEVICE turns a *one-time* host compromise into a
*persistent* implant that survives OS reinstall and can then act DEVICE → HOST.
This is the bridge that makes firmware attacks strategically valuable.

### 2.3 DEVICE → NETWORK

The peripheral (or a radio in it) reaches the network or other devices.

| # | Threat | Evidence | Example / reference |
| --- | --- | --- | --- |
| DN-1 | **Rogue/undisclosed radio** — a wired-looking device contains a cellular/Wi-Fi/BT radio for out-of-band C2 or exfil. | demonstrated | O.MG cable (Wi-Fi implant in a cable); NSA "COTTONMOUTH" (documented, ANT catalog). |
| DN-2 | **Exfiltration via secondary channel** — captured keystrokes leave via the device's radio, not the host network. | demonstrated | Same implant class as DN-1. |
| DN-3 | **Cloud-dependent peripheral phoning home** — legitimate but privacy/attack-relevant telemetry & update channels. | reported | Many "smart" keyboards/companion apps contact vendor cloud. |

**Why it matters:** DEVICE → NETWORK **bypasses host network monitoring
entirely** if the radio is independent of the host. This is the hardest class to
detect from the host and a major motivation for a hardware HID firewall that can
observe the physical device.

### 2.4 COMPANION SOFTWARE → HOST

The vendor's driver/configurator/RGB/macro app attacks or weakens the host.

| # | Threat | Evidence | Example / reference |
| --- | --- | --- | --- |
| CS-1 | **Vulnerable privileged driver/service** — companion software running as admin/root with exploitable bugs. | documented | Gaming-peripheral drivers have repeatedly shipped LPE bugs (industry pattern). |
| CS-2 | **Insecure auto-update channel** — companion app updates over weak/unauthenticated transport → RCE. | documented | Update-channel weaknesses are a recurring companion-software issue. |
| CS-3 | **Excessive privilege / kernel drivers** — RGB/fan/macro apps shipping signed kernel drivers usable by other malware ("BYOVD"). | reported | Vulnerable signed drivers are abused in BYOVD attacks broadly. |
| CS-4 | **Telemetry / data collection** — companion app harvests data beyond device function. | reported | Privacy-relevant; expands attack surface & data exposure. |

**Why it matters:** The *keyboard* may be innocent while its *software* is the
real risk. A HID threat model that ignores companion software misses a large
share of realized incidents.

---

## 3. Transport-specific analysis

### 3.1 USB / wired HID

- **Enumeration trust:** the host builds trust from device-supplied descriptors
  at plug-in; there is no cryptographic device identity in USB HID.
- **Re-enumeration:** a device can disconnect and reappear as something else;
  composite devices can add interfaces. Behavioral signal: unexpected
  re-enumeration or interface changes.
- **Parser surface:** report-descriptor and report parsing in the kernel is a
  recurring memory-safety hotspot (see `data/cves/` Linux HID entries).
- **Mitigations:** USB authorization / `authorized_default=0` (Linux),
  USBGuard, Windows device-installation policy, physical port control, and
  behavioral monitoring (`hidwatch`).

### 3.2 Bluetooth BR/EDR (Classic) HID

- **HIDP over L2CAP.** Historically the profile for BT keyboards.
- **Pairing weaknesses:** legacy pairing and downgraded key strength enable
  MITM/brute force (KNOB, CVE-2019-9506, `documented`).
- **Stack memory safety:** the host BT stack parses attacker-adjacent data
  (BlueBorne class — e.g. CVE-2017-14315 iOS; CVE-2020-0022 Android BlueFrag).
- **Authorization flaws:** improper access control in BlueZ (CVE-2020-0556,
  CVE-2020-24490).

### 3.3 Bluetooth Low Energy (BLE) HID over GATT (HOGP)

- **Role decoupling:** BLE lets a device act as a HID **Peripheral** and, under
  flawed host logic, get its HID reports accepted **without the user
  authorizing** it in the Central role. This is exactly **CVE-2023-45866**
  (BlueZ) and the family of "unauthenticated Bluetooth keyboard injection" bugs
  that also affected Android, Linux, macOS/iOS, and Windows stacks
  (`documented`, `demonstrated` by SkySafe/Marc Newlin, 2023). See
  `data/cves/cve-2023-45866.yaml`.
- **"Just Works" pairing:** encryption without authentication → MITM/spoofing.
- **Why BLE HID is uniquely dangerous:** low power + cheap radios + role
  decoupling + often-silent pairing = proximate keystroke injection with little
  or no user interaction.

---

## 4. Firmware & supply-chain layer

| # | Threat | Evidence |
| --- | --- | --- |
| FW-1 | Unsigned/insecure firmware update → arbitrary firmware (BadUSB precondition). | demonstrated |
| FW-2 | Downgrade/rollback to vulnerable firmware (no anti-rollback). | inferred/documented |
| FW-3 | Exposed debug interfaces (JTAG/SWD/DFU) enabling firmware extraction/replacement. | documented |
| FW-4 | Insecure bootloader (no verification, or verification bypass). | documented |
| FW-5 | Supply-chain implant during manufacturing/distribution (hardware or firmware). | demonstrated (NSA ANT catalog, documented); commodity scale = inferred |
| FW-6 | Compromised update infrastructure delivering malicious firmware to many devices at once. | reported (analogous to broader software supply-chain incidents) |

Supply-chain compromise is the highest-impact, lowest-observability class: it
can preload a device to be malicious before the user ever plugs it in, and it
scales.

---

## 5. Host-side software layer

| # | Threat | Evidence | Example |
| --- | --- | --- | --- |
| HS-1 | HID report/descriptor parser memory-safety bugs. | documented | CVE-2014-3184, CVE-2020-0465, CVE-2025-38103, CVE-2025-39806 |
| HS-2 | Bluetooth stack memory-safety bugs (RCE-capable). | documented | CVE-2017-14315, CVE-2020-0022 |
| HS-3 | Bluetooth authorization/access-control flaws. | documented | CVE-2020-0556, CVE-2020-24490, CVE-2023-45866 |
| HS-4 | Driver spoofing / signature issues. | documented | CVE-2024-21306 (MS Bluetooth driver spoofing) |
| HS-5 | Embedded/RTOS USB-HID stacks in *other products* (IoT hosts). | documented | CVE-2025-55096 (ThreadX USBX HID descriptor OOB), CVE-2025-68656 (ESP-IDF USB-HID UAF) |

Takeaway: HID parsing bugs are not a solved historical problem — they recur
across kernels and RTOSes year after year. A defensive intermediary that
validates descriptors/reports *before* they reach a fragile host parser has real
value.

---

## 6. Attacks requiring NO software vulnerability (design-inherent)

It is worth isolating the threats that patching cannot fix because they exploit
intended behavior:

- **Keystroke injection (DH-1)** — the host is *supposed* to accept keystrokes.
- **Device impersonation (DH-2)** — the host is *supposed* to trust "I am a
  keyboard."
- **Extra interfaces (DH-5)** — composite devices are a legitimate feature.

These require **policy, behavioral detection, physical control, or device
authorization**, not just patches. They are the strategic justification for
`hidwatch` (visibility) and the HID firewall (enforcement).

---

## 7. Out of scope (for this threat model)

- Acoustic / EM side-channel keystroke recovery from a *benign* keyboard
  (that's a keyboard-emanation problem, tracked separately if at all).
- General host malware unrelated to peripherals.
- Physical destruction / "USB Killer" style electrical attacks (a hardware
  safety concern, not an information-security HID concern) — noted but not
  modeled in depth.

---

## 8. Mitigation summary (mapped to directions)

| Direction | Primary mitigations |
| --- | --- |
| DEVICE → HOST | USB/Bluetooth device authorization (USBGuard, Linux authorized_default, Windows policy), behavioral monitoring (`hidwatch`), robust/fuzzed host parsers, HID firewall enforcement. |
| HOST → DEVICE | Signed firmware + secure boot on devices, anti-rollback, locked debug ports, least-privilege for flashing tools. |
| DEVICE → NETWORK | Hardware inspection, RF monitoring, disallow undisclosed radios, network egress monitoring, prefer wired/radio-disabled devices in sensitive settings. |
| COMPANION SOFTWARE → HOST | Least privilege, avoid kernel drivers, verified update channels, telemetry transparency, or avoid companion software entirely. |

See `docs/mitigation.md` and `docs/detection.md` for the detailed treatment.

---

## 9. Cross-references

- Attack taxonomy: `data/attack-taxonomy/taxonomy.yaml`
- Verified vulnerability dataset: `data/cves/`
- Host trust model deep-dive: `docs/host-trust-model.md`
- Attack-surface catalog: `docs/attack-surface.md`
- Firewall design (enforcement): `products/hid-firewall/architecture.md`
