# USB HID: Enumeration, Descriptors, and Attack Surface

A technical walkthrough of how a USB HID device is discovered, described, and
bound by a host, with the security-relevant behavior highlighted at each step.

Last reviewed: 2026-08-31

Primary sources:
- USB-IF, *USB 2.0 Specification*, Ch. 9 (Device Framework / Standard Requests) —
  https://www.usb.org/document-library/usb-20-specification
- USB-IF, *Device Class Definition for HID 1.11* —
  https://www.usb.org/document-library/device-class-definition-hid-111
- Linux kernel USB authorization —
  https://docs.kernel.org/usb/authorization.html
- Linux kernel HID —
  https://docs.kernel.org/hid/index.html

---

## 1. Enumeration: how a device becomes usable

When a USB device is attached, the host performs **enumeration**:

1. **Reset & default address.** Device responds at address 0.
2. **GET_DESCRIPTOR (Device).** Host reads the 18-byte **device descriptor**:
   `idVendor` (VID), `idProduct` (PID), `bcdDevice`, `bDeviceClass`,
   `iManufacturer`/`iProduct`/`iSerialNumber` (string indices), etc.
3. **SET_ADDRESS.** Host assigns a unique address.
4. **GET_DESCRIPTOR (Configuration).** Host reads the **configuration
   descriptor** and everything nested under it: **interface descriptors**,
   **endpoint descriptors**, and class-specific **HID descriptors**.
5. **SET_CONFIGURATION.** Host activates a configuration; the kernel matches each
   interface to a **driver** by class/subclass/protocol (and sometimes VID/PID).
6. For HID interfaces: host issues **GET_DESCRIPTOR (Report)** to fetch the
   **report descriptor**, then parses it.
7. Device begins sending **input reports** on its interrupt IN endpoint.

Every value in steps 2–6 is **supplied by the device** and accepted without
authentication. Enumeration is the moment the host constructs its trust in the
device — entirely from device-provided bytes.

### 1.1 Security-relevant facts about enumeration

- **VID/PID are not identity.** They are 16-bit firmware fields, freely chosen.
  Allow-listing by VID/PID is defeated by spoofing (see threat DH-7).
- **Serial number is optional and spoofable.** A device may omit it or lie.
- **Re-enumeration** (unplug/replug in firmware, or `SET_CONFIGURATION` changes)
  lets a device change identity or add interfaces at runtime. A device can boot
  as benign and re-enumerate as a keyboard. This is a strong behavioral signal.
- **Timing matters.** A device that begins injecting input microseconds after
  enumerating did not wait for a human. `hidwatch` treats time-since-attach as a
  feature.

---

## 2. The descriptor hierarchy

```
Device Descriptor
 └─ Configuration Descriptor
     └─ Interface Descriptor  (bInterfaceClass=0x03 HID)
         ├─ HID Descriptor    (points to the Report Descriptor, gives its length)
         ├─ Endpoint Descriptor (Interrupt IN — input reports)
         └─ Endpoint Descriptor (optional Interrupt OUT — output reports)
```

Key fields for a HID keyboard interface:

| Field | Typical value | Meaning |
| --- | --- | --- |
| `bInterfaceClass` | `0x03` | HID |
| `bInterfaceSubClass` | `0x01` | Boot interface subclass |
| `bInterfaceProtocol` | `0x01` | Keyboard (`0x02` = Mouse) |
| `bNumEndpoints` | `1`–`2` | interrupt IN (+ optional OUT) |

A **mismatch** between claimed class and actual behavior, or an **interface
count** that does not match the device's stated purpose, is suspicious.

### 2.1 The HID (class) descriptor vs the report descriptor

Do not confuse them:

- The **HID descriptor** is a small fixed structure inside the interface that
  says "there is a report descriptor, and it is N bytes long."
- The **report descriptor** is the variable-length item stream describing report
  layouts (see `hid-fundamentals.md` §2.2). The host fetches it separately with
  `GET_DESCRIPTOR(Report)` and then **parses** it.

The declared length `N` and the actual parsed content have repeatedly
disagreed in buggy hosts — a fruitful source of OOB reads/writes.

---

## 3. The USB-HID attack surface, step by step

| Enumeration step | What the device controls | Attack (taxonomy) |
| --- | --- | --- |
| Device descriptor | VID/PID/class/serial | Impersonation, VID/PID spoofing (HID-01) |
| Configuration descriptor | number & type of interfaces | Unexpected/extra interfaces, composite abuse (HID-01, DH-5) |
| HID descriptor | declared report-descriptor length | Length/content mismatch → parser bugs (HID-04) |
| Report descriptor | field sizes, counts, usages | Malicious descriptor → OOB (HID-04): CVE-2014-3184, CVE-2025-38103, CVE-2025-39806, CVE-2025-55096 |
| Runtime reports | contents, timing, conformance | Keystroke injection (HID-02); malformed reports → driver bugs (HID-05): CVE-2020-0465, CVE-2026-43140 |
| Re-enumeration | new identity/interfaces | Runtime identity change (behavioral signal) |

### 3.1 Why the parser is special

The report-descriptor parser is the one place a host must **structurally
interpret** unbounded, attacker-chosen data. Recurring failure modes:

- Trusting the declared length (`bDescriptorLength`) over the actual stream.
- Fixed-size internal buffers vs. large `Report Count`/`Report Size`.
- `report_fixup` device-quirk handlers that assume a minimum descriptor size.
- Integer under/overflow computing report byte lengths (CVE-2025-55096 CWE-191).

A defensive intermediary that **normalizes and validates the descriptor** before
it reaches a fragile host parser is one of the strongest arguments for a HID
firewall (see `products/hid-firewall/architecture.md`).

---

## 4. Host-side defenses that already exist

- **USB device authorization (Linux):** the kernel exposes a per-device
  `authorized` flag under sysfs; setting `authorized_default=0` blocks new
  devices until explicitly authorized. Frameworks like **USBGuard** implement
  policy on top of this. See `data/cves/product-usbguard.yaml`.
  Source: https://docs.kernel.org/usb/authorization.html
- **Windows:** device-installation restriction policies and, on managed fleets,
  removable-device and "block new HID" style controls.
- **Interface-class allow-listing:** block interfaces claiming HID-keyboard on
  devices that shouldn't have them.

Limitations (why we still need behavioral monitoring): authorization decisions
are made on **device-declared attributes**, which are spoofable, and cannot
observe *behavior* (typing rate, report anomalies) after authorization.

---

## 5. Observing USB HID on Linux (for hidwatch)

Non-destructive observation sources available on Linux:

- **sysfs**: `/sys/bus/usb/devices/*` (descriptors, `authorized`, interface
  classes), `/sys/bus/hid/devices/*`.
- **`/dev/hidraw*`**: raw HID reports (requires permissions; read-only
  observation of report traffic).
- **`udev`/`libudev`**: attach/detach/enumeration events.
- **`usbmon`** (`/sys/kernel/debug/usb/usbmon`): USB packet capture for analysis.
- **`lsusb -v`**, **`usbhid-dump`**: descriptor dumps for fixtures.

`hidwatch` uses these read-only sources; it never writes to devices. See
`software/hidwatch/`. (In restricted environments without HID hardware, the same
parsers run against synthetic fixtures in `lab/fixtures/`.)

---

## 6. Cross-references

- `docs/hid-fundamentals.md` — usages, descriptors, reports.
- `docs/host-trust-model.md` — OS trust model and authorization.
- `docs/attack-surface.md` — consolidated catalog.
- `data/cves/` — the USB-HID parser CVEs cited above.
