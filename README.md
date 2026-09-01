# HID Security Research

**Can we make human-input devices observable, verifiable, controllable, and
trustworthy?**

Keyboards and other HID devices are trusted input channels with a surprisingly
large attack surface. A keyboard is also a computer: MCU, firmware, bootloader,
update path, optional radios, and often privileged companion software. Hosts
normally accept its self-declared identity and treat its reports as user intent.
VID/PID are not authentication, commodity HID has no standard firmware
attestation, and keystroke injection requires no OS vulnerability.

This is a defensive research and engineering project: a cited knowledge base,
structured threat/vulnerability data, a working observation prototype, a safe
synthetic lab corpus, and realistic designs for an inline HID gateway and a
verifiable keyboard.

> **Current status: research foundation + alpha software, not a security
> product.** `hidwatch` parses descriptors and analyzes synthetic/session data;
> it does not yet provide live hidraw monitoring or enforcement. No hardware has
> been built or tested. See [Roadmap](ROADMAP.md).

## Architecture

```
Keyboard / HID device
        │ descriptors + reports (untrusted)
        ▼
 ┌──────────────────────┐       future inline path
 │ hidwatch             │       ┌──────────────────────┐
 │ inspect · parse      │──────▶│ HID Security Gateway │──────▶ Host
 │ analyze · explain    │       │ validate · policy    │
 └──────────────────────┘       │ rate-limit · log     │
        │                        └──────────────────────┘
        ▼
 cited dataset + synthetic corpus       future attested keyboard
```

The threat model distinguishes four directions because controls differ:

- **DEVICE → HOST:** impersonation, injection, malicious descriptors/reports,
  parser and driver exploitation.
- **HOST → DEVICE:** unsigned flashing, rollback, configuration/debug abuse.
- **DEVICE → NETWORK:** hidden radios, out-of-band exfiltration, telemetry.
- **COMPANION SOFTWARE → HOST:** vulnerable privileged drivers, updaters, cloud
  clients, and supply-chain compromise.

Read the full [Threat Model](THREAT_MODEL.md) and
[Attack Surface](docs/attack-surface.md).

## What exists today

| Area | Implemented | Planned / not claimed |
| --- | --- | --- |
| Research | Protocol docs, serious threat model, 15-class taxonomy, cited sources | Continuous review and broader corpus |
| Dataset | 21 schema-validated records: 14 CVEs + clearly labeled research/PoC/incident/product entries; generated Markdown/CSV index | Comprehensive coverage (not yet) |
| `hidwatch` | Stdlib-only core, defensive report-descriptor parser, correct read-only Linux sysfs inventory, attach/detach/change monitor, explainable risk analyzer, CLI | Live hidraw metrics, optional udev delivery, record, enforcement |
| Lab | Six synthetic scenarios; hostile parser tests; no real keystrokes | Authorized multi-device physical testing |
| Hardware | Detailed gateway and secure-keyboard architecture | No prototype or certification |
| Quality | 100 tests, dataset/schema validation, green CI | Production hardening and external audit |

## Quick start

```bash
# Research data
python -m pip install pyyaml jsonschema
python scripts/research-tools/validate_dataset.py
python scripts/research-tools/build_index.py --check

# hidwatch (works without hardware using safe synthetic fixtures)
cd software/hidwatch
python -m pip install -e ".[dev]"
hidwatch inspect --demo benign-keyboard
hidwatch analyze --demo badusb-flashdrive  # exits 2 because risk is CRITICAL
pytest
```

Example detection reasons include: an alleged flash drive exposing a boot
keyboard interface, input 10 ms after enumeration, impossible 120 keys/s,
machine-perfect timing, descriptor anomalies, and composite storage+keyboard.
Scores are explainable; no opaque model is involved.

## Research and documentation

- [Introduction](docs/introduction.md) · [HID fundamentals](docs/hid-fundamentals.md)
- [USB HID](docs/usb-hid.md) · [Bluetooth HID](docs/bluetooth-hid.md) ·
  [BLE/HOGP](docs/ble-hid.md)
- [Firmware security](docs/firmware-security.md) ·
  [Supply chain](docs/supply-chain.md) · [Host trust](docs/host-trust-model.md)
- [Detection](docs/detection.md) · [Mitigation](docs/mitigation.md)
- [Dataset index](data/cves/INDEX.md) ·
  [Attack taxonomy](data/attack-taxonomy/taxonomy.yaml)
- [HID firewall architecture](products/hid-firewall/architecture.md) ·
  [Secure keyboard architecture](hardware/architecture/secure-keyboard.md)
- [Business opportunity](docs/business-opportunity.md) ·
  [Future research](docs/future-research.md)

## Important findings so far

1. **Injection is often intended behavior, not exploitation.** Patching cannot
   remove a keyboard's ability to type; policy and provenance are required.
2. **Host parsing remains active attack surface.** HID descriptor/report bugs
   continue across Linux, Android, RTOS/embedded stacks, including recent
   records in the dataset.
3. **Wireless HID inherits parser risk and adds pairing/authorization plus a
   remotely reachable stack.** CVE-2023-45866 demonstrates no-interaction
   Bluetooth keyboard injection.
4. **Host-only defense has blind spots.** A wired firewall cannot block BLE
   injection into the host or an implant's independent radio.
5. **The realistic commercial wedge is software visibility and enterprise
   policy, not an immediate consumer appliance.** Hardware should follow a
   measured compatibility corpus and design-partner demand.

## Research quality and responsible use

We do not invent CVEs or incidents. Entries distinguish `CVE`, academic
research, proof of concept, documented incident, security product, and
 theoretical threat. Claims use the evidence vocabulary **observed / documented /
demonstrated / reported / inferred / theoretical**, carry source URLs,
confidence, and review dates. Primary sources are preferred and disagreement is
recorded.

This project does not ship malware, credential theft, persistence, C2, or
weaponized injection payloads. Only test devices and systems you own or are
explicitly authorized to test. Real HID captures are excluded because they may
contain credentials. Read [Security Policy](SECURITY.md) and
[Contributing](CONTRIBUTING.md).

## License

Software: MIT. Documentation and original datasets: CC BY 4.0; third-party facts
and advisory material remain subject to their source terms. See [LICENSE](LICENSE).
