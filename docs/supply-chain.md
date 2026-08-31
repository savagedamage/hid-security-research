# Supply-Chain Security for HID Devices

How malicious hardware or firmware can enter a peripheral before the user ever
receives it — the highest-impact, lowest-observability class in the threat
model.

Last reviewed: 2026-08-31

Primary sources:
- NIST SP 800-161r1, *Cybersecurity Supply Chain Risk Management Practices* —
  https://doi.org/10.6028/NIST.SP.800-161r1
- CISA ICT Supply Chain Risk Management —
  https://www.cisa.gov/topics/supply-chain-security
- NSA ANT catalog (Der Spiegel, 2013) —
  https://www.spiegel.de/international/world/catalog-reveals-nsa-has-back-doors-for-numerous-devices-a-940994.html

---

## 1. Where compromise can be introduced

```
 design → fab/assembly → firmware load → distribution → resale/refurb → user
   |          |               |               |              |
 malicious  implanted     backdoored      interdiction   tampered      (evil maid
 IP/chip    hardware      firmware        in transit     returns)       after delivery)
```

Each arrow is an opportunity. Taxonomy: **HID-08 Supply-Chain Implant**,
overlapping **HID-03 Malicious Firmware** and **HID-13 Physical Tampering**.

## 2. Evidence: this is real, not hypothetical

- **NSA ANT catalog / COTTONMOUTH** (`documented`) — leaked catalog describing
  USB hardware implants with covert RF for C2/exfil. Nation-state grade, but
  concrete proof the class exists.
  See `data/cves/incident-nsa-ant-cottonmouth.yaml`.
- **O.MG cable** (`demonstrated`) — a *commodity* malicious cable with an
  embedded Wi-Fi MCU; shows the capability has commoditized and that
  substitution during distribution is cheap.
  See `data/cves/poc-omg-cable.yaml`.
- **BadUSB** (`demonstrated`) — unsigned reflashable firmware means a device can
  be weaponized anywhere along the chain, including at a "trusted" reseller.

We label commodity-scale *covert* supply-chain implantation of ordinary
keyboards as `inferred` (plausible and demonstrated in principle) rather than
claiming a specific documented mass incident we cannot cite.

## 3. Why it's the worst class for defenders

- **Pre-compromised on arrival** — no "before" state to compare against.
- **Scales** — one poisoned firmware build or update server → many devices.
- **Often invisible to the host** — especially with an independent radio
  (DEVICE→NETWORK) that bypasses host network monitoring.
- **Trust laundering** — a reputable brand on the label transfers unearned trust
  to compromised internals.

## 4. Defenses (in rough order of assurance)

1. **Provenance & vendor assurance** — buy from vendors with documented secure
   development, signed firmware, and SBOM/firmware transparency (rare today,
   which is itself a finding).
2. **Tamper-evident packaging & custody** — detect distribution/interdiction and
   evil-maid tampering.
3. **Reproducible / transparent firmware builds** — let independent parties
   verify the firmware image matches published source (see secure-keyboard
   research). Almost nonexistent for consumer HID.
4. **Physical inspection / X-ray / RF scanning** — high-assurance environments
   only; detects hardware implants and hidden radios.
5. **Behavioral monitoring** (`hidwatch`) and **egress monitoring** — catches
   *some* effects (injection, unexpected interfaces) even when provenance is
   unknown; does **not** catch an independent-radio exfil channel.
6. **Prefer simple, radio-free, open-firmware devices** in sensitive settings.

## 5. The uncomfortable gap

There is currently **no practical, standardized way for an ordinary user to
verify that a keyboard's hardware and firmware are what the vendor claims.** This
gap is:

- a core motivation for the **trusted-keyboard** research
  (`products/trusted-keyboard/`), and
- a genuine product/differentiation opportunity (`docs/business-opportunity.md`):
  firmware transparency + attestation for input devices.

## 6. Cross-references

- `docs/firmware-security.md` — the firmware mechanics this abuses.
- `hardware/architecture/secure-keyboard.md` — supply-chain-verifiable design.
- `THREAT_MODEL.md` §4 — firmware & supply-chain.
