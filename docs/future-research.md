# Future Research

Open questions and research directions for making the HID layer trustworthy.
Distinct from `../ROADMAP.md` (which schedules concrete engineering); this page
is about the harder, more open problems.

Last reviewed: 2026-08-31

---

## 1. Device identity & attestation for commodity HID

**Problem:** there is no standard way for a host to verify a HID device is what
it claims. VID/PID are labels.

**Directions:**
- A lightweight **HID device attestation** scheme (device signs a host challenge
  with a manufacturer-provisioned key; host verifies against a transparency log).
- Reuse of existing identity primitives (DICE/RIoT, TPM-style, FIDO-like
  attestation) adapted to input peripherals.
- **Open question:** can this be added without an ecosystem-wide PKI, and without
  introducing a cloud dependency that itself becomes an attack surface?

## 2. Descriptor/report validation as a formal problem

**Problem:** HID parser bugs recur yearly (see 2025–2026 kernel CVEs).

**Directions:**
- A **formally specified, memory-safe reference HID parser** (e.g. in Rust) that
  hosts or a firewall can use to validate/normalize descriptors before a fragile
  parser sees them.
- **Fuzzing corpora** and differential testing across OS HID parsers.
- **Open question:** can a canonical "safe subset" of HID descriptors be defined
  that covers real devices while rejecting pathological inputs?

## 3. Behavioral detection that resists a capable adversary

**Problem:** Malboard shows rhythm can be forged; slow injection blurs into human
input.

**Directions:**
- Multi-signal models combining enumeration timing, identity stability, and
  content — with adversarial evaluation (assume the attacker knows the detector).
- **Out-of-band physical sensing** (does a real key actually move?) as ground
  truth — relevant to trusted-keyboard hardware.
- **Open question:** what is the theoretical floor for distinguishing injected
  from human input given an adversary that mimics human statistics?

## 4. Detecting independent-radio exfiltration

**Problem:** DEVICE→NETWORK via an independent radio is invisible to the host.

**Directions:**
- Practical, low-cost **RF anomaly detection** for peripherals.
- Hardware inspection heuristics; power-draw fingerprinting of implants.
- **Open question:** can a HID firewall on the wire infer the presence of a
  hidden radio (e.g. via power-line side channels)? Uncertain; likely limited.

## 5. Firmware transparency for peripherals

**Problem:** users can't verify keyboard firmware matches published source.

**Directions:**
- **Reproducible firmware builds** + a transparency log for input devices.
- Vendor SBOM/firmware-attestation norms; procurement criteria.
- **Open question:** what's the minimum viable transparency scheme a small
  keyboard vendor could actually adopt?

## 6. Standardization & policy

- Should OSes expose a **behavioral HID policy** API (rate limits, new-keyboard
  confirmation) natively? (Some platforms partially do for Bluetooth.)
- Could USB-IF / Bluetooth SIG add optional **device authentication** for HID?
- What procurement/regulatory levers (NIST, CISA guidance) would move the market?

## 7. Deliberately out-of-scope (for now)

- Acoustic/EM keystroke *emanation* recovery from benign keyboards (a separate
  side-channel field).
- "USB Killer" electrical attacks (hardware safety, not infosec HID).

## 8. How to contribute research

Open a discussion or PR with a problem statement, prior work (cited), and a
proposed experiment. Speculative ideas are welcome **if labeled** `theoretical`
per the evidence vocabulary. See `../CONTRIBUTING.md`.
