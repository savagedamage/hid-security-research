# Security Policy

`hid-security-research` is a **defensive** security research project. This
document explains how to report vulnerabilities (both in this project and in the
HID ecosystem), the ethical boundaries all contributors must respect, and how we
handle sensitive material such as malicious-device samples.

Last reviewed: 2026-08-31

---

## 1. Supported versions

This project is pre-1.0 research software. Only the `main` branch is supported.
There are no long-term support branches yet. Once we publish tagged releases,
this section will list which are receiving security fixes.

| Version | Supported |
| ------- | --------- |
| `main` (unreleased) | ✅ |
| tagged releases | none yet |

---

## 2. Reporting a vulnerability *in this project*

If you find a security flaw in code in this repository (for example, a bug in
the `hidwatch` parser that could be exploited by a malicious HID report):

1. **Do not open a public issue.**
2. Use GitHub's **private vulnerability reporting** ("Report a vulnerability"
   button under the Security tab), or email the maintainers listed in
   `CONTRIBUTING.md`.
3. Include: affected file/commit, a description, and a minimal reproducer
   (a synthetic HID report / descriptor is fine — **never** a real capture of
   someone's keystrokes).
4. We aim to acknowledge within **7 days** and to agree on a disclosure
   timeline. Our default coordinated-disclosure window is **90 days**.

Because `hidwatch` parses attacker-controllable input (HID report descriptors
and reports), parser robustness is treated as a security property, not just a
correctness property.

---

## 3. Reporting a vulnerability you found in a real HID device / stack

This project catalogs HID vulnerabilities, but **we are not a CNA (CVE Numbering
Authority)** and we do not coordinate disclosure on behalf of vendors.

If your research concerns a *third-party* product:

- Report it to **the affected vendor** and/or a coordinating body such as
  **CISA / CERT-CC** (https://www.kb.cert.org/vuls/report/) first.
- Follow responsible-disclosure practice; give the vendor a reasonable window.
- Once the issue is **public** (has a CVE, advisory, or the vendor has
  disclosed), you are welcome to contribute a dataset entry to
  `data/cves/` documenting it, with primary-source citations.

We will **not** accept dataset entries describing **non-public 0-days**. This
repository only documents vulnerabilities that are already public.

---

## 4. Ethical & legal boundaries (mandatory for all contributors)

This is defensive research. The following are **out of scope and will be
rejected**:

- Malware, credential stealers, keyloggers intended for deployment, persistence
  mechanisms, or command-and-control (C2) infrastructure.
- Weaponized keystroke-injection payloads or "ready-to-run" BadUSB attack
  scripts. (Describing the *technique* and citing public research is fine;
  shipping a turnkey attack tool is not.)
- Any tool whose primary purpose is to compromise systems the user does not
  own or lack authorization to test.
- Instructions targeting a specific real-world victim.

**Only test against hardware and systems you own or are explicitly authorized
to test.** HID injection against another person's machine may violate computer
misuse / unauthorized access laws (e.g. the US CFAA, the UK Computer Misuse Act,
and equivalents). Contributors are responsible for their own legal compliance.

What **is** in scope: threat modeling, protocol documentation, defensive
detection/monitoring code, synthetic test fixtures, analysis of *public*
vulnerabilities, and secure-hardware design research.

---

## 5. Handling malicious-device samples and captures

- **Do not commit real HID captures.** A capture of real typing is effectively a
  keylog and may contain passwords. `.gitignore` blocks `lab/captures/*` binary
  formats by default. Only **synthetic** fixtures (generated, not recorded from
  a human) belong in `lab/fixtures/`.
- If a fixture is *derived from* a real malicious device, it must be reduced to
  the minimal non-sensitive artifact needed (e.g. the HID report descriptor
  bytes), with any captured payload text removed.
- Firmware images of third-party devices must **not** be redistributed here;
  link to the vendor or a reputable archive instead, and note the SHA-256.

---

## 6. No secrets in the repository

Never commit credentials, API keys, private keys, tokens, or personal data.
CI runs secret scanning (`gitleaks`) on every push and pull request. If a secret
is ever committed, treat it as compromised: rotate it immediately and open a
private report. `.gitignore` excludes common secret file patterns as a
first-line defense, but scanning is the real control.

---

## 7. Attribution and good faith

We support good-faith security research and will not pursue legal action against
researchers who act in good faith, follow this policy, and respect the ethical
boundaries above. Findings contributed here should credit their original authors
and cite primary sources.
