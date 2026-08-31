# Introduction

Why HID security matters, what this project is, and how to read the rest of the
documentation.

Last reviewed: 2026-08-31

---

## The one-paragraph thesis

Operating systems trust input devices to provide input. But a modern keyboard is
a *computer*: it has a microcontroller, firmware, often a wireless radio,
sometimes an update mechanism, and frequently privileged companion software on
the host. None of the trust the OS extends to it is verified — VID/PID are not
authenticated, firmware is rarely attested, and a keystroke from a malicious
device is indistinguishable from one a human meant to type. **The HID layer is an
under-appreciated security boundary.** This project aims to make it observable,
controllable, auditable, and eventually trustworthy.

## Who this is for

- **Security researchers** who want a citable, organized map of HID threats and
  a place to contribute findings.
- **Defenders / blue teams** who need to understand and monitor HID risk.
- **Hardware/firmware engineers** interested in trustworthy-device design.
- **Builders** evaluating whether defensive HID products are worth making.

## How to read the docs

Start here, then:

1. `hid-fundamentals.md` — how HID works and where the boundaries are (read this
   before anything else).
2. Transport deep-dives: `usb-hid.md`, `bluetooth-hid.md`, `ble-hid.md`.
3. `firmware-security.md`, `supply-chain.md` — the device/vendor side.
4. `host-trust-model.md` — the OS side.
5. `attack-surface.md` — a consolidated catalog cross-referenced to
   `../THREAT_MODEL.md` and `../data/attack-taxonomy/taxonomy.yaml`.
6. `detection.md`, `mitigation.md` — what defenders can actually do.
7. `future-research.md`, `business-opportunity.md` — where this goes.

Software lives in `../software/hidwatch/`; hardware/product design in
`../hardware/` and `../products/`.

## Evidence discipline (why you can trust this repo)

Every factual claim about a device or attack is tagged with an evidence label
(`observed`/`documented`/`demonstrated`/`reported`/`inferred`/`theoretical`, see
`../GLOSSARY.md`) and cited to a primary source with a URL and review date. We do
not fabricate CVEs or incidents, and we distinguish demonstrated attacks from
vendor marketing and from theoretical concerns. If we can't verify something, we
say so.

## Current status (honest)

This is an early-stage research foundation with working tooling, not a finished
product. See `../README.md` §"Current status" and `../ROADMAP.md` for exactly
what is implemented versus planned.
