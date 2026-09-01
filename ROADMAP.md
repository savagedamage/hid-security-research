# Roadmap

Last reviewed: 2026-08-31. Stages are gates, not calendar promises.

## Stage 0 — Research foundation (current: substantially complete)

Deliverables: governance, glossary, threat model, transport/firmware/supply-chain
documentation, source discipline. Exit: primary-source citations and review
process exist. Risk: stale or overstated research.

## Stage 1 — Threat database (current: initial release)

Deliverables: schema, taxonomy, validator, generated index, verified CVE and
non-CVE entries. Exit: recurring update process, duplicate/relevance review, ≥50
high-confidence HID-specific records. Dependencies: primary-source access.
Risk: keyword over-inclusion of generic Bluetooth/USB issues.

## Stage 2 — HID protocol tooling (current: prototype)

Deliverables: memory-safe report-descriptor parser, normalization design,
malformed-input corpus, differential tests against mature parsers. Exit: fuzzing
campaign with no crashes and documented compatibility on diverse descriptors.
Risk: HID quirks and vendor-defined usages.

## Stage 3 — HIDWatch prototype (current: v0.1 core)

Deliverables: list/monitor/inspect/analyze/report/policy CLI and Linux enumeration are
implemented; dependency-free polling attach/detach/change monitoring is
implemented. Remaining: optional live udev delivery, hidraw report metrics, and
safe recording with redaction.
Exit: installs cleanly on supported Linux; integration tests on authorized real
hardware. Risk: permissions, privacy of captures, platform variance.

## Stage 4 — Behavioral detection

Prerequisites: representative benign corpus, labeling process. Deliverables:
per-device baselines, rate/timing/interface/re-enumeration rules, explainable
scores, adversarial tests, false-positive metrics. Exit: published evaluation,
not merely demo fixtures. Risk: Malboard/human-paced evasion; scanner/macros.

## Stage 5 — Hardware proof of concept

Prerequisites: stable parser/policy API. Build a log-only USB host↔device proxy
on suitable dual-role hardware; measure latency, descriptor compatibility, power,
and failure modes. Exit: ≥100 devices pass basic function and logs are complete.
Risk: electrical/USB compliance, gadget-host timing, hardware becoming a new
parser target.

## Stage 6 — HID firewall prototype

Add descriptor normalization, report conformance, quarantine, physical approval,
and rate limiting. Default first pilots to detect-only. Exit: enforcement cannot
be bypassed on the wired path and failure behavior is explicit. Risk: blocking
legitimate input; wired-only coverage limitations.

## Stage 7 — Security validation

Independent threat-model review, fuzzing, red-team exercise, secure boot/update
for gateway, tamper-evident logging, SBOM/reproducible builds, disclosure process.
Exit: public assessment and tracked residual risks. Risk: gateway compromise.

## Stage 8 — Pilot users

Three to five design partners in enterprise/high-assurance environments. Measure
deployment friction, detection utility, false positives, and incident-response
outcomes. Exit: evidence users retain and act on the product. Risk: no meaningful
buyer pain beyond existing device controls.

## Stage 9 — Potential commercialization

Only after pilot evidence: enterprise support/policy platform first; forensic
appliance second; hardware gateway selectively. Secure keyboard remains a
separate high-assurance program requiring supply-chain and certification
investment. Exit: repeatable buyer, deployment, support, and unit economics.

## Immediate next milestone

Live Linux visibility: udev event monitoring + descriptor collection + privacy-
preserving report metrics, tested on authorized physical devices. No enforcement
until observation quality and false positives are measured.
