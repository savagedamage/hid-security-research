# HID research scope and inclusion criteria

This page defines what belongs in the HID security catalog and how to distinguish
a materially HID-related record from generic USB, Bluetooth, or malware news.
It governs candidate triage; it does not establish that any candidate claim is
true.

Last reviewed: 2026-09-02

## Inclusion rule

Include a public record when reliable evidence shows that HID is material to at
least one part of the security mechanism:

- **Attack vector:** hostile HID descriptors, reports, usages, pairing,
  authorization, transport behavior, or device identity.
- **Execution mechanism:** unintended keyboard, pointer, consumer-control, or
  other HID input causes a security-relevant host action.
- **Target:** HID firmware, bootloader, receiver, radio, driver, parser, device
  service, updater, or privileged companion software is attacked.
- **Trust boundary:** a HID device or component crosses a privilege,
  authorization, provenance, or isolation boundary.
- **Persistence or concealment:** peripheral firmware or hardware is modified to
  retain or hide malicious behavior.
- **Collection or exfiltration:** input is captured at a HID-relevant layer or
  leaves through the peripheral or its independent channel.
- **Defense:** a standard, dataset, experiment, or tool directly measures,
  restricts, verifies, or mitigates HID risk.

Each canonical entry must contain a concise technical explanation of that
relevance. Keyword overlap alone is not sufficient.

## Exclusion and boundary cases

Exclude records whose only relationship is that they use the same broad
transport or connector, including:

- generic USB-storage malware that never presents or attacks HID;
- generic Bluetooth flaws without a demonstrated or documented HID path;
- ordinary host keyloggers that do not involve a HID device, HID stack, or
  peripheral companion component;
- electrical destruction devices with no HID security mechanism;
- generic driver flaws in products that happen to include a peripheral unless
  the vulnerable component or attack chain is relevant to HID trust; and
- unsupported marketing claims or search-result summaries.

A broader stack vulnerability may be included only when the entry identifies a
specific HID-relevant reachability or impact path. If that path is uncertain,
keep the item in the candidate queue with an honest evidence label rather than
promoting it.

## Malware and campaign records

Catalog public intelligence about malware or campaigns only when HID has a
material role such as initial access, execution, privilege escalation,
persistence, collection, or exfiltration. Record aliases, HID's role in the
attack chain, affected components, evidence quality, public sources, detection
opportunities, and mitigations.

The repository stores metadata and defensive analysis—not binaries, command
payloads, credential-capture output, operational playbooks, or live samples.
Malware delivered from generic removable storage is not HID-related unless a
separate HID mechanism is evidenced.

The current canonical schema has no dedicated malware entry type. Until a
reviewed catalog-schema migration is complete, malware leads stay in the
candidate queue; do not force them into an inaccurate category.

## Device and platform breadth

HID extends beyond keyboards. Relevant targets may include mice, touchpads,
digitizers, touchscreens, game controllers, scanners, macro pads, assistive
input, presentation controls, KVMs, composite devices, virtual HID, and
receiver/dongle ecosystems. Research should state the precise device role and
avoid generalizing keyboard-specific findings to all HID.

Coverage should be evaluated across USB HID, Bluetooth HIDP, BLE HOGP,
proprietary radio, non-USB embedded transports, virtual devices, major desktop
and mobile hosts, and embedded/RTOS hosts. A zero in the generated coverage
report is a research lead, not proof that no relevant issue exists.

## Promotion checklist

Before moving a candidate into the canonical catalog, confirm:

- the record passes the inclusion rule;
- at least one primary or authoritative source is cited where available;
- facts, interpretation, and uncertainty are distinguishable;
- attack class, direction, platform, transport, and entry type are supportable;
- dates, evidence label, confidence, and `last_reviewed` are present;
- conflicting sources and scope limitations are documented;
- no sensitive or weaponized material is included; and
- the dataset validator and generated-index checks pass.

See `../CONTRIBUTING.md`, `../GLOSSARY.md`, and
`../data/research-queue/README.md`.
