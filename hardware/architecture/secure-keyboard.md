# Secure Keyboard Reference Architecture

Status: research design; no prototype or security certification exists yet.
Last reviewed: 2026-08-31

## Goal

A security-oriented keyboard should provide trustworthy input without creating a
larger cloud, driver, radio, or software attack surface. It must make its
hardware identity and running firmware verifiable while remaining useful when
all vendor infrastructure is offline.

## Reference design

```
keys → matrix scanner → isolated HID MCU → USB data
                         │
 immutable ROM → signed bootloader → signed application
       │               │              │
 fused root key     anti-rollback   measured image
       └──────────── attestation key / challenge response
```

Required properties:

1. Immutable boot ROM verifies the first mutable stage against a fused public-key
   hash; every later stage is verified before execution (secure boot).
2. Device-unique attestation key is generated or injected in controlled
   provisioning, non-exportable, and separated from firmware-signing keys.
3. Authenticated firmware updates are signed, version-bound, fail-safe, and
   protected by a monotonic anti-rollback counter. Recovery images are verified.
4. Measurements cover bootloader, application, configuration, and policy. A
   nonce-bound signed quote prevents replay.
5. Debug is authenticated during development and irreversibly locked for
   production; production UART emits no secrets.
6. Keys/configuration are minimized. No keystroke history is stored. Macros are
   disabled by default or require a physical authorization gesture.
7. Wired-only baseline. Radios are absent, not merely software-disabled. A radio
   variant requires authenticated LE Secure Connections and explicit physical
   pairing UX.
8. No privileged driver, mandatory account, telemetry, or cloud dependency.
   Standard USB HID remains the compatibility path.
9. Tamper-evident enclosure, serialized PCB, documented component provenance,
   and visible evidence if debug pads or case have been accessed.
10. Open firmware, reproducible builds, signed release manifests, SBOM, and a
    public append-only firmware transparency log.

## Attestation protocol sketch

Host/gateway sends a random nonce and requested measurement set. Device returns:

- device certificate / public identity;
- firmware and configuration measurements;
- monotonic version and lifecycle state;
- signature over the nonce and all claims.

This proves possession of a key and binds claims to a fresh challenge. It does
**not** prove the physical key matrix is unmodified, eliminate side channels, or
make the manufacturer's provisioning trustworthy. Certificate revocation and
privacy are hard: a stable device identity permits tracking. Pairwise or
privacy-preserving attestations should be investigated.

## Supply-chain model

Reproducibility verifies source→binary correspondence, not that a delivered PCB
runs that binary. Attestation links the running measurement to a provisioned
identity, but provisioning can be compromised. High assurance therefore needs:
component provenance, split-control key ceremonies, sampled destructive
inspection, transparent firmware releases, and reproducible independent builds.

## Trade-offs and failure modes

- Secure elements increase cost, sourcing risk, and opaque proprietary code.
- Locked debug makes repair and community development harder.
- Anti-rollback can brick devices if version state is corrupted.
- Attestation PKI creates issuer and revocation governance problems.
- Open source enables audit but does not by itself guarantee shipped firmware.
- Wireless convenience materially enlarges attack surface.
- A companion app can erase the security benefit; the design intentionally
  avoids one for ordinary operation.

## Validation requirements before any trust claim

Threat-model review, schematic/PCB review, reproducible-build verification,
fault-injection and voltage/clock glitch testing, update interruption testing,
rollback attempts, debug-lock verification, parser fuzzing, USB compliance and
latency testing, third-party penetration testing, and an explicit residual-risk
report. Do not market the design as “secure” before this work exists.

Sources:
- NIST SP 800-193, Platform Firmware Resiliency Guidelines:
  https://doi.org/10.6028/NIST.SP.800-193
- NISTIR 8320, Hardware-Enabled Security:
  https://doi.org/10.6028/NIST.IR.8320
- TCG DICE architecture: https://trustedcomputinggroup.org/work-groups/dice-architectures/
- Reproducible Builds: https://reproducible-builds.org/docs/
- in-toto supply-chain framework: https://in-toto.io/
