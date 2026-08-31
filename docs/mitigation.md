# Mitigation

Concrete defensive measures against HID threats, organized by attack direction
and honest about residual risk.

Last reviewed: 2026-08-31

See `../THREAT_MODEL.md` §8 for the summary table; this page is the detailed
treatment.

---

## 1. DEVICE → HOST (injection, impersonation, parser attacks)

| Measure | Addresses | Notes / limits |
| --- | --- | --- |
| USB device authorization (USBGuard, `authorized_default=0`) | HID-01/02 | Attribute-based; spoofable; still raises the bar substantially. |
| Windows device-installation policy / block new HID | HID-01/02 | Managed fleets; unmanaged rarely deploy it. |
| Behavioral monitoring (`hidwatch`) | HID-02, HID-01 | Detects, does not block by itself; false positives need baselining. |
| HID firewall enforcement (future) | HID-01/02/04/05 | Can rate-limit, quarantine, normalize descriptors inline. |
| Keep host HID/USB stacks patched | HID-04/05/15 | Parser CVEs recur; patching is necessary but reactive. |
| Physical port control / port blockers | HID-01/02/08/13 | Cheap, effective against opportunistic attacks. |
| Data-blocker ("USB condom") cables where only power is needed | HID-01/02/11 | Blocks data lines entirely. |
| Screen lock + short timeout | HID-02 | Injection into a locked session is far less useful. |

## 2. HOST → DEVICE (firmware, config, debug)

| Measure | Addresses | Notes / limits |
| --- | --- | --- |
| Signed firmware + secure boot on the device | HID-03/10 | Requires vendor support; rare in consumer HID. |
| Anti-rollback (fused version counter) | HID-10 | Prevents downgrade to vulnerable firmware. |
| Locked debug ports (readout protection) | HID-14 | Vendor/hardware measure; verify in procurement. |
| Least-privilege flashing tools | HID-10 | Don't run vendor updaters as admin unnecessarily. |
| Track & patch device firmware versions | HID-03/10 | e.g. Apple Magic Keyboard 2.0.6 (CVE-2024-0230). |

## 3. DEVICE → NETWORK (exfiltration, telemetry)

| Measure | Addresses | Notes / limits |
| --- | --- | --- |
| Prefer wired, radio-free devices in sensitive settings | HID-11/12 | Removes the independent-radio channel entirely. |
| Physical inspection / X-ray / RF scanning | HID-08/11 | High-assurance only; detects hidden radios. |
| Network egress monitoring | HID-11/12 | Only catches exfil that traverses the host network — **not** an independent radio. |
| Disallow/replace cloud-dependent peripherals | HID-12 | Reduces telemetry attack surface. |

**Honest limit:** an independent radio (O.MG/COTTONMOUTH class) defeats all
host-based network controls. There is no software-only mitigation; this is why
the threat model flags DEVICE→NETWORK as the hardest class.

## 4. COMPANION SOFTWARE → HOST

| Measure | Addresses | Notes / limits |
| --- | --- | --- |
| Avoid installing vendor companion software when not needed | HID-09 | Often the simplest and best mitigation. |
| Least privilege; avoid kernel drivers | HID-09 | Blocks BYOVD-style abuse of signed peripheral drivers. |
| Verify update-channel integrity (signed, TLS-pinned) | HID-09 | Insecure updaters are a recurring RCE vector. |
| Vulnerable-driver blocklists (e.g. OS-provided) | HID-09 | Mitigates BYOVD using known-bad signed drivers. |
| Telemetry review / network policy | HID-09/12 | Understand what the app sends. |

## 5. Wireless-specific (Bluetooth / BLE / 2.4 GHz)

- **Patch stacks** (CVE-2023-45866, KNOB, BlueBorne, BlueFrag).
- **Require authenticated pairing** (LE Secure Connections; avoid Just Works for
  input devices).
- **Disable Bluetooth when unused**; avoid remaining connectable/discoverable.
- **Enforce minimum encryption key entropy** (KNOB mitigation, ≥ 7 octets).
- **Prefer wired input** where the threat model warrants; avoid weak proprietary
  2.4 GHz dongles (MouseJack/KeyJack), update dongle firmware.

## 6. A layered defense recommendation (practical baseline)

For a **security-conscious individual / SMB** today, with only existing tools:

1. Deploy **USBGuard** (Linux) or **Windows device-installation policy** with a
   curated allow-list.
2. Run **`hidwatch monitor`** for behavioral visibility and alerting.
3. **Patch** OS HID/USB/Bluetooth stacks promptly.
4. **Disable Bluetooth** when not needed; require authenticated pairing.
5. **Physical control** of ports and custody of keyboards.
6. **Avoid** unnecessary vendor companion software; prefer simple, radio-free,
   well-patched devices.

For **high-assurance** environments, add physical/RF inspection, radio-free
policy, and (aspirationally) attested/trusted keyboards from the
trusted-keyboard research.

## 7. Residual risk (always state it)

Even with all of the above:
- Perfectly human-paced injection may evade behavioral detection.
- Independent-radio exfil is not host-detectable.
- Supply-chain-preloaded firmware may arrive already malicious.
- Zero-day parser bugs may exist before patches.

Mitigation reduces risk; it does not eliminate it. That residual is the
justification for the longer-term hardware and trusted-device research.

## 8. Cross-references

- `detection.md` — detecting before mitigating.
- `products/hid-firewall/architecture.md` — enforcement design.
- `hardware/architecture/secure-keyboard.md` — device-side assurance.
