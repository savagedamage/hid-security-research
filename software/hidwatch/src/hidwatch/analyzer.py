"""Behavioral analysis and transparent risk scoring for HID devices.

Implements the detection model from docs/detection.md §2-3. Every risk verdict is
accompanied by an explicit, human-readable reason (a Finding) — a security tool
that says "HIGH" without saying why is not useful. Detection is multi-signal:

  1. Enumeration/identity signals   (analyze_device)
  2. Descriptor signals             (analyze_device, via descriptor parser)
  3. Behavioral signals             (analyze_behavior)

Known limitations are documented in docs/detection.md §4 (a capable malicious
device can forge human rhythm; slow injection blurs into human input; independent
-radio exfil is invisible to the host). The scoring here is intentionally
conservative and explainable, not an opaque model.
"""

from __future__ import annotations

import statistics

from hidwatch.descriptor import DescriptorError, parse_report_descriptor
from hidwatch.models import Device, Finding, HidReportEvent, RiskLevel, RiskReport
from hidwatch.policy import DEFAULT_POLICY, Policy


def analyze_device(device: Device, policy: Policy = DEFAULT_POLICY) -> RiskReport:
    """Assess a device from its declared identity and descriptor (no behavior)."""
    report = RiskReport(device=device)
    allowlisted = device.vendor_id is not None and policy.is_allowlisted(device.vid_pid)

    # --- Unexpected keyboard interface on a device declared as something else ---
    purpose = (device.declared_purpose or "").lower()
    kbd_ifaces = device.keyboard_interfaces
    if kbd_ifaces and purpose and "keyboard" not in purpose and "input" not in purpose:
        report.add(
            Finding(
                level=RiskLevel.HIGH,
                code="UNEXPECTED_KEYBOARD_IFACE",
                message=(
                    f"device declared as '{device.declared_purpose}' exposes a "
                    f"keyboard interface (classic BadUSB pattern)"
                ),
                signal="enumeration",
            )
        )

    # --- Composite device mixing storage/network + HID keyboard ---
    classes = {i.interface_class for i in device.interfaces}
    if any(i.is_keyboard for i in device.interfaces) and (0x08 in classes or 0x02 in classes):
        report.add(
            Finding(
                level=RiskLevel.HIGH,
                code="COMPOSITE_KBD_PLUS_STORAGE_OR_NET",
                message=(
                    "composite device exposes both a keyboard interface and "
                    "mass-storage/network interface(s)"
                ),
                signal="enumeration",
            )
        )

    # --- Missing serial on a keyboard (weakens identity/allow-listing) ---
    if kbd_ifaces and not device.serial and not allowlisted:
        report.add(
            Finding(
                level=RiskLevel.LOW,
                code="NO_SERIAL",
                message="keyboard device reports no serial number (identity is weak/anonymous)",
                signal="identity",
            )
        )

    # --- Descriptor analysis ---
    if device.report_descriptor is not None:
        try:
            summary = parse_report_descriptor(device.report_descriptor)
        except DescriptorError as exc:
            report.add(
                Finding(
                    level=RiskLevel.MEDIUM,
                    code="DESCRIPTOR_MALFORMED",
                    message=f"report descriptor failed safe parsing: {exc}",
                    signal="descriptor",
                )
            )
        else:
            for anomaly in summary.anomalies:
                report.add(
                    Finding(
                        level=RiskLevel.MEDIUM,
                        code="DESCRIPTOR_ANOMALY",
                        message=f"report descriptor anomaly: {anomaly}",
                        signal="descriptor",
                    )
                )
            # A device declaring a keyboard usage page it shouldn't have.
            if (
                summary.declares_keyboard
                and purpose
                and "keyboard" not in purpose
                and "input" not in purpose
            ):
                report.add(
                    Finding(
                        level=RiskLevel.HIGH,
                        code="DESCRIPTOR_KEYBOARD_UNEXPECTED",
                        message=(
                            f"descriptor declares Keyboard usage page but device "
                            f"purpose is '{device.declared_purpose}'"
                        ),
                        signal="descriptor",
                    )
                )
    return report


def analyze_behavior(
    device: Device,
    events: list[HidReportEvent],
    policy: Policy = DEFAULT_POLICY,
    attach_time: float | None = None,
) -> RiskReport:
    """Assess a device from its runtime HID report behavior.

    `attach_time` is the timestamp at which the device enumerated; if provided,
    time-to-first-input is evaluated.
    """
    report = RiskReport(device=device)
    fast_ok = device.vendor_id is not None and policy.is_fast_input_allowlisted(device.vid_pid)

    keypresses = [e for e in events if e.is_keypress]

    # --- Time-to-first-input relative to enumeration ---
    if attach_time is not None and keypresses:
        first_dt_ms = (keypresses[0].timestamp - attach_time) * 1000.0
        if first_dt_ms < policy.injection_reaction_ms:
            report.add(
                Finding(
                    level=RiskLevel.HIGH,
                    code="INPUT_TOO_SOON",
                    message=(
                        f"input began {first_dt_ms:.1f} ms after enumeration; "
                        f"no human reaction window"
                    ),
                    signal="behavior",
                )
            )
        elif first_dt_ms < policy.min_human_reaction_ms:
            report.add(
                Finding(
                    level=RiskLevel.MEDIUM,
                    code="INPUT_SOON",
                    message=(
                        f"input began {first_dt_ms:.1f} ms after enumeration "
                        f"(faster than typical human reaction)"
                    ),
                    signal="behavior",
                )
            )

    # --- Keystroke rate ---
    if len(keypresses) >= policy.min_samples_for_timing:
        span = keypresses[-1].timestamp - keypresses[0].timestamp
        if span > 0:
            rate = (len(keypresses) - 1) / span
            if rate >= policy.impossible_keystroke_rate:
                report.add(
                    Finding(
                        level=RiskLevel.CRITICAL,
                        code="IMPOSSIBLE_RATE",
                        message=f"impossible typing rate: {rate:.0f} keystrokes/sec",
                        signal="behavior",
                    )
                )
            elif rate >= policy.max_human_keystroke_rate:
                level = RiskLevel.MEDIUM if fast_ok else RiskLevel.HIGH
                note = " (fast-input allow-listed → downgraded)" if fast_ok else ""
                report.add(
                    Finding(
                        level=level,
                        code="HIGH_RATE",
                        message=f"elevated typing rate: {rate:.0f} keystrokes/sec{note}",
                        signal="behavior",
                    )
                )

        # --- Timing regularity (machine-perfect intervals) ---
        intervals = [
            keypresses[k + 1].timestamp - keypresses[k].timestamp
            for k in range(len(keypresses) - 1)
        ]
        if len(intervals) >= policy.min_samples_for_timing - 1:
            jitter = statistics.pstdev(intervals)
            if jitter < policy.min_human_jitter_stdev_s and not fast_ok:
                report.add(
                    Finding(
                        level=RiskLevel.HIGH,
                        code="LOW_JITTER",
                        message=(
                            f"machine-like keystroke timing: jitter stdev "
                            f"{jitter * 1000:.2f} ms (humans vary more)"
                        ),
                        signal="behavior",
                    )
                )
    return report


def analyze(
    device: Device,
    events: list[HidReportEvent] | None = None,
    policy: Policy = DEFAULT_POLICY,
    attach_time: float | None = None,
) -> RiskReport:
    """Combined device + behavioral assessment into a single RiskReport."""
    combined = analyze_device(device, policy)
    if events:
        behavior = analyze_behavior(device, events, policy, attach_time)
        for f in behavior.findings:
            combined.add(f)
    return combined
