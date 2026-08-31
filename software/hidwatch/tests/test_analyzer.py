"""Tests for behavioral analysis and risk scoring."""

from __future__ import annotations

from hidwatch.analyzer import analyze, analyze_behavior, analyze_device
from hidwatch.fixtures import badusb_flashdrive, benign_keyboard, synth_typing
from hidwatch.models import Device, DeviceInterface, RiskLevel, Transport
from hidwatch.policy import Policy


def test_benign_keyboard_is_low_risk() -> None:
    report = analyze_device(benign_keyboard())
    assert report.level == RiskLevel.LOW


def test_badusb_flashdrive_flagged_high() -> None:
    report = analyze_device(badusb_flashdrive())
    assert report.level >= RiskLevel.HIGH
    codes = {f.code for f in report.findings}
    assert "UNEXPECTED_KEYBOARD_IFACE" in codes
    assert "COMPOSITE_KBD_PLUS_STORAGE_OR_NET" in codes


def test_impossible_rate_is_critical() -> None:
    dev = benign_keyboard()
    events = synth_typing(n=40, rate_hz=150.0, jitter_stdev=0.0)
    report = analyze_behavior(dev, events, attach_time=0.0)
    assert report.level == RiskLevel.CRITICAL
    assert any(f.code == "IMPOSSIBLE_RATE" for f in report.findings)


def test_input_right_after_attach_flagged() -> None:
    dev = benign_keyboard()
    events = synth_typing(n=12, rate_hz=10.0, start=0.005, jitter_stdev=0.03)
    report = analyze_behavior(dev, events, attach_time=0.0)
    assert any(f.code == "INPUT_TOO_SOON" for f in report.findings)


def test_low_jitter_flagged() -> None:
    dev = benign_keyboard()
    # Human-plausible rate but machine-perfect timing.
    events = synth_typing(n=20, rate_hz=8.0, start=3.0, jitter_stdev=0.0)
    report = analyze_behavior(dev, events, attach_time=0.0)
    assert any(f.code == "LOW_JITTER" for f in report.findings)


def test_human_typing_not_flagged() -> None:
    dev = benign_keyboard()
    events = synth_typing(n=30, rate_hz=6.0, start=3.0, jitter_stdev=0.05, seed=11)
    report = analyze_behavior(dev, events, attach_time=0.0)
    assert report.level == RiskLevel.LOW


def test_fast_input_allowlist_downgrades_rate() -> None:
    dev = Device(
        transport=Transport.USB,
        vendor_id=0x05E0,
        product_id=0x1200,
        product="Scanner",
        declared_purpose="keyboard",
        interfaces=[DeviceInterface(0x03, 0x01, 0x01)],
    )
    events = synth_typing(n=14, rate_hz=30.0, start=5.0, jitter_stdev=0.02)
    strict = analyze_behavior(dev, events, attach_time=0.0)
    lenient = analyze_behavior(
        dev, events, policy=Policy(fast_input_allowlist={"05e0:1200"}), attach_time=0.0
    )
    assert lenient.level < strict.level


def test_combined_analyze_merges_findings() -> None:
    dev = badusb_flashdrive()
    events = synth_typing(n=40, rate_hz=120.0, start=0.01, jitter_stdev=0.0)
    report = analyze(dev, events, attach_time=0.0)
    assert report.level == RiskLevel.CRITICAL
    # Contains both enumeration and behavior signals.
    signals = {f.signal for f in report.findings}
    assert "enumeration" in signals
    assert "behavior" in signals


def test_reasons_are_sorted_severe_first() -> None:
    dev = badusb_flashdrive()
    events = synth_typing(n=40, rate_hz=120.0, start=0.01, jitter_stdev=0.0)
    report = analyze(dev, events, attach_time=0.0)
    reasons = report.reasons()
    assert reasons[0].startswith("[CRITICAL]")
