"""hidwatch command-line interface.

Subcommands (see software/hidwatch/README.md):
  hidwatch list                 -- enumerate HID/USB devices (read-only)
  hidwatch inspect [--demo X]   -- detailed view of a device / fixture
  hidwatch analyze <scenario>   -- risk-analyze a JSON scenario or a fixture
  hidwatch descriptor <hex>     -- parse+validate a raw report descriptor
  hidwatch policy               -- show effective policy thresholds
  hidwatch report <scenario>    -- full risk report (device + behavior)

Design: safe by default, explainable output, works without hardware (against
fixtures). No network calls. No writes to devices.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from hidwatch import __version__
from hidwatch.analyzer import analyze, analyze_device
from hidwatch.descriptor import DescriptorError, parse_report_descriptor
from hidwatch.fixtures import (
    badusb_flashdrive,
    benign_keyboard,
    load_scenario,
    synth_typing,
)
from hidwatch.models import Device, RiskLevel, RiskReport
from hidwatch.policy import DEFAULT_POLICY

DEMOS = {
    "benign-keyboard": benign_keyboard,
    "badusb-flashdrive": badusb_flashdrive,
}


def _print_device(device: Device) -> None:
    print(f"Device:        {device.product or '(unknown)'}")
    print(f"  Transport:   {device.transport.value}")
    print(f"  VID:PID:     {device.vid_pid}")
    print(f"  Manufacturer:{device.manufacturer or '-'}")
    print(f"  Serial:      {device.serial or '-'}")
    print(f"  Interfaces:  {len(device.interfaces)}")
    for iface in device.interfaces:
        role = "keyboard" if iface.is_keyboard else "mouse" if iface.is_mouse else (
            "HID" if iface.is_hid else f"class 0x{iface.interface_class:02x}"
        )
        print(
            f"    - class=0x{iface.interface_class:02x} "
            f"sub=0x{iface.subclass:02x} proto=0x{iface.protocol:02x} "
            f"[{role}] {iface.description}"
        )
    if device.report_descriptor is not None:
        try:
            summ = parse_report_descriptor(device.report_descriptor)
            pages = ", ".join(f"0x{p:02x}" for p in sorted(summ.usage_pages))
            print(f"  Descriptor:  {len(device.report_descriptor)} bytes, "
                  f"{summ.item_count} items, usage pages: {pages}")
            print(f"    keyboard={summ.declares_keyboard} "
                  f"consumer={summ.declares_consumer} "
                  f"vendor={summ.declares_vendor_defined} "
                  f"input_bits={summ.total_input_bits}")
            if summ.anomalies:
                print(f"    anomalies: {'; '.join(summ.anomalies)}")
        except DescriptorError as exc:
            print(f"  Descriptor:  MALFORMED ({exc})")


def _print_risk(report: RiskReport) -> None:
    level = report.level
    banner = {
        RiskLevel.LOW: "LOW",
        RiskLevel.MEDIUM: "MEDIUM",
        RiskLevel.HIGH: "HIGH",
        RiskLevel.CRITICAL: "CRITICAL",
    }[level]
    print(f"Risk:          {banner}")
    if report.findings:
        print("Reasons:")
        for reason in report.reasons():
            print(f"  - {reason}")
    else:
        print("Reasons:       none (no risk signals observed)")


def _resolve_device(name: str) -> Device:
    if name in DEMOS:
        return DEMOS[name]()
    raise SystemExit(f"unknown demo device '{name}'. Available: {', '.join(DEMOS)}")


def cmd_list(args: argparse.Namespace) -> int:
    from hidwatch.backends import linux_sysfs

    if not linux_sysfs.available():
        print("No HID enumeration backend available on this host "
              "(sysfs /sys/bus/usb not present).")
        print("hidwatch does not fabricate devices; run against fixtures instead:")
        print("  hidwatch inspect --demo benign-keyboard")
        print("  hidwatch analyze --demo badusb-flashdrive")
        return 0
    devices = linux_sysfs.list_usb_devices()
    hid_only = [d for d in devices if d.hid_interfaces] if not args.all else devices
    if not hid_only:
        print("No HID devices found." if not args.all else "No USB devices found.")
        return 0
    for d in hid_only:
        kinds = "keyboard" if d.keyboard_interfaces else "HID"
        print(f"{d.vid_pid}  {kinds:9}  {d.product or '(unknown)'}  "
              f"[{len(d.interfaces)} iface]")
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    if args.demo:
        device = _resolve_device(args.demo)
        _print_device(device)
        _print_risk(analyze_device(device))
        return 0
    from hidwatch.backends import linux_sysfs

    devices = linux_sysfs.list_usb_devices()
    match = [d for d in devices if d.vid_pid == args.vid_pid] if args.vid_pid else devices
    if not match:
        print("No matching device. Use --demo <name> to inspect a fixture.")
        return 1
    for d in match:
        _print_device(d)
        _print_risk(analyze_device(d))
        print()
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    if args.demo == "badusb-flashdrive":
        device = badusb_flashdrive()
        # Simulate scripted injection: fast, machine-perfect, right after attach.
        events = synth_typing(n=40, rate_hz=120.0, start=0.01, jitter_stdev=0.0)
        report = analyze(device, events, attach_time=0.0)
    elif args.demo == "benign-keyboard":
        device = benign_keyboard()
        events = synth_typing(n=25, rate_hz=6.0, start=2.5, jitter_stdev=0.05)
        report = analyze(device, events, attach_time=0.0)
    elif args.scenario:
        scn = load_scenario(args.scenario)
        report = analyze(scn["device"], scn["events"], attach_time=scn["attach_time"])
        print(f"Scenario:      {scn['name']}")
        if scn.get("expected_risk"):
            print(f"Expected risk: {scn['expected_risk']}")
    else:
        raise SystemExit("provide a scenario file or --demo <name>")
    _print_device(report.device)
    _print_risk(report)
    return 0 if report.level < RiskLevel.HIGH else 2


def cmd_descriptor(args: argparse.Namespace) -> int:
    hexstr = args.hex.replace(" ", "").replace(":", "")
    try:
        data = bytes.fromhex(hexstr)
    except ValueError:
        raise SystemExit("invalid hex string") from None
    try:
        summ = parse_report_descriptor(data)
    except DescriptorError as exc:
        print(f"MALFORMED: {exc}")
        return 2
    pages = ", ".join(f"0x{p:02x}" for p in sorted(summ.usage_pages))
    print(f"Items:          {summ.item_count}")
    print(f"Usage pages:    {pages}")
    print(f"Report IDs:     {sorted(summ.report_ids) or '(none)'}")
    print(f"Input bits:     {summ.total_input_bits}")
    print(f"Keyboard:       {summ.declares_keyboard}")
    print(f"Consumer:       {summ.declares_consumer}")
    print(f"Vendor-defined: {summ.declares_vendor_defined}")
    if summ.anomalies:
        print("Anomalies:")
        for a in summ.anomalies:
            print(f"  - {a}")
    return 0


def cmd_policy(_args: argparse.Namespace) -> int:
    p = DEFAULT_POLICY
    print("Effective policy (defaults; tune per environment):")
    print(f"  max_human_keystroke_rate:   {p.max_human_keystroke_rate} keys/s")
    print(f"  impossible_keystroke_rate:  {p.impossible_keystroke_rate} keys/s")
    print(f"  min_human_reaction_ms:      {p.min_human_reaction_ms} ms")
    print(f"  injection_reaction_ms:      {p.injection_reaction_ms} ms")
    print(f"  min_human_jitter_stdev_s:   {p.min_human_jitter_stdev_s} s")
    print(f"  min_samples_for_timing:     {p.min_samples_for_timing}")
    print(f"  allowlist_vid_pid:          {sorted(p.allowlist_vid_pid) or '(empty)'}")
    print(f"  fast_input_allowlist:       {sorted(p.fast_input_allowlist) or '(empty)'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hidwatch",
        description="Defensive HID observability and behavioral risk analysis.",
    )
    parser.add_argument("--version", action="version", version=f"hidwatch {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="enumerate HID/USB devices (read-only)")
    p_list.add_argument("--all", action="store_true", help="show all USB devices, not just HID")
    p_list.set_defaults(func=cmd_list)

    p_ins = sub.add_parser("inspect", help="detailed view + risk of a device/fixture")
    p_ins.add_argument("--demo", choices=sorted(DEMOS), help="inspect a built-in fixture")
    p_ins.add_argument("--vid-pid", help="filter by vid:pid (hardware)")
    p_ins.set_defaults(func=cmd_inspect)

    p_an = sub.add_parser("analyze", help="risk-analyze a scenario or fixture")
    p_an.add_argument("scenario", nargs="?", help="path to a JSON scenario file")
    p_an.add_argument("--demo", choices=sorted(DEMOS), help="analyze a built-in fixture")
    p_an.set_defaults(func=cmd_analyze)

    p_desc = sub.add_parser("descriptor", help="parse+validate a raw report descriptor")
    p_desc.add_argument("hex", help="report descriptor as hex (spaces/colons ok)")
    p_desc.set_defaults(func=cmd_descriptor)

    p_pol = sub.add_parser("policy", help="show effective policy thresholds")
    p_pol.set_defaults(func=cmd_policy)

    # report is an alias for analyze with full output
    p_rep = sub.add_parser("report", help="alias for analyze (full risk report)")
    p_rep.add_argument("scenario", nargs="?", help="path to a JSON scenario file")
    p_rep.add_argument("--demo", choices=sorted(DEMOS), help="analyze a built-in fixture")
    p_rep.set_defaults(func=cmd_analyze)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
