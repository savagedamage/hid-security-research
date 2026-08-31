"""Synthetic HID fixtures and scenario loading.

hidwatch is designed to run meaningfully even with NO HID hardware access (e.g.
in CI, containers, or restricted environments — see docs/detection.md and the
project's honesty rule about not pretending hardware testing occurred). This
module provides:

  * canonical benign and suspicious device fixtures, and
  * a loader for the JSON scenario files under lab/fixtures/.

Fixtures are SYNTHETIC (generated, never recorded from a real human's typing).
See SECURITY.md §5.
"""

from __future__ import annotations

import json
from pathlib import Path

from hidwatch.models import Device, DeviceInterface, HidReportEvent, Transport

# Boot-keyboard report descriptor (canonical, from HID 1.11 spec Appendix E.6).
BOOT_KEYBOARD_DESCRIPTOR = bytes(
    [
        0x05, 0x01,  # Usage Page (Generic Desktop)
        0x09, 0x06,  # Usage (Keyboard)
        0xA1, 0x01,  # Collection (Application)
        0x05, 0x07,  #   Usage Page (Keyboard/Keypad)
        0x19, 0xE0,  #   Usage Minimum (Left Control)
        0x29, 0xE7,  #   Usage Maximum (Right GUI)
        0x15, 0x00,  #   Logical Minimum (0)
        0x25, 0x01,  #   Logical Maximum (1)
        0x75, 0x01,  #   Report Size (1)
        0x95, 0x08,  #   Report Count (8)
        0x81, 0x02,  #   Input (Data,Var,Abs)  -- modifier byte
        0x95, 0x01,  #   Report Count (1)
        0x75, 0x08,  #   Report Size (8)
        0x81, 0x01,  #   Input (Const)         -- reserved byte
        0x95, 0x06,  #   Report Count (6)
        0x75, 0x08,  #   Report Size (8)
        0x15, 0x00,  #   Logical Minimum (0)
        0x25, 0x65,  #   Logical Maximum (101)
        0x05, 0x07,  #   Usage Page (Keyboard/Keypad)
        0x19, 0x00,  #   Usage Minimum (0)
        0x29, 0x65,  #   Usage Maximum (101)
        0x81, 0x00,  #   Input (Data,Array)    -- 6 keycodes
        0xC0,        # End Collection
    ]
)


def benign_keyboard() -> Device:
    """A normal boot-protocol USB keyboard."""
    return Device(
        transport=Transport.USB,
        vendor_id=0x046D,
        product_id=0xC31C,
        manufacturer="Example Corp",
        product="Standard Keyboard",
        serial="KB-0001",
        interfaces=[DeviceInterface(0x03, 0x01, 0x01, "HID Boot Keyboard")],
        report_descriptor=BOOT_KEYBOARD_DESCRIPTOR,
        declared_purpose="keyboard",
    )


def badusb_flashdrive() -> Device:
    """A 'flash drive' that also exposes a keyboard interface (BadUSB pattern)."""
    return Device(
        transport=Transport.USB,
        vendor_id=0x1234,
        product_id=0x5678,
        manufacturer="Generic",
        product="USB Flash Drive",
        serial=None,
        interfaces=[
            DeviceInterface(0x08, 0x06, 0x50, "Mass Storage"),
            DeviceInterface(0x03, 0x01, 0x01, "HID Boot Keyboard"),
        ],
        report_descriptor=BOOT_KEYBOARD_DESCRIPTOR,
        declared_purpose="storage",
    )


def synth_typing(
    n: int,
    rate_hz: float,
    start: float = 0.0,
    jitter_stdev: float = 0.03,
    seed: int = 1,
) -> list[HidReportEvent]:
    """Generate synthetic keystroke events at a target rate with optional jitter.

    Deterministic given `seed`. jitter_stdev=0 produces machine-perfect timing.
    """
    import random

    rng = random.Random(seed)
    events: list[HidReportEvent] = []
    t = start
    interval = 1.0 / rate_hz if rate_hz > 0 else 0.1
    for k in range(n):
        events.append(HidReportEvent(timestamp=t, keys=(0x04 + (k % 20),), raw_len=8))
        step = interval
        if jitter_stdev > 0:
            step = max(0.0, rng.gauss(interval, jitter_stdev))
        t += step
    return events


def load_scenario(path: str | Path) -> dict:
    """Load a JSON scenario file (lab/fixtures/*.json).

    Schema (see lab/fixtures/README.md):
      {
        "name": str,
        "description": str,
        "expected_risk": "LOW|MEDIUM|HIGH|CRITICAL",
        "device": {... Device fields, hex ints as strings or ints ...},
        "attach_time": float | null,
        "events": [{"timestamp": float, "keys": [int], "modifiers": int,
                    "raw_len": int}]
      }
    """
    data = json.loads(Path(path).read_text())
    dev_raw = data.get("device", {})

    def _hex(v: object) -> int | None:
        if v is None:
            return None
        if isinstance(v, str):
            return int(v, 16) if v.lower().startswith("0x") else int(v, 16)
        if isinstance(v, int):
            return v
        raise ValueError(f"unsupported id value: {v!r}")

    interfaces = [
        DeviceInterface(
            interface_class=int(i["class"]),
            subclass=int(i.get("subclass", 0)),
            protocol=int(i.get("protocol", 0)),
            description=i.get("description", ""),
        )
        for i in dev_raw.get("interfaces", [])
    ]
    rd = dev_raw.get("report_descriptor")
    report_descriptor = bytes.fromhex(rd) if rd else None

    device = Device(
        transport=Transport(dev_raw.get("transport", "usb")),
        vendor_id=_hex(dev_raw.get("vendor_id")),
        product_id=_hex(dev_raw.get("product_id")),
        manufacturer=dev_raw.get("manufacturer"),
        product=dev_raw.get("product"),
        serial=dev_raw.get("serial"),
        interfaces=interfaces,
        report_descriptor=report_descriptor,
        declared_purpose=dev_raw.get("declared_purpose"),
    )
    events = [
        HidReportEvent(
            timestamp=float(e["timestamp"]),
            keys=tuple(e.get("keys", [])),
            modifiers=int(e.get("modifiers", 0)),
            raw_len=int(e.get("raw_len", 0)),
            report_id=e.get("report_id"),
        )
        for e in data.get("events", [])
    ]
    return {
        "name": data.get("name", Path(path).stem),
        "description": data.get("description", ""),
        "expected_risk": data.get("expected_risk"),
        "device": device,
        "attach_time": data.get("attach_time"),
        "events": events,
    }
