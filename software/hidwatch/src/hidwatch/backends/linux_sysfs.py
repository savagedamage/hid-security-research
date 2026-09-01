"""Read-only Linux backend for enumerating and monitoring USB/HID devices.

Reads only from sysfs (`/sys/bus/usb/devices`). It never writes to a device,
changes authorization, claims an interface, or flashes firmware.

Linux normally exposes device and interface entries as *siblings*::

    /sys/bus/usb/devices/1-1
    /sys/bus/usb/devices/1-1:1.0

The scanner therefore associates interface entries by their `<device>:` prefix;
it does not incorrectly assume they are child directories.

When sysfs is absent or unreadable, functions return empty results. hidwatch does
not fabricate hardware observations.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from hidwatch.models import Device, DeviceInterface, Transport

SYSFS_USB = Path("/sys/bus/usb/devices")
EventKind = Literal["attach", "detach", "change"]


@dataclass(frozen=True)
class UsbDeviceEvent:
    """A device lifecycle event derived from two read-only sysfs snapshots."""

    kind: EventKind
    sysfs_name: str
    device: Device
    previous: Device | None = None


UsbSnapshot = dict[str, Device]


def _read(path: Path) -> str | None:
    try:
        return path.read_text().strip()
    except (OSError, UnicodeDecodeError):
        return None


def _read_hex(path: Path) -> int | None:
    val = _read(path)
    if val is None:
        return None
    try:
        return int(val, 16)
    except ValueError:
        return None


def _dir_readable(path: Path) -> bool:
    try:
        with os.scandir(path):
            return True
    except OSError:
        return False


def available(root: Path | None = None) -> bool:
    """Return whether the selected sysfs USB directory can be enumerated."""
    selected = SYSFS_USB if root is None else root
    try:
        return selected.is_dir() and _dir_readable(selected)
    except OSError:
        return False


def _snapshot_usb_devices(root: Path | None = None) -> UsbSnapshot | None:
    """Capture an inventory, returning ``None`` when the scan itself failed.

    ``None`` is intentionally distinct from an empty successful inventory so a
    transient permission/read failure is not misreported as every device
    detaching.
    """
    selected = SYSFS_USB if root is None else root
    if not available(selected):
        return None

    try:
        entries = sorted(selected.iterdir(), key=lambda p: p.name)
    except OSError:
        return None

    device_entries = [entry for entry in entries if (entry / "idVendor").exists()]
    interface_entries = [entry for entry in entries if (entry / "bInterfaceClass").exists()]
    snapshot: UsbSnapshot = {}

    for entry in device_entries:
        device = Device(
            transport=Transport.USB,
            vendor_id=_read_hex(entry / "idVendor"),
            product_id=_read_hex(entry / "idProduct"),
            manufacturer=_read(entry / "manufacturer"),
            product=_read(entry / "product"),
            serial=_read(entry / "serial"),
        )

        prefix = f"{entry.name}:"
        for interface in interface_entries:
            if not interface.name.startswith(prefix):
                continue
            icls = _read_hex(interface / "bInterfaceClass")
            if icls is None:
                continue
            device.interfaces.append(
                DeviceInterface(
                    interface_class=icls,
                    subclass=_read_hex(interface / "bInterfaceSubClass") or 0,
                    protocol=_read_hex(interface / "bInterfaceProtocol") or 0,
                    description=interface.name,
                )
            )

        snapshot[entry.name] = device
    return snapshot


def snapshot_usb_devices(root: Path | None = None) -> UsbSnapshot:
    """Capture a point-in-time USB inventory keyed by stable sysfs path name.

    The key identifies a physical topology slot for the current enumeration
    (for example ``1-1``), which makes reconnects and interface-set changes
    detectable without pretending VID/PID or serial are authenticated identity.
    """
    return _snapshot_usb_devices(root) or {}


def list_usb_devices(root: Path | None = None) -> list[Device]:
    """Enumerate USB devices and sibling interfaces from sysfs (read-only)."""
    return list(snapshot_usb_devices(root).values())


def diff_snapshots(before: UsbSnapshot, after: UsbSnapshot) -> list[UsbDeviceEvent]:
    """Return deterministic attach, detach, and metadata/interface change events."""
    events: list[UsbDeviceEvent] = []
    before_keys = set(before)
    after_keys = set(after)

    for name in sorted(before_keys - after_keys):
        events.append(UsbDeviceEvent("detach", name, before[name]))
    for name in sorted(after_keys - before_keys):
        events.append(UsbDeviceEvent("attach", name, after[name]))
    for name in sorted(before_keys & after_keys):
        if before[name] != after[name]:
            events.append(UsbDeviceEvent("change", name, after[name], previous=before[name]))
    return events


def watch_usb_events(
    *,
    interval: float = 1.0,
    iterations: int | None = None,
    root: Path | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> Iterator[UsbDeviceEvent]:
    """Poll sysfs and yield lifecycle events without claiming/writing devices.

    ``iterations`` counts comparisons after the initial baseline. ``None`` runs
    until interrupted. Polling is a zero-runtime-dependency fallback; a future
    optional udev backend can reduce latency while preserving this interface.
    """
    if interval < 0:
        raise ValueError("interval must be non-negative")
    if iterations is not None and iterations < 0:
        raise ValueError("iterations must be non-negative or None")

    previous = _snapshot_usb_devices(root) or {}
    completed = 0
    while iterations is None or completed < iterations:
        sleep(interval)
        current = _snapshot_usb_devices(root)
        if current is not None:
            yield from diff_snapshots(previous, current)
            previous = current
        completed += 1
