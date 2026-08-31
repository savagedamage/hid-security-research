"""Read-only Linux backend for enumerating HID/USB devices.

Non-destructive by design: reads only from sysfs (`/sys/bus/usb/devices`). Never
writes to devices, never changes the `authorized` flag, never flashes firmware.
See docs/usb-hid.md §5 for the observation sources.

If sysfs is unavailable (non-Linux, container without /sys, restricted
environment), functions return an empty list rather than raising, so the rest of
hidwatch (parsers, analyzers, fixtures) still works. hidwatch NEVER fabricates
device data — absence of hardware yields an empty result, not invented devices.
"""

from __future__ import annotations

import os
from pathlib import Path

from hidwatch.models import Device, DeviceInterface, Transport

SYSFS_USB = Path("/sys/bus/usb/devices")


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


def available() -> bool:
    """True if we can enumerate USB devices via sysfs on this host.

    Returns False (not raise) if the path is absent or unreadable (e.g. Android
    or a restricted container), so callers degrade gracefully.
    """
    try:
        return SYSFS_USB.is_dir() and _dir_readable(SYSFS_USB)
    except OSError:
        return False


def _dir_readable(path: Path) -> bool:
    try:
        with os.scandir(path):
            return True
    except OSError:
        return False


def list_usb_devices() -> list[Device]:
    """Enumerate USB devices and their HID interfaces from sysfs (read-only)."""
    if not available():
        return []

    devices: list[Device] = []
    try:
        entries = sorted(SYSFS_USB.iterdir())
    except OSError:
        return []
    for entry in entries:
        # Device directories have an idVendor file; interfaces do not.
        vid_file = entry / "idVendor"
        if not vid_file.exists():
            continue

        device = Device(
            transport=Transport.USB,
            vendor_id=_read_hex(entry / "idVendor"),
            product_id=_read_hex(entry / "idProduct"),
            manufacturer=_read(entry / "manufacturer"),
            product=_read(entry / "product"),
            serial=_read(entry / "serial"),
        )

        # Interfaces are child dirs named like "1-1:1.0".
        for sub in sorted(entry.iterdir()):
            if not sub.is_dir() or ":" not in sub.name:
                continue
            icls = _read_hex(sub / "bInterfaceClass")
            if icls is None:
                continue
            device.interfaces.append(
                DeviceInterface(
                    interface_class=icls,
                    subclass=_read_hex(sub / "bInterfaceSubClass") or 0,
                    protocol=_read_hex(sub / "bInterfaceProtocol") or 0,
                    description=sub.name,
                )
            )

        devices.append(device)
    return devices
