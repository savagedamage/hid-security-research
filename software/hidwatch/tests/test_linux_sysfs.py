"""Tests for read-only Linux sysfs USB enumeration and lifecycle monitoring."""

from __future__ import annotations

from pathlib import Path

import pytest

from hidwatch.backends import linux_sysfs
from hidwatch.backends.linux_sysfs import (
    diff_snapshots,
    list_usb_devices,
    snapshot_usb_devices,
    watch_usb_events,
)
from hidwatch.models import Device, DeviceInterface, Transport


def _write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)


def _add_device(
    root: Path,
    name: str = "1-1",
    *,
    vid: str = "046d",
    pid: str = "c31c",
    product: str = "Test Keyboard",
    serial: str | None = "SER-1",
    interface_class: str = "03",
    interface_subclass: str = "01",
    interface_protocol: str = "01",
) -> None:
    device = root / name
    _write(device / "idVendor", vid)
    _write(device / "idProduct", pid)
    _write(device / "manufacturer", "Test Corp")
    _write(device / "product", product)
    if serial is not None:
        _write(device / "serial", serial)

    # Real Linux sysfs layout: interface is a sibling, not a child.
    interface = root / f"{name}:1.0"
    _write(interface / "bInterfaceClass", interface_class)
    _write(interface / "bInterfaceSubClass", interface_subclass)
    _write(interface / "bInterfaceProtocol", interface_protocol)


def test_snapshot_associates_sibling_hid_interface(tmp_path: Path) -> None:
    _add_device(tmp_path)
    snapshot = snapshot_usb_devices(tmp_path)

    assert list(snapshot) == ["1-1"]
    device = snapshot["1-1"]
    assert device.vid_pid == "046d:c31c"
    assert device.product == "Test Keyboard"
    assert len(device.interfaces) == 1
    assert device.interfaces[0].is_keyboard
    assert device.interfaces[0].description == "1-1:1.0"


def test_multiple_device_interfaces_do_not_cross_associate(tmp_path: Path) -> None:
    _add_device(tmp_path, "1-1")
    _add_device(
        tmp_path,
        "1-10",
        vid="1234",
        pid="5678",
        product="Mouse",
        interface_protocol="02",
    )
    snapshot = snapshot_usb_devices(tmp_path)

    assert snapshot["1-1"].interfaces[0].is_keyboard
    assert snapshot["1-10"].interfaces[0].is_mouse
    assert len(snapshot["1-1"].interfaces) == 1
    assert len(snapshot["1-10"].interfaces) == 1


def test_nested_hub_path_associates_multiple_interfaces(tmp_path: Path) -> None:
    _add_device(tmp_path, "1-2.3")
    second = tmp_path / "1-2.3:1.1"
    _write(second / "bInterfaceClass", "03")
    _write(second / "bInterfaceSubClass", "00")
    _write(second / "bInterfaceProtocol", "00")

    snapshot = snapshot_usb_devices(tmp_path)
    interfaces = snapshot["1-2.3"].interfaces
    assert [interface.description for interface in interfaces] == [
        "1-2.3:1.0",
        "1-2.3:1.1",
    ]


def test_unreadable_or_missing_root_returns_empty(tmp_path: Path) -> None:
    assert snapshot_usb_devices(tmp_path / "missing") == {}
    assert list_usb_devices(tmp_path / "missing") == []


def test_malformed_hex_is_treated_as_unknown_not_crash(tmp_path: Path) -> None:
    _add_device(tmp_path, vid="not-hex")
    device = snapshot_usb_devices(tmp_path)["1-1"]
    assert device.vendor_id is None
    assert device.product_id == 0xC31C


def test_diff_snapshots_attach_detach_and_change() -> None:
    keyboard = Device(
        transport=Transport.USB,
        vendor_id=0x046D,
        product_id=0xC31C,
        interfaces=[DeviceInterface(0x03, 0x01, 0x01)],
    )
    changed = Device(
        transport=Transport.USB,
        vendor_id=0x046D,
        product_id=0xC31C,
        product="Now composite",
        interfaces=[DeviceInterface(0x03, 0x01, 0x01), DeviceInterface(0x08)],
    )
    mouse = Device(
        transport=Transport.USB,
        vendor_id=0x1234,
        product_id=0x5678,
        interfaces=[DeviceInterface(0x03, 0x01, 0x02)],
    )

    events = diff_snapshots(
        {"1-1": keyboard, "2-1": mouse},
        {"1-1": changed, "3-1": keyboard},
    )

    assert [(event.kind, event.sysfs_name) for event in events] == [
        ("detach", "2-1"),
        ("attach", "3-1"),
        ("change", "1-1"),
    ]
    assert events[-1].previous == keyboard


def test_watcher_detects_attach_with_injected_sleep(tmp_path: Path) -> None:
    calls = 0

    def mutate(_interval: float) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            _add_device(tmp_path)

    events = list(watch_usb_events(root=tmp_path, interval=0, iterations=1, sleep=mutate))
    assert len(events) == 1
    assert events[0].kind == "attach"
    assert events[0].device.keyboard_interfaces


def test_watcher_preserves_baseline_across_transient_scan_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keyboard = Device(
        transport=Transport.USB,
        vendor_id=0x046D,
        product_id=0xC31C,
        interfaces=[DeviceInterface(0x03, 0x01, 0x01)],
    )
    scans = iter([{"1-1": keyboard}, None, {"1-1": keyboard}])
    monkeypatch.setattr(linux_sysfs, "_snapshot_usb_devices", lambda _root: next(scans))

    events = list(watch_usb_events(interval=0, iterations=2, sleep=lambda _interval: None))
    assert events == []


def test_repeated_identical_polls_do_not_duplicate_events(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keyboard = Device(
        transport=Transport.USB,
        vendor_id=0x046D,
        product_id=0xC31C,
        interfaces=[DeviceInterface(0x03, 0x01, 0x01)],
    )
    scans = iter([{}, {"1-1": keyboard}, {"1-1": keyboard}, {}])
    monkeypatch.setattr(linux_sysfs, "_snapshot_usb_devices", lambda _root: next(scans))

    events = list(watch_usb_events(interval=0, iterations=3, sleep=lambda _interval: None))
    assert [(event.kind, event.sysfs_name) for event in events] == [
        ("attach", "1-1"),
        ("detach", "1-1"),
    ]


def test_watcher_validates_arguments(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="interval"):
        next(watch_usb_events(root=tmp_path, interval=-1, iterations=1))
    with pytest.raises(ValueError, match="iterations"):
        next(watch_usb_events(root=tmp_path, interval=0, iterations=-1))
