"""Core data models for hidwatch.

Deliberately dependency-free (stdlib dataclasses/enums only). These types are the
shared vocabulary between the descriptor parser, the analyzer, and the CLI, and
they mirror the concepts in docs/hid-fundamentals.md.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class RiskLevel(enum.IntEnum):
    """Ordered risk levels. IntEnum so we can take max() over findings."""

    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


class Transport(enum.Enum):
    USB = "usb"
    BLUETOOTH_BREDR = "bluetooth-bredr"
    BLE = "ble"
    PROPRIETARY_RF = "proprietary-rf"
    UNKNOWN = "unknown"


# USB HID class/subclass/protocol constants (see docs/usb-hid.md).
USB_CLASS_HID = 0x03
HID_SUBCLASS_BOOT = 0x01
HID_PROTOCOL_KEYBOARD = 0x01
HID_PROTOCOL_MOUSE = 0x02


@dataclass(frozen=True)
class DeviceInterface:
    """A single interface exposed by a device (USB composite devices have many)."""

    interface_class: int
    subclass: int = 0
    protocol: int = 0
    description: str = ""

    @property
    def is_hid(self) -> bool:
        return self.interface_class == USB_CLASS_HID

    @property
    def is_keyboard(self) -> bool:
        return self.is_hid and self.protocol == HID_PROTOCOL_KEYBOARD

    @property
    def is_mouse(self) -> bool:
        return self.is_hid and self.protocol == HID_PROTOCOL_MOUSE


@dataclass
class Device:
    """An observed HID device and its declared identity.

    All fields are DEVICE-ASSERTED and therefore untrusted (see
    docs/host-trust-model.md). hidwatch records them as claims, not facts.
    """

    transport: Transport = Transport.UNKNOWN
    vendor_id: int | None = None
    product_id: int | None = None
    manufacturer: str | None = None
    product: str | None = None
    serial: str | None = None
    interfaces: list[DeviceInterface] = field(default_factory=list)
    # Raw HID report descriptor bytes, if captured.
    report_descriptor: bytes | None = None
    # Free-form declared purpose from the user/allow-list (e.g. "storage"),
    # used to flag unexpected capabilities.
    declared_purpose: str | None = None

    @property
    def vid_pid(self) -> str:
        v = f"{self.vendor_id:04x}" if self.vendor_id is not None else "????"
        p = f"{self.product_id:04x}" if self.product_id is not None else "????"
        return f"{v}:{p}"

    @property
    def keyboard_interfaces(self) -> list[DeviceInterface]:
        return [i for i in self.interfaces if i.is_keyboard]

    @property
    def hid_interfaces(self) -> list[DeviceInterface]:
        return [i for i in self.interfaces if i.is_hid]


@dataclass(frozen=True)
class HidReportEvent:
    """A single observed HID report at a point in time.

    `timestamp` is seconds (monotonic-ish) from an arbitrary origin.
    `keys` is the set of active keyboard usage codes in this report (may be empty
    for non-keyboard reports). `raw_len` is the report length in bytes.
    """

    timestamp: float
    keys: tuple[int, ...] = ()
    modifiers: int = 0
    raw_len: int = 0
    report_id: int | None = None

    @property
    def is_keypress(self) -> bool:
        return bool(self.keys) or self.modifiers != 0


@dataclass(frozen=True)
class Finding:
    """A single reason contributing to a risk assessment."""

    level: RiskLevel
    code: str  # short machine code, e.g. "UNEXPECTED_KEYBOARD_IFACE"
    message: str  # human-readable explanation
    signal: str  # which detector produced it, e.g. "enumeration", "behavior"


@dataclass
class RiskReport:
    """Aggregate risk assessment for a device/session."""

    device: Device
    findings: list[Finding] = field(default_factory=list)

    @property
    def level(self) -> RiskLevel:
        if not self.findings:
            return RiskLevel.LOW
        return max(f.level for f in self.findings)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def reasons(self) -> list[str]:
        # Sorted by severity, most severe first.
        ordered = sorted(self.findings, key=lambda f: f.level, reverse=True)
        return [f"[{f.level}] {f.message}" for f in ordered]
