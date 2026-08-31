"""hidwatch — defensive HID observability and behavioral risk analysis.

hidwatch makes the behavior of HID (keyboard/input) devices *observable* so that
injection, impersonation, and descriptor anomalies can be detected. It is a
DEFENSIVE tool: it observes locally and never writes to devices, and the core
library makes no network calls (see SECURITY.md / docs/detection.md).

Public API surface:
    hidwatch.models      — dataclasses for devices, reports, findings
    hidwatch.descriptor  — HID report-descriptor parser
    hidwatch.analyzer    — behavioral analysis + risk scoring
    hidwatch.policy      — tunable thresholds / allow-lists
"""

from __future__ import annotations

__version__ = "0.1.0"

from hidwatch.models import (
    Device,
    DeviceInterface,
    Finding,
    HidReportEvent,
    RiskLevel,
    RiskReport,
)

__all__ = [
    "Device",
    "DeviceInterface",
    "Finding",
    "HidReportEvent",
    "RiskLevel",
    "RiskReport",
    "__version__",
]
