"""HID report-descriptor parser.

Parses the HID report-descriptor item stream (see docs/hid-fundamentals.md §2.2
and the USB-IF HID 1.11 spec §6.2.2). This is the exact byte format used by USB
HID, Bluetooth HIDP, and BLE HOGP (the Report Map), so one parser serves all
transports.

DESIGN RULE (security-critical): every byte here is attacker-controlled. This
parser must NEVER crash, hang, or read out of bounds on hostile input. It raises
`DescriptorError` on malformed input and otherwise returns a structured summary,
including any *anomalies* worth flagging. It never trusts declared sizes; it
bounds every read against the actual buffer. It is the reference implementation
that docs/future-research.md §2 argues hosts should have.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --- HID item type / tag constants (HID 1.11 §6.2.2) ---
ITEM_TYPE_MAIN = 0
ITEM_TYPE_GLOBAL = 1
ITEM_TYPE_LOCAL = 2

# Main item tags
TAG_INPUT = 0x8
TAG_OUTPUT = 0x9
TAG_FEATURE = 0xB
TAG_COLLECTION = 0xA
TAG_END_COLLECTION = 0xC

# Global item tags
TAG_USAGE_PAGE = 0x0
TAG_LOGICAL_MIN = 0x1
TAG_LOGICAL_MAX = 0x2
TAG_REPORT_SIZE = 0x7
TAG_REPORT_ID = 0x8
TAG_REPORT_COUNT = 0x9
TAG_PUSH = 0xA
TAG_POP = 0xB

# Local item tags
TAG_USAGE = 0x0

# Well-known usage pages (docs/hid-fundamentals.md §2.1)
USAGE_PAGE_GENERIC_DESKTOP = 0x01
USAGE_PAGE_KEYBOARD = 0x07
USAGE_PAGE_LED = 0x08
USAGE_PAGE_CONSUMER = 0x0C

# Sanity bounds. Real devices are far below these; anything approaching them is
# either buggy or hostile. We reject absurd values rather than allocate on them.
# A single field wider than 128 bits, or a report with >1024 fields, is not seen
# in legitimate input devices.
MAX_DESCRIPTOR_LEN = 4096
MAX_REPORT_SIZE_BITS = 128
MAX_REPORT_COUNT = 1024
MAX_ITEMS = 4096
MAX_COLLECTION_DEPTH = 64


class DescriptorError(ValueError):
    """Raised on a malformed HID report descriptor."""


@dataclass
class ReportField:
    """A declared field within a report."""

    kind: str  # "input" | "output" | "feature"
    usage_page: int
    report_size_bits: int
    report_count: int
    report_id: int | None


@dataclass
class DescriptorSummary:
    """Structured, safe summary of a parsed report descriptor."""

    usage_pages: set[int] = field(default_factory=set)
    report_ids: set[int] = field(default_factory=set)
    fields: list[ReportField] = field(default_factory=list)
    total_input_bits: int = 0
    anomalies: list[str] = field(default_factory=list)
    item_count: int = 0

    @property
    def declares_keyboard(self) -> bool:
        return USAGE_PAGE_KEYBOARD in self.usage_pages

    @property
    def declares_consumer(self) -> bool:
        return USAGE_PAGE_CONSUMER in self.usage_pages

    @property
    def declares_vendor_defined(self) -> bool:
        return any(p >= 0xFF00 for p in self.usage_pages)


def _signed(value: int, size: int) -> int:
    """Interpret `value` (size bytes) as signed two's complement."""
    if size == 0:
        return 0
    sign_bit = 1 << (size * 8 - 1)
    return (value ^ sign_bit) - sign_bit


def parse_report_descriptor(data: bytes) -> DescriptorSummary:
    """Parse a HID report descriptor into a safe summary.

    Raises DescriptorError on malformed input. Records non-fatal oddities in
    `summary.anomalies` (these feed the risk analyzer).
    """
    if not isinstance(data, (bytes, bytearray)):
        raise DescriptorError("descriptor must be bytes")
    if len(data) == 0:
        raise DescriptorError("empty descriptor")
    if len(data) > MAX_DESCRIPTOR_LEN:
        raise DescriptorError(
            f"descriptor too large: {len(data)} > {MAX_DESCRIPTOR_LEN} bytes"
        )

    summary = DescriptorSummary()

    # Parser state (globals persist; locals reset per main item).
    usage_page = 0
    report_size = 0
    report_count = 0
    report_id: int | None = None
    collection_depth = 0
    global_stack: list[tuple[int, int, int, int | None]] = []

    i = 0
    n = len(data)
    while i < n:
        summary.item_count += 1
        if summary.item_count > MAX_ITEMS:
            raise DescriptorError("too many items (possible hostile/looping descriptor)")

        prefix = data[i]
        i += 1

        # Long items (prefix 0xFE) — rare; parse length safely and skip.
        if prefix == 0xFE:
            if i + 1 >= n:
                raise DescriptorError("truncated long item header")
            data_size = data[i]
            i += 2  # bDataSize + bLongItemTag
            if i + data_size > n:
                raise DescriptorError("truncated long item body")
            i += data_size
            summary.anomalies.append("contains long items (unusual for input devices)")
            continue

        # Short item: bSize(2) | bType(2) | bTag(4)
        size_code = prefix & 0x03
        item_size = 4 if size_code == 3 else size_code
        item_type = (prefix >> 2) & 0x03
        item_tag = (prefix >> 4) & 0x0F

        if i + item_size > n:
            raise DescriptorError(
                f"truncated item at offset {i - 1}: needs {item_size} data bytes"
            )
        raw = int.from_bytes(data[i : i + item_size], "little")
        i += item_size

        if item_type == ITEM_TYPE_GLOBAL:
            if item_tag == TAG_USAGE_PAGE:
                usage_page = raw & 0xFFFF
                summary.usage_pages.add(usage_page)
            elif item_tag == TAG_REPORT_SIZE:
                report_size = raw
                if report_size > MAX_REPORT_SIZE_BITS:
                    raise DescriptorError(
                        f"Report Size {report_size} exceeds sane bound {MAX_REPORT_SIZE_BITS}"
                    )
            elif item_tag == TAG_REPORT_COUNT:
                report_count = raw
                if report_count > MAX_REPORT_COUNT:
                    raise DescriptorError(
                        f"Report Count {report_count} exceeds sane bound {MAX_REPORT_COUNT}"
                    )
            elif item_tag == TAG_REPORT_ID:
                report_id = raw & 0xFF
                if report_id == 0:
                    summary.anomalies.append("Report ID 0 declared (reserved/invalid)")
                summary.report_ids.add(report_id)
            elif item_tag == TAG_PUSH:
                if len(global_stack) > MAX_COLLECTION_DEPTH:
                    raise DescriptorError("global Push stack too deep")
                global_stack.append((usage_page, report_size, report_count, report_id))
            elif item_tag == TAG_POP:
                if not global_stack:
                    raise DescriptorError("Pop without matching Push")
                usage_page, report_size, report_count, report_id = global_stack.pop()
            # Logical min/max parsed for completeness but not needed for summary.
            elif item_tag in (TAG_LOGICAL_MIN, TAG_LOGICAL_MAX):
                _ = _signed(raw, item_size)

        elif item_type == ITEM_TYPE_MAIN:
            if item_tag == TAG_COLLECTION:
                collection_depth += 1
                if collection_depth > MAX_COLLECTION_DEPTH:
                    raise DescriptorError("collection nesting too deep")
            elif item_tag == TAG_END_COLLECTION:
                collection_depth -= 1
                if collection_depth < 0:
                    raise DescriptorError("End Collection without matching Collection")
            elif item_tag in (TAG_INPUT, TAG_OUTPUT, TAG_FEATURE):
                kind = {TAG_INPUT: "input", TAG_OUTPUT: "output", TAG_FEATURE: "feature"}[
                    item_tag
                ]
                fld = ReportField(
                    kind=kind,
                    usage_page=usage_page,
                    report_size_bits=report_size,
                    report_count=report_count,
                    report_id=report_id,
                )
                summary.fields.append(fld)
                if kind == "input":
                    summary.total_input_bits += report_size * report_count
            # locals reset after each main item (we don't track usages in detail here)

        # local items (usages, etc.) — accepted; detailed usage tracking omitted
        # for the summary. We only need pages + structure for risk analysis.

    if collection_depth != 0:
        summary.anomalies.append(
            f"unbalanced collections (depth {collection_depth} at end)"
        )
    if global_stack:
        summary.anomalies.append(f"{len(global_stack)} unmatched Push item(s)")
    if summary.total_input_bits > MAX_REPORT_SIZE_BITS * MAX_REPORT_COUNT:
        summary.anomalies.append("implausibly large total input report size")

    return summary
