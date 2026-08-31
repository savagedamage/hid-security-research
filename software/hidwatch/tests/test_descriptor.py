"""Tests for the defensive HID report-descriptor parser.

The parser consumes fully attacker-controlled input, so robustness (never crash,
never hang, never OOB) is a security property. These tests include hostile and
random inputs.
"""

from __future__ import annotations

import random

import pytest

from hidwatch.descriptor import DescriptorError, parse_report_descriptor
from hidwatch.fixtures import BOOT_KEYBOARD_DESCRIPTOR


def test_boot_keyboard_parses() -> None:
    summ = parse_report_descriptor(BOOT_KEYBOARD_DESCRIPTOR)
    assert summ.declares_keyboard
    assert not summ.declares_vendor_defined
    # 8 modifier bits + 8 reserved + 6*8 keycodes = 64 input bits
    assert summ.total_input_bits == 64
    assert summ.anomalies == []


def test_empty_descriptor_rejected() -> None:
    with pytest.raises(DescriptorError):
        parse_report_descriptor(b"")


def test_non_bytes_rejected() -> None:
    with pytest.raises(DescriptorError):
        parse_report_descriptor("not bytes")  # type: ignore[arg-type]


def test_oversized_descriptor_rejected() -> None:
    with pytest.raises(DescriptorError):
        parse_report_descriptor(b"\x00" * 5000)


def test_truncated_item_rejected() -> None:
    # 0x06 = Usage Page, 4-byte data, but no data bytes follow.
    with pytest.raises(DescriptorError):
        parse_report_descriptor(bytes([0x07]))


def test_absurd_report_size_rejected() -> None:
    # Report Size = 255 (0x75 0xFF) exceeds sane bound.
    with pytest.raises(DescriptorError):
        parse_report_descriptor(bytes([0x75, 0xFF]))


def test_absurd_report_count_rejected() -> None:
    # Report Count = 0xFFFF via 2-byte item.
    with pytest.raises(DescriptorError):
        parse_report_descriptor(bytes([0x96, 0xFF, 0xFF]))


def test_pop_without_push_rejected() -> None:
    with pytest.raises(DescriptorError):
        parse_report_descriptor(bytes([0xB4]))  # Pop (global tag 0xB, size 0)


def test_end_collection_without_collection_rejected() -> None:
    with pytest.raises(DescriptorError):
        parse_report_descriptor(bytes([0xC0]))  # End Collection with no open one


def test_report_id_zero_is_anomaly() -> None:
    # Usage Page GD, Report ID 0, then a benign input to keep it going.
    desc = bytes([0x05, 0x01, 0x85, 0x00, 0x75, 0x08, 0x95, 0x01, 0x81, 0x00])
    summ = parse_report_descriptor(desc)
    assert any("Report ID 0" in a for a in summ.anomalies)


def test_unbalanced_collection_is_anomaly() -> None:
    desc = bytes([0x05, 0x01, 0x09, 0x06, 0xA1, 0x01])  # open collection, never close
    summ = parse_report_descriptor(desc)
    assert any("unbalanced" in a for a in summ.anomalies)


def test_vendor_defined_usage_page_detected() -> None:
    # Usage Page 0xFF00 (2-byte data): 0x06 0x00 0xFF
    desc = bytes([0x06, 0x00, 0xFF, 0x75, 0x08, 0x95, 0x01, 0x81, 0x00])
    summ = parse_report_descriptor(desc)
    assert summ.declares_vendor_defined


@pytest.mark.parametrize("seed", range(50))
def test_fuzz_random_bytes_never_crashes(seed: int) -> None:
    """Random inputs must raise DescriptorError or return cleanly — never crash."""
    rng = random.Random(seed)
    length = rng.randint(1, 300)
    data = bytes(rng.randrange(256) for _ in range(length))
    try:
        summ = parse_report_descriptor(data)
    except DescriptorError:
        return
    # If it parsed, the summary must be well-formed.
    assert summ.item_count >= 0
    assert summ.total_input_bits >= 0


def test_fuzz_truncations_of_valid_descriptor() -> None:
    """Every prefix of a valid descriptor must parse-or-raise, never crash."""
    for k in range(1, len(BOOT_KEYBOARD_DESCRIPTOR) + 1):
        try:
            parse_report_descriptor(BOOT_KEYBOARD_DESCRIPTOR[:k])
        except DescriptorError:
            pass
