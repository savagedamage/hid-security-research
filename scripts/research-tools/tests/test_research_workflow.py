from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft7Validator, FormatChecker

REPO = Path(__file__).resolve().parents[3]
TOOLS = REPO / "scripts" / "research-tools"


def load_script(name: str):
    path = TOOLS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_committed_coverage_report_is_current() -> None:
    coverage = load_script("build_coverage")
    assert coverage.OUTPUT_PATH.read_text() == coverage.build()


def test_coverage_exposes_known_catalog_gaps() -> None:
    coverage = load_script("build_coverage")
    report = coverage.build()
    assert "`HID-09` — Companion Software Compromise" in report
    assert "`HID-10` — Firmware Update Abuse" in report
    assert "`Windows` | 0 | **gap**" in report
    assert "`COMPANION_TO_HOST` | 0 | **gap**" in report


def test_candidate_queue_validates() -> None:
    schema = json.loads(
        (REPO / "data/schemas/research-candidate.schema.json").read_text()
    )
    queue = yaml.safe_load((REPO / "data/research-queue/candidates.yaml").read_text())
    errors = list(
        Draft7Validator(schema, format_checker=FormatChecker()).iter_errors(queue)
    )
    assert errors == []


@pytest.mark.parametrize("status", ["ready-for-entry", "rejected", "duplicate"])
def test_reviewed_candidate_statuses_require_review_date(status: str) -> None:
    schema = json.loads(
        (REPO / "data/schemas/research-candidate.schema.json").read_text()
    )
    candidate = {
        "version": "0.1.0",
        "last_reviewed": "2026-09-02",
        "candidates": [
            {
                "id": "candidate-0001",
                "title": "Synthetic test candidate",
                "discovered_from": "test",
                "source_url": "https://example.invalid/advisory",
                "discovered_on": "2026-09-02",
                "possible_attack_classes": [],
                "possible_directions": [],
                "possible_platforms": [],
                "possible_transports": [],
                "target_record_type": "CVE",
                "status": status,
                "hid_relevance": (
                    "HID is materially involved in this synthetic schema test."
                    if status == "ready-for-entry"
                    else None
                ),
                "review_notes": (
                    "Rejected or duplicate for this synthetic schema test."
                    if status != "ready-for-entry"
                    else None
                ),
                "reviewed_on": None,
            }
        ],
    }
    errors = list(
        Draft7Validator(schema, format_checker=FormatChecker()).iter_errors(candidate)
    )
    assert errors


def test_noncanonical_candidate_kind_cannot_be_ready_for_entry() -> None:
    schema = json.loads(
        (REPO / "data/schemas/research-candidate.schema.json").read_text()
    )
    queue = {
        "version": "0.1.0",
        "last_reviewed": "2026-09-02",
        "candidates": [
            {
                "id": "candidate-0001",
                "title": "Synthetic malware research lead",
                "discovered_from": "test",
                "source_url": "https://example.invalid/report",
                "discovered_on": "2026-09-02",
                "possible_attack_classes": ["HID-02"],
                "possible_directions": ["DEVICE_TO_HOST"],
                "possible_platforms": ["Linux"],
                "possible_transports": ["usb"],
                "target_record_type": "malware-or-campaign",
                "status": "ready-for-entry",
                "hid_relevance": "HID is material to this synthetic schema-only test lead.",
                "review_notes": None,
                "reviewed_on": "2026-09-02",
            }
        ],
    }
    errors = list(
        Draft7Validator(schema, format_checker=FormatChecker()).iter_errors(queue)
    )
    assert errors
