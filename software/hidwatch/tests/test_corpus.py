"""Corpus tests: every lab/fixtures/*.json scenario must analyze to at least its
declared expected risk band. Keeps fixtures and detector honest together.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from hidwatch.analyzer import analyze
from hidwatch.fixtures import load_scenario
from hidwatch.models import RiskLevel
from hidwatch.policy import Policy

FIXTURES_DIR = Path(__file__).resolve().parents[3] / "lab" / "fixtures"

SCENARIOS = sorted(FIXTURES_DIR.glob("*.json")) if FIXTURES_DIR.is_dir() else []

# The barcode scanner is a known benign fast-typer; with its VID:PID allow-listed
# its residual risk should drop to MEDIUM (demonstrating false-positive control).
FAST_INPUT_ALLOWLIST = {"05e0:1200"}


@pytest.mark.skipif(not SCENARIOS, reason="fixtures directory not found")
@pytest.mark.parametrize("path", SCENARIOS, ids=lambda p: p.name)
def test_scenario_meets_expected_risk(path: Path) -> None:
    scn = load_scenario(path)
    report = analyze(scn["device"], scn["events"], attach_time=scn["attach_time"])
    expected = RiskLevel[scn["expected_risk"]]
    assert report.level == expected, (
        f"{path.name}: expected {expected}, got {report.level}; "
        f"reasons={report.reasons()}"
    )


def test_barcode_scanner_downgrades_with_allowlist() -> None:
    path = FIXTURES_DIR / "benign-barcode-scanner.json"
    if not path.exists():
        pytest.skip("scanner fixture missing")
    scn = load_scenario(path)
    policy = Policy(fast_input_allowlist=FAST_INPUT_ALLOWLIST)
    report = analyze(
        scn["device"], scn["events"], policy=policy, attach_time=scn["attach_time"]
    )
    # Allow-listing a legitimate fast typer must reduce its risk below HIGH.
    assert report.level < RiskLevel.HIGH


def test_all_scenarios_have_names() -> None:
    for path in SCENARIOS:
        scn = load_scenario(path)
        assert scn["name"]
        assert scn["expected_risk"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
