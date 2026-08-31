"""Smoke tests for the CLI entry point (argument parsing + subcommands)."""

from __future__ import annotations

import pytest

from hidwatch.cli import main


def test_version_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "hidwatch" in capsys.readouterr().out


def test_inspect_demo_benign(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["inspect", "--demo", "benign-keyboard"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Risk:" in out
    assert "LOW" in out


def test_analyze_demo_badusb_returns_nonzero_risk(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = main(["analyze", "--demo", "badusb-flashdrive"])
    out = capsys.readouterr().out
    # exit code 2 signals HIGH+ risk (useful for scripting/CI gating).
    assert rc == 2
    assert "CRITICAL" in out


def test_descriptor_subcommand(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["descriptor", "05010906A1010507" "19E029E7150025017501" "95088102C0"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Usage pages" in out


def test_descriptor_malformed_returns_2(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["descriptor", "07"])  # truncated Usage Page item
    out = capsys.readouterr().out
    assert rc == 2
    assert "MALFORMED" in out


def test_policy_subcommand(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["policy"])
    assert rc == 0
    assert "keystroke_rate" in capsys.readouterr().out


def test_list_degrades_without_backend(capsys: pytest.CaptureFixture[str]) -> None:
    # Should never crash even if sysfs is unavailable/unreadable.
    rc = main(["list"])
    assert rc == 0
