"""Policy: tunable thresholds and allow-lists for risk scoring.

Kept separate from the analyzer so operators can tune detection without touching
detection logic (docs/detection.md §3). Defaults are conservative starting
points grounded in the reasoning in docs/detection.md, NOT authoritative
constants — they are meant to be tuned per environment and per-device baseline.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Policy:
    # --- Behavioral thresholds ---
    # Sustained keystrokes/sec above which input is suspicious. Human fast typing
    # is ~8-12 keystrokes/sec in bursts; barcode scanners/macro pads can exceed
    # this legitimately, hence allow-listing exists.
    max_human_keystroke_rate: float = 20.0
    # Rate that is essentially impossible for a human, regardless of device.
    impossible_keystroke_rate: float = 60.0
    # Milliseconds after enumeration within which input implies no human.
    min_human_reaction_ms: float = 250.0
    # Very fast: input within this window means automation with high confidence.
    injection_reaction_ms: float = 50.0
    # Inter-keystroke timing variance (stdev, seconds) below which timing looks
    # machine-generated. Humans have jitter; scripts often don't.
    min_human_jitter_stdev_s: float = 0.004
    # Minimum number of keystrokes before jitter/rate verdicts are trusted.
    min_samples_for_timing: int = 8

    # --- Device allow-listing / baselining ---
    # VID:PID strings known-good in this environment (skip identity flags).
    allowlist_vid_pid: set[str] = field(default_factory=set)
    # VID:PID known to legitimately behave like fast injectors (barcode scanners,
    # macro pads). They still get monitored but rate flags are downgraded.
    fast_input_allowlist: set[str] = field(default_factory=set)

    def is_allowlisted(self, vid_pid: str) -> bool:
        return vid_pid in self.allowlist_vid_pid

    def is_fast_input_allowlisted(self, vid_pid: str) -> bool:
        return vid_pid in self.fast_input_allowlist


DEFAULT_POLICY = Policy()
