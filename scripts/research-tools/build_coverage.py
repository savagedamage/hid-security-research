#!/usr/bin/env python3
"""Generate a deterministic coverage report for the HID research catalog.

Coverage counts are associations, not mutually exclusive totals: one catalog
entry can reference several classes, directions, platforms, or transports.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Iterable
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CATALOG_DIR = REPO / "data" / "cves"
TAXONOMY_PATH = REPO / "data" / "attack-taxonomy" / "taxonomy.yaml"
CATALOG_SCHEMA_PATH = REPO / "data" / "schemas" / "cve-entry.schema.json"
CANDIDATE_SCHEMA_PATH = REPO / "data" / "schemas" / "research-candidate.schema.json"
QUEUE_PATH = REPO / "data" / "research-queue" / "candidates.yaml"
OUTPUT_PATH = REPO / "research" / "coverage.md"

# Deliberate review targets. Values not listed here are still shown as observed
# extras, but these targets make important zero-coverage platforms visible.
TARGET_PLATFORMS = (
    "Android",
    "ChromeOS",
    "Linux",
    "Windows",
    "macOS",
    "iOS",
    "RTOS",
    "hardware",
    "cross-platform",
)


def load_yaml(path: Path) -> dict:
    value = yaml.safe_load(path.read_text())
    if not isinstance(value, dict):
        raise TypeError(f"{path.relative_to(REPO)} must contain a YAML mapping")
    return value


def load_entries() -> list[dict]:
    return [
        load_yaml(path)
        for path in sorted(CATALOG_DIR.glob("*.yaml"))
        if not path.name.startswith("_")
    ]


def count_values(entries: Iterable[dict], field: str) -> Counter[str]:
    counts: Counter[str] = Counter()
    for entry in entries:
        values = entry.get(field, []) or []
        if isinstance(values, str):
            values = [values]
        counts.update(str(value) for value in values)
    return counts


def schema_enum(schema: dict, *path: str) -> list[str]:
    value: object = schema
    for key in path:
        if not isinstance(value, dict):
            raise TypeError(f"schema path {'/'.join(path)} is not a mapping")
        value = value[key]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"schema path {'/'.join(path)} is not a string enum")
    return value


def coverage_table(
    title: str, label: str, ordered_values: Iterable[str], counts: Counter[str]
) -> list[str]:
    lines = [
        f"## {title}",
        "",
        f"| {label} | Records | Status |",
        "| --- | ---: | --- |",
    ]
    for value in ordered_values:
        count = counts[value]
        status = "covered" if count else "**gap**"
        lines.append(f"| `{value}` | {count} | {status} |")
    lines.append("")
    return lines


def frequency_table(
    title: str, label: str, ordered_values: Iterable[str], counts: Counter[str]
) -> list[str]:
    lines = [f"## {title}", "", f"| {label} | Records |", "| --- | ---: |"]
    for value in ordered_values:
        lines.append(f"| `{value}` | {counts[value]} |")
    lines.append("")
    return lines


def render_coverage(
    entries: list[dict],
    taxonomy: dict,
    catalog_schema: dict,
    candidate_schema: dict,
    queue: dict,
) -> str:
    class_counts = count_values(entries, "attack_class")
    direction_counts = count_values(entries, "attack_direction")
    platform_counts = count_values(entries, "platform")
    transport_counts = count_values(entries, "transport")
    type_counts = count_values(entries, "entry_type")
    evidence_counts = count_values(entries, "evidence")
    confidence_counts = count_values(entries, "confidence")

    classes = taxonomy.get("classes", [])
    directions = list((taxonomy.get("directions") or {}).keys())
    class_ids = [item["id"] for item in classes]
    uncovered_classes = [item for item in classes if not class_counts[item["id"]]]
    uncovered_directions = [
        value for value in directions if not direction_counts[value]
    ]

    observed_platforms = set(platform_counts)
    platforms = list(TARGET_PLATFORMS) + sorted(
        observed_platforms - set(TARGET_PLATFORMS)
    )
    uncovered_platforms = [
        value for value in TARGET_PLATFORMS if not platform_counts[value]
    ]

    transports = schema_enum(catalog_schema, "properties", "transport", "items", "enum")
    entry_types = schema_enum(catalog_schema, "properties", "entry_type", "enum")
    evidence_values = schema_enum(catalog_schema, "properties", "evidence", "enum")
    confidence_values = schema_enum(catalog_schema, "properties", "confidence", "enum")
    statuses = schema_enum(
        candidate_schema,
        "definitions",
        "candidate",
        "properties",
        "status",
        "enum",
    )

    candidates = queue.get("candidates", []) or []
    candidate_statuses: Counter[str] = Counter(
        str(candidate.get("status"))
        for candidate in candidates
        if isinstance(candidate, dict)
    )

    lines = [
        "# HID research catalog coverage",
        "",
        "> Auto-generated by `scripts/research-tools/build_coverage.py`. Do not edit by hand.",
        "> Counts describe catalog associations and may overlap because entries are multi-valued.",
        "",
        "## Snapshot",
        "",
        f"- Canonical records: **{len(entries)}**",
        f"- Taxonomy classes covered: **{len(class_ids) - len(uncovered_classes)} of {len(class_ids)}**",
        f"- Taxonomy classes with no record: **{len(uncovered_classes)}**",
        f"- Discovery candidates awaiting or preserving triage: **{len(candidates)}**",
        "",
        "A gap means only that the current catalog has no matching record. It does not",
        "show that no relevant vulnerability, attack, incident, or research exists.",
        "",
        "## Attack classes",
        "",
        "| Class | Name | Records | Status |",
        "| --- | --- | ---: | --- |",
    ]
    for item in classes:
        class_id = item["id"]
        count = class_counts[class_id]
        status = "covered" if count else "**gap**"
        lines.append(f"| `{class_id}` | {item['name']} | {count} | {status} |")
    lines.append("")

    lines += coverage_table(
        "Attack directions", "Direction", directions, direction_counts
    )
    lines += coverage_table(
        "Target platform coverage", "Platform", platforms, platform_counts
    )
    lines += frequency_table(
        "Transport associations", "Transport", transports, transport_counts
    )
    lines += frequency_table("Entry types", "Type", entry_types, type_counts)
    lines += frequency_table(
        "Evidence labels", "Evidence", evidence_values, evidence_counts
    )
    lines += frequency_table(
        "Confidence labels", "Confidence", confidence_values, confidence_counts
    )
    lines += frequency_table("Candidate queue", "Status", statuses, candidate_statuses)

    lines += ["## Immediate research priorities", ""]
    if uncovered_classes:
        lines.append("### Unrepresented taxonomy classes")
        lines.append("")
        for item in uncovered_classes:
            lines.append(f"- `{item['id']}` — {item['name']}")
        lines.append("")
    if uncovered_directions:
        lines.append("### Unrepresented attack directions")
        lines.append("")
        for value in uncovered_directions:
            lines.append(f"- `{value}`")
        lines.append("")
    if uncovered_platforms:
        lines.append("### Target platforms with no catalog record")
        lines.append("")
        for value in uncovered_platforms:
            lines.append(f"- `{value}`")
        lines.append("")

    lines += [
        "## How to use this report",
        "",
        "Use gaps to drive source discovery, then place leads in",
        "`data/research-queue/candidates.yaml`. Do not fill a gap with a weakly related",
        "record. Promotion still requires the evidence and inclusion checks in",
        "`research/scope-and-inclusion.md` and `CONTRIBUTING.md`.",
        "",
    ]
    return "\n".join(lines)


def build() -> str:
    return render_coverage(
        load_entries(),
        load_yaml(TAXONOMY_PATH),
        json.loads(CATALOG_SCHEMA_PATH.read_text()),
        json.loads(CANDIDATE_SCHEMA_PATH.read_text()),
        load_yaml(QUEUE_PATH),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="fail if the report is stale"
    )
    args = parser.parse_args()
    rendered = build()

    if args.check:
        if not OUTPUT_PATH.exists() or OUTPUT_PATH.read_text() != rendered:
            print(
                "Coverage report is out of date; run build_coverage.py and commit the result."
            )
            return 1
        print("OK: research coverage report is up to date.")
        return 0

    OUTPUT_PATH.write_text(rendered)
    print(
        f"Wrote {OUTPUT_PATH.relative_to(REPO)} from {len(load_entries())} catalog entries."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
