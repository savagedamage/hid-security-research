#!/usr/bin/env python3
"""Validate discovery-stage HID research candidates.

The candidate queue is deliberately separate from the canonical catalog. This
validator checks its JSON Schema, stable-ID uniqueness, and taxonomy references.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import yaml
    from jsonschema import Draft7Validator, FormatChecker
except ImportError as exc:  # pragma: no cover - environment guard
    print(
        f"ERROR: missing dependency: {exc}. Install with: pip install pyyaml jsonschema"
    )
    sys.exit(2)

REPO = Path(__file__).resolve().parents[2]
QUEUE = REPO / "data" / "research-queue" / "candidates.yaml"
SCHEMA = REPO / "data" / "schemas" / "research-candidate.schema.json"
TAXONOMY = REPO / "data" / "attack-taxonomy" / "taxonomy.yaml"


def main() -> int:
    errors: list[str] = []

    try:
        queue = yaml.safe_load(QUEUE.read_text())
    except yaml.YAMLError as exc:
        print(f"RESEARCH QUEUE VALIDATION FAILED:\n\n  - invalid YAML: {exc}")
        return 1

    schema = json.loads(SCHEMA.read_text())
    validator = Draft7Validator(schema, format_checker=FormatChecker())
    for err in sorted(validator.iter_errors(queue), key=lambda item: list(item.path)):
        location = "/".join(str(part) for part in err.path) or "(root)"
        errors.append(f"schema[{location}]: {err.message}")

    taxonomy = yaml.safe_load(TAXONOMY.read_text())
    taxonomy_ids = {item["id"] for item in taxonomy.get("classes", [])}
    seen_ids: set[str] = set()
    candidates = queue.get("candidates", []) if isinstance(queue, dict) else []

    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        candidate_id = candidate.get("id")
        if candidate_id in seen_ids:
            errors.append(f"duplicate candidate id: {candidate_id}")
        elif isinstance(candidate_id, str):
            seen_ids.add(candidate_id)

        for attack_class in candidate.get("possible_attack_classes", []) or []:
            if attack_class not in taxonomy_ids:
                errors.append(
                    f"{candidate_id}: attack class '{attack_class}' not found in taxonomy.yaml"
                )

    if errors:
        print(f"RESEARCH QUEUE VALIDATION FAILED ({len(errors)} error(s)):\n")
        for error in errors:
            print(f"  - {error}")
        return 1

    print(
        f"OK: {len(candidates)} research candidate(s) valid; "
        f"all attack-class refs resolve against {len(taxonomy_ids)} taxonomy classes."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
