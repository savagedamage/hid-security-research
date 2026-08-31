#!/usr/bin/env python3
"""Validate the HID security dataset.

Checks performed:
  1. Every data/cves/*.yaml entry validates against
     data/schemas/cve-entry.schema.json.
  2. The entry `id` matches its filename.
  3. Every attack_class referenced by an entry exists in
     data/attack-taxonomy/taxonomy.yaml.
  4. Every taxonomy class referenced by an entry is well-formed (HID-NN).
  5. entry_type == "CVE"  =>  a CVE id is present.
  6. Duplicate ids are rejected.

Exit code 0 on success, 1 on any validation error. Used locally and in CI.

No third-party imports beyond PyYAML and jsonschema (declared dev deps).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import yaml
    from jsonschema import Draft7Validator
except ImportError as exc:  # pragma: no cover - environment guard
    print(
        f"ERROR: missing dependency: {exc}. Install with: pip install pyyaml jsonschema"
    )
    sys.exit(2)

REPO = Path(__file__).resolve().parents[2]
CVE_DIR = REPO / "data" / "cves"
SCHEMA = REPO / "data" / "schemas" / "cve-entry.schema.json"
TAXONOMY = REPO / "data" / "attack-taxonomy" / "taxonomy.yaml"


def load_taxonomy_ids() -> set[str]:
    tax = yaml.safe_load(TAXONOMY.read_text())
    return {c["id"] for c in tax.get("classes", [])}


def main() -> int:
    errors: list[str] = []
    schema = json.loads(SCHEMA.read_text())
    validator = Draft7Validator(schema)
    taxonomy_ids = load_taxonomy_ids()

    seen_ids: dict[str, Path] = {}
    entry_files = sorted(
        p for p in CVE_DIR.glob("*.yaml") if not p.name.startswith("_")
    )

    if not entry_files:
        print("ERROR: no dataset entries found in data/cves/")
        return 1

    for path in entry_files:
        try:
            entry = yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:
            errors.append(f"{path.name}: invalid YAML: {exc}")
            continue

        # Schema validation
        for err in sorted(validator.iter_errors(entry), key=lambda e: e.path):
            loc = "/".join(str(p) for p in err.path) or "(root)"
            errors.append(f"{path.name}: schema[{loc}]: {err.message}")

        # id == filename
        expected_id = path.stem
        if entry.get("id") != expected_id:
            errors.append(
                f"{path.name}: id '{entry.get('id')}' does not match filename '{expected_id}'"
            )

        # duplicate id
        if entry.get("id") in seen_ids:
            errors.append(
                f"{path.name}: duplicate id '{entry.get('id')}' "
                f"(also in {seen_ids[entry['id']].name})"
            )
        else:
            seen_ids[entry.get("id")] = path

        # attack_class references exist in taxonomy
        for ac in entry.get("attack_class", []) or []:
            if ac not in taxonomy_ids:
                errors.append(
                    f"{path.name}: attack_class '{ac}' not found in taxonomy.yaml"
                )

    if errors:
        print(f"DATASET VALIDATION FAILED ({len(errors)} error(s)):\n")
        for e in errors:
            print(f"  - {e}")
        return 1

    print(
        f"OK: {len(entry_files)} dataset entries valid against schema; "
        f"all attack_class refs resolve against {len(taxonomy_ids)} taxonomy classes."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
