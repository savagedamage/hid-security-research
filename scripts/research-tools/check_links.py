#!/usr/bin/env python3
"""Validate repository-local Markdown links without network access."""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PATTERN = re.compile(r"\[[^]]+\]\(([^)]+)\)")


def main() -> int:
    missing: list[tuple[Path, str]] = []
    checked = 0
    for page in REPO.rglob("*.md"):
        if ".git" in page.parts or ".pytest_cache" in page.parts:
            continue
        for target in PATTERN.findall(page.read_text(errors="replace")):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            local = target.split("#", 1)[0]
            if not local:
                continue
            checked += 1
            if not (page.parent / local).resolve().exists():
                missing.append((page.relative_to(REPO), target))
    if missing:
        print(f"FAILED: {len(missing)} missing local Markdown link(s):")
        for page, target in missing:
            print(f"  {page}: {target}")
        return 1
    print(f"OK: {checked} local Markdown links resolve.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
