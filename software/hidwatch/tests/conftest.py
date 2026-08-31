"""Pytest configuration: make the src/ layout importable without an install.

Allows `pytest` to run directly (e.g. in restricted environments where the
editable install can't be built) by putting src/ on sys.path.
"""

from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
