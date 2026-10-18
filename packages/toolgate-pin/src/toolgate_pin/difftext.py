"""Unified diffs of tool definitions with hidden characters revealed."""

from __future__ import annotations

import difflib
import json
from typing import Any

from toolgate_pin.reveal import reveal


def _lines(defn: dict[str, Any] | None) -> list[str]:
    if defn is None:
        return []
    return json.dumps(defn, indent=2, sort_keys=True, ensure_ascii=False).split("\n")


def diff(pinned: dict[str, Any] | None, observed: dict[str, Any] | None) -> str:
    a, b = _lines(pinned), _lines(observed)
    if a == b and (pinned is None) == (observed is None):
        return ""
    out = difflib.unified_diff(a, b, fromfile="pinned", tofile="observed", lineterm="")
    return "\n".join(reveal(line) for line in out)
