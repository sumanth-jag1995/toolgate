"""`toolgate-pin bench`: print the headline detection / false-positive table."""

from __future__ import annotations

import importlib
import os
import sys
from typing import Any

from toolgate_pin.bench import render, run_bench
from toolgate_pin.reveal import safe_print
from toolgate_pin.scanner import TIERS


def _classifier_available() -> bool:
    """True when the optional classifier tier (Task 10) can run here."""
    try:
        mod = importlib.import_module("toolgate_pin.scanner.classifier")
    except ImportError:
        return False
    available = getattr(mod, "available", None)
    try:
        return bool(available()) if callable(available) else False
    except Exception:  # noqa: BLE001  a broken optional tier is just unavailable
        return False


def auto_tiers() -> tuple[str, ...]:
    """rules always; classifier if installed; judge if OPENROUTER_API_KEY is set."""
    tiers = ["rules"]
    if _classifier_available():
        tiers.append("classifier")
    if os.environ.get("OPENROUTER_API_KEY"):
        tiers.append("judge")
    return tuple(tiers)


def _tier_objects(tiers: tuple[str, ...], no_cache: bool) -> tuple[Any, Any]:
    """(classifier, judge) scorers for the requested tiers.

    Tasks 10 and 11 build these; until then a requested classifier or judge is
    reported unavailable by run_bench.
    """
    del tiers, no_cache
    return None, None


def run(*, split: str, tiers: str | None, fmt: str, no_cache: bool) -> int:
    """Always exits 0: bench reports, it never gates."""
    if tiers is None:
        chosen = auto_tiers()
    else:
        chosen = tuple(t.strip() for t in tiers.split(",") if t.strip())
        unknown = [t for t in chosen if t not in TIERS]
        if unknown:
            print(
                f"toolgate-pin bench: unknown tier(s) ignored: {', '.join(unknown)}"
                f" (choose from {', '.join(TIERS)})",
                file=sys.stderr,
            )
            chosen = tuple(t for t in chosen if t in TIERS)
    classifier, judge = _tier_objects(chosen, no_cache)
    result = run_bench(
        split=split,  # type: ignore[arg-type]
        tiers=chosen,
        judge=judge,
        classifier=classifier,
    )
    safe_print(render(result, fmt))  # type: ignore[arg-type]
    return 0
