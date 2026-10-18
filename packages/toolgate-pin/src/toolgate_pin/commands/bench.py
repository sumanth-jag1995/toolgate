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

    The judge is built only when requested and OPENROUTER_API_KEY is set; a
    missing scorer is reported unavailable by run_bench. (The classifier is
    built by a later task.)
    """
    judge = None
    if "judge" in tiers:
        from toolgate_pin.scanner.judge import Judge

        judge = Judge.from_env(use_cache=not no_cache)
    return None, judge


def run(*, split: str, tiers: str | None, fmt: str, no_cache: bool) -> int:
    """Always exits 0: bench reports, it never gates."""
    if tiers is None:
        # Auto mode builds scorers for the tiers available here but requests
        # every tier, so the ones that cannot run are listed as unavailable.
        available = auto_tiers()
        chosen = TIERS
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
        available = chosen
    classifier, judge = _tier_objects(available, no_cache)
    result = run_bench(
        split=split,  # type: ignore[arg-type]
        tiers=chosen,
        judge=judge,
        classifier=classifier,
    )
    if fmt in ("md", "json"):
        _utf8_when_redirected(sys.stdout)
    safe_print(render(result, fmt))  # type: ignore[arg-type]
    return 0


def _utf8_when_redirected(stream: Any) -> None:
    """md/json are files for READMEs and tools: write UTF-8 when redirected,
    whatever the console code page (a TTY keeps safe_print's fallback)."""
    try:
        if stream.isatty():
            return
        stream.reconfigure(encoding="utf-8")
    except (AttributeError, OSError, ValueError):
        pass  # not a TextIOWrapper (e.g. a test capture): leave it alone
