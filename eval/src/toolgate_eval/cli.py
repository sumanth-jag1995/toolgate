"""``toolgate-eval``: check-env, run, report, loadtest (Task 9).

Exit codes: 0 ok, 1 environment check failed, 2 usage/config error or not yet
available, 3 the model API's daily quota is exhausted (resume later).
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from servicing_agent.config import ConfigError

from toolgate_eval import runner
from toolgate_eval.world import WorldError

EXIT_QUOTA = 3


def _csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def _conditions(value: str) -> list[str]:
    items = _csv(value)
    bad = [c for c in items if c not in runner.CONDITIONS]
    if bad or not items:
        raise argparse.ArgumentTypeError(f"conditions must be from {runner.CONDITIONS}")
    return items


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="toolgate-eval")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("check-env", help="check the stack and the API key (names only)")
    run = sub.add_parser("run", help="run (or resume) the evaluation matrix")
    run.add_argument("--models", type=Path, default=Path("eval/models.yaml"))
    run.add_argument("--conditions", type=_conditions, default=list(runner.CONDITIONS))
    run.add_argument("--repeats", type=int, default=3)
    run.add_argument("--results", type=Path, default=Path("eval/results/run.jsonl"))
    run.add_argument("--max-episodes", type=int, default=None)
    run.add_argument("--variants", type=_csv, default=None)
    run.add_argument(
        "--keep-errors",
        action="store_true",
        help="treat recorded error episodes as done instead of retrying them",
    )
    only = run.add_mutually_exclusive_group()
    only.add_argument("--clean-only", action="store_true")
    only.add_argument("--attack-only", action="store_true")
    rep = sub.add_parser("report", help="summarise a results file")
    rep.add_argument("--results", type=Path, default=Path("eval/results/run.jsonl"))
    rep.add_argument("--format", choices=("text", "md", "json"), default="text")
    rep.add_argument(
        "--corpus-hash",
        default=None,
        help="corpus to report (default: the corpus of the last record)",
    )
    sub.add_parser("loadtest", help="gateway load test")
    return p


def _check_env() -> int:
    checks = runner.check_env()
    for name, ok in checks:
        print(f"{name}: {'ok' if ok else 'missing'}")
    return 0 if all(ok for _, ok in checks) else 1


def _run(args: argparse.Namespace) -> int:
    opts = runner.RunOptions(
        models_path=args.models,
        conditions=args.conditions,
        repeats=args.repeats,
        results_path=args.results,
        max_episodes=args.max_episodes,
        variants=args.variants,
        attack=not args.clean_only,
        clean=not args.attack_only,
        keep_errors=args.keep_errors,
    )
    try:
        summary = asyncio.run(runner.run_cli(opts))
    except (ConfigError, runner.RunnerError, WorldError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        f"ran {summary.ran}, skipped {summary.skipped}, errors {summary.errors}, "
        f"leaked {summary.leaked}, stopped {summary.stopped or 'no'}"
    )
    if summary.stopped == "quota":
        print("model API quota exhausted: re-run the same command later to resume")
        return EXIT_QUOTA
    return 0


def _report(args: argparse.Namespace) -> int:
    from toolgate_pin.reveal import safe_print

    from toolgate_eval.report import load_records, render, summarise

    if not args.results.is_file():
        print(f"error: no results file {args.results}", file=sys.stderr)
        return 2
    summary = summarise(load_records(args.results), corpus_hash=args.corpus_hash)
    if args.format in ("md", "json"):
        _utf8_when_redirected(sys.stdout)
    safe_print(render(summary, args.format))
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


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "check-env":
        return _check_env()
    if args.command == "run":
        return _run(args)
    if args.command == "report":
        return _report(args)
    print("loadtest not available yet")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
