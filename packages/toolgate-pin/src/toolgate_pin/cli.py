"""toolgate-pin command line interface (stdlib argparse)."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

from toolgate_pin.connect import UsageError
from toolgate_pin.models import Target

DEFAULT_LOCKFILE = "toolgate.lock.json"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="toolgate-pin",
        description="Pin MCP tool definitions and quarantine any that change.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser(
        "demo", help="offline demo: pin a bundled server, catch a poisoned tool"
    )
    demo.add_argument(
        "--no-fail",
        action="store_true",
        help="exit 0 even though a tool is quarantined",
    )

    server = sub.add_parser("demo-server", help="run the bundled demo MCP server")
    server.add_argument(
        "--mutated", action="store_true", help="serve the poisoned tool description"
    )
    approve = sub.add_parser(
        "approve", help="review new or changed tools on a server and pin them"
    )
    _add_target(approve)
    approve.add_argument(
        "--header",
        action="append",
        default=[],
        metavar='"K: V"',
        help="request header template; the value must use ${ENV_VAR} (repeatable)",
    )
    approve.add_argument("--as", dest="approver", metavar="NAME", help="approver")
    approve.add_argument("--yes", action="store_true", help="skip the confirmation")
    approve.add_argument(
        "--override",
        metavar="REASON",
        help="approve even though a tier judged a tool malicious",
    )
    approve.add_argument(
        "--classifier", action="store_true", help="also run the classifier tier"
    )
    approve.add_argument("--judge", action="store_true", help="also run the LLM judge")

    check = sub.add_parser(
        "check", help="fail if any pinned server's tools changed (CI form: no target)"
    )
    _add_target(check)
    check.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def _add_target(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "target",
        nargs="*",
        help="http(s) URL, or with --stdio the server command after --",
    )
    p.add_argument(
        "--stdio", action="store_true", help="run a stdio server: --stdio -- CMD..."
    )
    p.add_argument("--name", metavar="ID", help="server id (default: serverInfo.name)")
    p.add_argument(
        "--lockfile", default=DEFAULT_LOCKFILE, metavar="PATH", help="lockfile path"
    )


def _target(args: argparse.Namespace, headers: Sequence[str] = ()) -> Target | None:
    """Target from argv, or None for none. Raises UsageError."""
    words = list(args.target)
    if args.stdio:
        if not words:
            raise UsageError("--stdio needs a command: --stdio -- CMD [ARGS...]")
        return Target(command=tuple(words), headers=tuple(headers))
    if not words:
        return None
    if len(words) != 1 or not words[0].startswith(("http://", "https://")):
        raise UsageError(
            "a target is an http(s):// URL, or --stdio -- CMD [ARGS...] for stdio"
        )
    return Target(url=words[0], headers=tuple(headers))


def _usage_error(command: str, exc: UsageError) -> int:
    print(f"toolgate-pin {command}: {exc}", file=sys.stderr)
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "demo":
        from toolgate_pin.commands import demo

        return demo.run(args.no_fail)
    if args.command == "demo-server":
        from toolgate_pin.demo_server import build_demo_server

        server = build_demo_server(mutated=args.mutated)
        logging.getLogger("mcp").setLevel(logging.WARNING)  # quiet per-request INFO
        server.run("stdio")
        return 0
    if args.command == "approve":
        from toolgate_pin.commands import approve as approve_cmd

        try:
            target = _target(args, args.header)
        except UsageError as exc:
            return _usage_error("approve", exc)
        if target is None:
            return _usage_error(
                "approve", UsageError("give a URL or --stdio -- CMD [ARGS...]")
            )
        tiers = ["rules"]
        if args.classifier:
            tiers.append("classifier")
        if args.judge:
            tiers.append("judge")
        return approve_cmd.run(
            target,
            name=args.name,
            lockfile=args.lockfile,
            approver=args.approver,
            yes=args.yes,
            override=args.override,
            tiers=tiers,
        )
    if args.command == "check":
        from toolgate_pin.commands import check as check_cmd

        try:
            target = _target(args)
        except UsageError as exc:
            return _usage_error("check", exc)
        return check_cmd.run(
            target, name=args.name, lockfile=args.lockfile, fmt=args.format
        )
    return 2  # pragma: no cover  (later tasks register more subcommands)


if __name__ == "__main__":
    raise SystemExit(main())
