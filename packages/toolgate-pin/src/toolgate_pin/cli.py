"""toolgate-pin command line interface (stdlib argparse)."""

from __future__ import annotations

import argparse
from collections.abc import Sequence


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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "demo":
        from toolgate_pin.commands import demo

        return demo.run(args.no_fail)
    if args.command == "demo-server":
        from toolgate_pin.demo_server import build_demo_server

        build_demo_server(mutated=args.mutated).run("stdio")
        return 0
    return 2  # pragma: no cover  (later tasks register more subcommands)


if __name__ == "__main__":
    raise SystemExit(main())
