"""`toolgate-pin demo`: pin a bundled server, poison one tool, show the catch."""

from __future__ import annotations

import asyncio
import logging
import sys
from typing import Any, TextIO

import mcp.types

from toolgate_pin.connect import in_memory_session
from toolgate_pin.demo_server import build_demo_server
from toolgate_pin.models import PinSet, Target
from toolgate_pin.pinner import Pinner
from toolgate_pin.pinning import pin_server
from toolgate_pin.reveal import decode_tag_text, safe_print
from toolgate_pin.store import InMemoryStore

SERVER_ID = "insurer-demo"


async def _list(mutated: bool) -> tuple[list[mcp.types.Tool], Any]:
    async with in_memory_session(build_demo_server(mutated=mutated)) as session:
        # The helper already initialized once; repeating it returns serverInfo.
        init = (await session.initialize()).serverInfo
        tools = (await session.list_tools()).tools
        return tools, init


def _ascii_brackets(text: str, out: TextIO) -> str:
    """diff() marks hidden characters with unicode brackets; use ASCII ones if
    the stream cannot encode them."""
    try:
        "⟦⟧".encode(getattr(out, "encoding", None) or "utf-8")
    except (UnicodeEncodeError, LookupError):
        return text.replace("⟦", "[[").replace("⟧", "]]")
    return text


def run(no_fail: bool, out: TextIO | None = None) -> int:
    out = out if out is not None else sys.stdout
    logging.getLogger("mcp").setLevel(logging.WARNING)  # quiet per-request INFO
    colour = bool(getattr(out, "isatty", lambda: False)())

    def paint(text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if colour else text

    def emit(text: str = "") -> None:
        safe_print(text, file=out)

    clean_tools, clean_info = asyncio.run(_list(False))
    store = InMemoryStore(PinSet({}))
    store.save(
        store.load().with_server(
            pin_server(
                SERVER_ID,
                clean_info.name,
                Target(command=("toolgate-pin", "demo-server")),
                clean_tools,
                approved_by="demo",
            )
        )
    )
    pinner = Pinner(store)

    mutated_tools, mutated_info = asyncio.run(_list(True))
    result = pinner.verify(SERVER_ID, mutated_tools, server_info=mutated_info)

    emit(paint("toolgate-pin demo: pin a server, then change one tool", "1"))
    emit(paint(f"✓ pinned {len(clean_tools)} tools", "32"))
    by_name = {t.name: t for t in mutated_tools}
    for q in result.quarantined:
        emit(paint(f"✗ quarantined {q.tool_name} ({q.reason})", "31"))
        emit(_ascii_brackets(q.diff, out))
        tool = by_name.get(q.tool_name)
        hidden = decode_tag_text(tool.description or "") if tool else None
        if hidden:
            emit(f'hidden text: "{hidden}"')
        for f in q.findings:
            emit(f"{f.rule_id} {f.severity} {f.field_path}")
    emit(
        "next: review the diff, then run `toolgate-pin approve` "
        "only if the change is intended."
    )
    return 0 if no_fail else 1
