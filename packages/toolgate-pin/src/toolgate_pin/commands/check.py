"""`toolgate-pin check`: compare live servers with the lockfile. Never writes."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from collections.abc import Mapping
from dataclasses import replace
from typing import Any, TextIO

from toolgate_pin.connect import (
    ConnectError,
    UsageError,
    describe_error,
    fetch_tools,
    same_origin,
    target_display,
)
from toolgate_pin.models import PinSet, Quarantine, Target
from toolgate_pin.pinner import Pinner
from toolgate_pin.reveal import (
    ascii_brackets,
    decode_tag_text,
    safe_print,
    stream_can_encode,
)
from toolgate_pin.store import InMemoryStore, LockfileError, LockfileStore


def _with_stored_headers(target: Target, name: str | None, pins: PinSet) -> Target:
    """An explicit URL target authenticates with the header templates pinned for
    the same server (by --name, else by an identical stored URL), but only on
    the pinned origin. Raises UsageError rather than send a server's
    credentials to a different scheme, host or port."""
    if target.url is None or target.headers:
        return target
    sp = pins.get(name) if name else None
    if sp is None:
        sp = next(
            (s for s in pins.servers.values() if s.target.url == target.url), None
        )
    if sp is None or not sp.target.headers:
        return target
    if sp.target.url is None or not same_origin(sp.target.url, target.url):
        raise UsageError(
            f"--name {sp.server_id} does not carry its pinned credentials to a "
            "different origin (scheme, host and port must match the pinned URL)"
        )
    return replace(target, headers=sp.target.headers)


def _quarantine_json(q: Quarantine) -> dict[str, Any]:
    return {
        "tool_name": q.tool_name,
        "reason": q.reason,
        "observed_hash": q.observed_hash,
        "pinned_hash": q.pinned_hash,
        "diff": q.diff,
    }


def run(
    target: Target | None,
    *,
    name: str | None,
    lockfile: str,
    fmt: str = "text",
    out: TextIO | None = None,
    err: TextIO | None = None,
    env: Mapping[str, str] | None = None,
) -> int:
    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr
    env = env if env is not None else os.environ
    text = fmt == "text"
    bad = "✗" if stream_can_encode(out, "✗") else "[x]"

    def emit(line: str = "") -> None:
        if text:
            safe_print(ascii_brackets(line, out), file=out)

    try:
        pins = LockfileStore(lockfile).load()
    except LockfileError as exc:
        safe_print(f"toolgate-pin check: {exc}", file=err)
        return 2

    if target is None:
        if not pins.servers:
            safe_print(
                f"toolgate-pin check: no servers pinned in {lockfile}; "
                "run `toolgate-pin approve` first",
                file=err,
            )
            return 2
        jobs: list[tuple[str | None, Target]] = [
            (sid, sp.target) for sid, sp in pins.servers.items()
        ]
    else:
        try:
            jobs = [(name, _with_stored_headers(target, name, pins))]
        except UsageError as exc:
            safe_print(f"toolgate-pin check: {exc}", file=err)
            return 2

    pinner = Pinner(InMemoryStore(pins))
    code = 0
    servers: list[dict[str, Any]] = []
    for sid, tgt in jobs:
        label = sid or target_display(tgt)
        try:
            init, tools = asyncio.run(fetch_tools(tgt, env))
        except (UsageError, ConnectError) as exc:
            message = describe_error(exc) if isinstance(exc, ConnectError) else str(exc)
            emit(f"{label}: error: {message}")
            servers.append({"server_id": sid, "error": message, "quarantined": []})
            code = 2
            continue
        sid = sid or init.serverInfo.name
        result = pinner.verify(sid, tools, server_info=init.serverInfo)
        servers.append(
            {
                "server_id": sid,
                "error": None,
                "quarantined": [_quarantine_json(q) for q in result.quarantined],
            }
        )
        if result.ok:
            emit(f"{sid}: ok ({len(tools)} tools match the lockfile)")
            continue
        code = max(code, 1)
        emit(f"{sid}: {len(result.quarantined)} quarantined")
        descriptions = {t.name: t.description or "" for t in tools}
        for q in result.quarantined:
            emit(f"  {bad} {q.tool_name} ({q.reason})")
            if q.diff:
                emit(q.diff)
            hidden = decode_tag_text(descriptions.get(q.tool_name, ""))
            if hidden and q.reason in ("drift", "unpinned"):
                emit(f'    hidden text: "{hidden}"')
            for f in q.findings:
                emit(f"    {f.rule_id} {f.severity} {f.field_path}: {f.message}")

    if text:
        emit(
            "check passed"
            if code == 0
            else "check failed: review the diffs; re-run `toolgate-pin approve` "
            "only for intended changes"
        )
    else:
        out.write(json.dumps({"ok": code == 0, "servers": servers}, indent=2) + "\n")
    return code
