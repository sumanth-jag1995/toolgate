"""`toolgate-pin approve`: review new or changed tools, then pin them."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from collections.abc import Mapping, Sequence
from typing import TextIO

import mcp.types

from toolgate_pin.canon import as_definition, pin_hash
from toolgate_pin.connect import (
    ConnectError,
    UsageError,
    describe_error,
    fetch_tools,
    target_display,
    validate_header_template,
    validate_url,
)
from toolgate_pin.difftext import diff
from toolgate_pin.models import InventoryTool, ScanReport, ServerPin, Target
from toolgate_pin.pinning import duplicate_names, pin_server
from toolgate_pin.reveal import ascii_brackets, decode_tag_text, safe_print
from toolgate_pin.scanner import DEFAULT_CONFIG, scan_definition
from toolgate_pin.store import LockfileError, LockfileStore

_GIT_TIMEOUT = 5


def git_user_name() -> str | None:
    try:
        proc = subprocess.run(
            ["git", "config", "user.name"],
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    name = proc.stdout.strip() if proc.returncode == 0 else ""
    return name or None


def malicious_tiers(report: ScanReport) -> list[str]:
    """Which tiers that ran produced a malicious verdict on their own."""
    tiers: list[str] = []
    if any(f.severity == "high" and not f.preexisting for f in report.findings):
        tiers.append("rules")
    score = report.classifier_score
    if score is not None and score >= DEFAULT_CONFIG.classifier_high:
        tiers.append("classifier")
    if report.judge is not None and report.judge.verdict == "malicious":
        tiers.append("judge")
    return tiers


def _inventory(
    server_id: str, tools: Sequence[mcp.types.Tool], others: Mapping[str, ServerPin]
) -> tuple[InventoryTool, ...]:
    """This server's current tools plus every other pinned server's tools."""
    inv = [InventoryTool(server_id, t.name) for t in tools]
    for sid, sp in others.items():
        if sid == server_id:
            continue
        inv.extend(
            InventoryTool(sid, name, tp.definition) for name, tp in sp.tools.items()
        )
    return tuple(inv)


def run(
    target: Target,
    *,
    name: str | None,
    lockfile: str,
    approver: str | None,
    yes: bool,
    override: str | None,
    tiers: Sequence[str],
    out: TextIO | None = None,
    err: TextIO | None = None,
    env: Mapping[str, str] | None = None,
) -> int:
    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr
    env = env if env is not None else os.environ
    judge = None
    if "judge" in tiers:
        from toolgate_pin.scanner.judge import Judge

        judge = Judge.from_env(env=env)  # None without a key: reported unavailable

    def emit(text: str = "") -> None:
        safe_print(ascii_brackets(text, out), file=out)

    def fail(message: str, code: int = 2) -> int:
        out.flush()  # keep the review above the verdict when both are a terminal
        safe_print(f"toolgate-pin approve: {message}", file=err)
        return code

    try:
        if target.url is not None:
            validate_url(target.url)
        for h in target.headers:
            validate_header_template(h)
    except UsageError as exc:
        return fail(str(exc))
    if not yes and (sys.stdin is None or not sys.stdin.isatty()):
        return fail("no terminal to confirm in; review the changes, then pass --yes")
    approver = approver or git_user_name()
    if not approver:
        return fail("cannot tell who is approving; pass --as NAME")

    store = LockfileStore(lockfile)
    try:
        pins = store.load()
    except LockfileError as exc:
        return fail(str(exc))
    try:
        init, tools = asyncio.run(fetch_tools(target, env))
    except UsageError as exc:
        return fail(str(exc))
    except ConnectError as exc:
        return fail(describe_error(exc))

    dupes = duplicate_names(t.name for t in tools)
    if dupes:
        return fail(
            f"the server lists tool {', '.join(repr(d) for d in dupes)} more than "
            "once; refusing to approve an ambiguous tool list"
        )

    server_name = init.serverInfo.name
    server_id = name or server_name
    prior = pins.get(server_id)
    inventory = _inventory(server_id, tools, pins.servers)

    reports: dict[str, ScanReport] = {}
    emit(f"{server_id} ({target_display(target)}): {len(tools)} tools")
    if prior is not None and prior.server_name != server_name:
        emit(f"! server name changed: {prior.server_name!r} -> {server_name!r}")
    unavailable: set[str] = set()
    hashes: dict[str, str] = {}
    for tool in tools:
        try:
            hashes[tool.name] = pin_hash(tool)
        except Exception as exc:  # noqa: BLE001  hostile content: refuse, never crash
            return fail(
                f"tool {tool.name!r} cannot be canonicalized ({type(exc).__name__})"
            )
    for tool in tools:
        old = prior.tools.get(tool.name) if prior is not None else None
        if old is not None and old.hash == hashes[tool.name]:
            continue
        report = scan_definition(
            tool,
            server_id=server_id,
            prior=old.definition if old is not None else None,
            inventory=inventory,
            tiers=tiers,
            judge=judge,
        )
        reports[tool.name] = report
        unavailable.update(report.unavailable)
        kind = "changed" if old is not None else "new"
        emit(f"{'~' if old else '+'} {kind} tool {tool.name}: {report.verdict}")
        emit(diff(old.definition if old else None, as_definition(tool)))
        hidden = decode_tag_text(tool.description or "")
        if hidden:
            emit(f'  hidden text: "{hidden}"')
        for f in report.findings:
            mark = " (already approved)" if f.preexisting else ""
            emit(f"  {f.rule_id} {f.severity} {f.field_path}: {f.message}{mark}")
    current = {t.name for t in tools}
    removed = [n for n in (prior.tools if prior else {}) if n not in current]
    for tname in removed:
        emit(f"- removed tool {tname}")
        emit(diff(prior.tools[tname].definition, None))  # type: ignore[union-attr]
    for tier in sorted(unavailable):
        emit(f"note: the {tier} tier is unavailable; it did not run")

    blocked = {
        n: malicious_tiers(r) for n, r in reports.items() if r.verdict == "malicious"
    }
    if blocked and override is None:
        return fail(
            f"blocked: {', '.join(blocked)} judged malicious. Fix the server, or "
            'pass --override "<reason>" to approve anyway',
            3,
        )

    changed = bool(
        reports
        or removed
        or prior is None
        or prior.server_name != server_name
        or prior.target != target
    )
    if not changed:
        emit(f"no changes; {lockfile} is up to date")
        return 0
    if not yes:
        try:
            answer = input(f"Approve and write {lockfile}? [y/N] ").strip().lower()
        except EOFError:
            answer = ""
        if answer not in ("y", "yes"):
            emit("not approved; nothing written")
            return 0

    reasons: dict[str, str] = {
        n: f"{override} [tiers: {','.join(t) or 'none'}]" for n, t in blocked.items()
    }
    sp = pin_server(
        server_id,
        server_name,
        target,
        tools,
        approved_by=approver,
        prior=prior,
        reports=reports,
        override_reasons=reasons,
    )
    try:
        store.save(pins.with_server(sp))
    except OSError as exc:
        return fail(f"{lockfile}: cannot write ({type(exc).__name__})")
    emit(
        f"approved {len(reports)} new or changed, {len(removed)} removed; "
        f"wrote {lockfile} (commit it)"
    )
    return 0
