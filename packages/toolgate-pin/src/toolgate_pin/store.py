"""Lockfile persistence: in-memory and atomic JSON file stores."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Protocol

from toolgate_pin.models import PinSet, ServerPin, Target, ToolPin

_VERSION = 1


class LockfileError(Exception):
    """Raised for unreadable or malformed lockfiles (message: path + reason)."""


class PinStore(Protocol):
    def load(self) -> PinSet: ...

    def save(self, pins: PinSet) -> None: ...


class InMemoryStore:
    def __init__(self, pins: PinSet | None = None) -> None:
        self._pins = pins if pins is not None else PinSet({})

    def load(self) -> PinSet:
        return self._pins

    def save(self, pins: PinSet) -> None:
        self._pins = pins


def _to_json(pins: PinSet) -> dict[str, Any]:
    servers: dict[str, Any] = {}
    for sid, sp in pins.servers.items():
        tools = {
            name: {
                "hash": tp.hash,
                "definition": tp.definition,
                "approved_by": tp.approved_by,
                "approved_at": tp.approved_at,
                "scan": tp.scan,
                "override_reason": tp.override_reason,
            }
            for name, tp in sp.tools.items()
        }
        servers[sid] = {
            "server_name": sp.server_name,
            "target": {
                "url": sp.target.url,
                "command": list(sp.target.command)
                if sp.target.command is not None
                else None,
                "headers": list(sp.target.headers),
            },
            "tools": tools,
        }
    return {"version": _VERSION, "servers": servers}


def _need(obj: Any, key: str, typ: type | tuple[type, ...], where: str) -> Any:
    if not isinstance(obj, dict) or key not in obj:
        raise ValueError(f"missing '{key}' in {where}")
    val = obj[key]
    if not isinstance(val, typ):
        raise TypeError(f"'{key}' in {where} has wrong type")
    return val


def _str_list(val: Any, where: str) -> tuple[str, ...]:
    if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
        raise ValueError(f"{where} must be a list of strings")
    return tuple(val)


def _from_json(data: Any) -> PinSet:
    if not isinstance(data, dict):
        raise TypeError("top level must be an object")
    if data.get("version") != _VERSION:
        raise ValueError(f"unsupported version (expected {_VERSION})")
    servers_raw = _need(data, "servers", dict, "lockfile")
    servers: dict[str, ServerPin] = {}
    for sid, srv in servers_raw.items():
        where = f"server '{sid}'"
        name = _need(srv, "server_name", str, where)
        tgt = _need(srv, "target", dict, where)
        url = tgt.get("url")
        if url is not None and not isinstance(url, str):
            raise ValueError(f"target url in {where} must be a string or null")
        cmd = tgt.get("command")
        command = None if cmd is None else _str_list(cmd, f"target command in {where}")
        headers = _str_list(tgt.get("headers", []), f"target headers in {where}")
        tools_raw = _need(srv, "tools", dict, where)
        tools: dict[str, ToolPin] = {}
        for tname, tp in tools_raw.items():
            twhere = f"tool '{tname}' in {where}"
            reason = tp.get("override_reason") if isinstance(tp, dict) else None
            if reason is not None and not isinstance(reason, str):
                raise ValueError(
                    f"override_reason in {twhere} must be a string or null"
                )
            tools[tname] = ToolPin(
                name=tname,
                hash=_need(tp, "hash", str, twhere),
                definition=_need(tp, "definition", dict, twhere),
                approved_by=_need(tp, "approved_by", str, twhere),
                approved_at=_need(tp, "approved_at", str, twhere),
                scan=_need(tp, "scan", dict, twhere),
                override_reason=reason,
            )
        servers[sid] = ServerPin(
            server_id=sid,
            server_name=name,
            target=Target(url=url, command=command, headers=headers),
            tools=tools,
        )
    return PinSet(servers)


class LockfileStore:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)

    def load(self) -> PinSet:
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return PinSet({})
        except OSError as exc:
            raise LockfileError(
                f"{self.path}: cannot read ({type(exc).__name__})"
            ) from exc
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LockfileError(
                f"{self.path}: invalid JSON ({type(exc).__name__})"
            ) from exc
        try:
            return _from_json(data)
        except (ValueError, TypeError) as exc:
            raise LockfileError(f"{self.path}: {exc}") from exc

    def save(self, pins: PinSet) -> None:
        text = (
            json.dumps(_to_json(pins), indent=2, sort_keys=True, ensure_ascii=False)
            + "\n"
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(
            dir=self.path.parent, prefix=self.path.name + ".", suffix=".tmp"
        )
        try:
            with open(fd, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
