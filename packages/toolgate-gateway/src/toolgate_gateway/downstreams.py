from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from toolgate_gateway.policy import PolicyError, load_yaml_mapping

_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,40}$")


@dataclass(frozen=True)
class DownstreamConfig:
    server_id: str
    url: str


def load_downstreams(path: Path | str) -> list[DownstreamConfig]:
    data = load_yaml_mapping(path)
    items = data.get("downstreams")
    if not isinstance(items, list):
        raise PolicyError(path, "'downstreams' must be a list")
    out: list[DownstreamConfig] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            raise PolicyError(path, "each downstream must be a mapping")
        sid, url = item.get("server_id"), item.get("url")
        if not isinstance(sid, str) or not _ID_RE.fullmatch(sid):
            raise PolicyError(path, "invalid downstream server_id")
        if not isinstance(url, str) or not url:
            raise PolicyError(path, f"downstream {sid!r} needs a url")
        if sid in seen:
            raise PolicyError(path, f"duplicate downstream server_id {sid!r}")
        seen.add(sid)
        out.append(DownstreamConfig(sid, url))
    return out


def namespaced(server_id: str, tool: str) -> str:
    return f"{server_id}.{tool}"


def split_namespaced(name: str) -> tuple[str, str] | None:
    server, sep, tool = name.partition(".")
    return (server, tool) if sep else None
