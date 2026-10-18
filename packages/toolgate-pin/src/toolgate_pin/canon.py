"""Canonical hashing of MCP tool definitions (JCS over a normalized definition)."""

from __future__ import annotations

import hashlib
import unicodedata
from collections.abc import Mapping
from typing import Any

import mcp.types
import rfc8785

HASHED_FIELDS = (
    "name",
    "title",
    "description",
    "inputSchema",
    "outputSchema",
    "annotations",
)


def as_definition(tool: mcp.types.Tool | Mapping[str, Any]) -> dict[str, Any]:
    """Return only the hashed fields of a tool, with None values dropped."""
    if isinstance(tool, mcp.types.Tool):
        raw: Mapping[str, Any] = tool.model_dump(by_alias=True, exclude_none=True)
    else:
        raw = tool
    return {k: raw[k] for k in HASHED_FIELDS if raw.get(k) is not None}


def _norm_str(value: str) -> str:
    # NFC (never NFKC); collapse str.isspace runs to one space; trim.
    # Cf characters are deliberately preserved.
    text = unicodedata.normalize("NFC", value)
    out: list[str] = []
    pending_space = False
    for ch in text:
        if ch.isspace():
            pending_space = True
            continue
        if pending_space and out:
            out.append(" ")
        pending_space = False
        out.append(ch)
    return "".join(out)


def _normalize(node: Any) -> Any:
    if isinstance(node, str):
        return _norm_str(node)
    if isinstance(node, Mapping):
        result: dict[str, Any] = {}
        for key, val in node.items():
            norm_key = _norm_str(key) if isinstance(key, str) else key
            norm_val = _normalize(val)
            if (
                key == "required"
                and isinstance(norm_val, list)
                and all(isinstance(x, str) for x in norm_val)
            ):
                norm_val = sorted(norm_val)
            result[norm_key] = norm_val
        return result
    if isinstance(node, (list, tuple)):
        return [_normalize(x) for x in node]
    return node


def canonicalize(tool: mcp.types.Tool | Mapping[str, Any]) -> bytes:
    """JCS (RFC 8785) bytes of the normalized hashed-field definition."""
    return rfc8785.dumps(_normalize(as_definition(tool)))


def pin_hash(tool: mcp.types.Tool | Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonicalize(tool)).hexdigest()
