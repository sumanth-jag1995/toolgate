"""Tighten FastMCP-generated tool input schemas.

This is the only module that touches FastMCP private attributes:
``mcp._tool_manager._tools[name].parameters`` (mcp 1.x, verified on 1.30.0).
"""

from typing import Any

from mcp.server.fastmcp import FastMCP

_SUBSCHEMA_LIST_KEYS = ("anyOf", "oneOf", "allOf", "prefixItems")
_SUBSCHEMA_MAP_KEYS = ("properties", "$defs", "definitions", "patternProperties")


def _is_object_schema(node: dict[str, Any]) -> bool:
    return node.get("type") == "object" or "properties" in node


def _harden(node: Any) -> None:
    if not isinstance(node, dict):
        return
    if _is_object_schema(node):
        node["additionalProperties"] = False
    for key in _SUBSCHEMA_MAP_KEYS:
        for sub in (node.get(key) or {}).values():
            _harden(sub)
    for key in _SUBSCHEMA_LIST_KEYS:
        for sub in node.get(key) or []:
            _harden(sub)
    for key in ("items", "not", "if", "then", "else"):
        _harden(node.get(key))


def forbid_extra_arguments(mcp: FastMCP) -> None:
    """Make every tool reject undeclared arguments at call time.

    FastMCP 1.x validates arguments with a generated pydantic model that ignores
    extras by default, even though the advertised schema says otherwise. We flip
    that model to ``extra="forbid"`` and rebuild it (uses
    ``mcp._tool_manager._tools[name].fn_metadata.arg_model``). Validation errors
    surface as tool errors (``isError``).
    """
    for tool in mcp._tool_manager._tools.values():
        arg_model = tool.fn_metadata.arg_model
        arg_model.model_config["extra"] = "forbid"
        arg_model.model_rebuild(force=True)


def harden_schemas(mcp: FastMCP) -> None:
    """Set ``additionalProperties: false`` on every object node of every tool input schema."""
    for tool in mcp._tool_manager._tools.values():
        _harden(tool.parameters)
