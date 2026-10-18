import re

import mcp.types
from toolgate_pin.canon import pin_hash

BASE = {
    "name": "get_claim_status",
    "description": "Returns  the status\n of a claim.",
    "inputSchema": {
        "type": "object",
        "properties": {"claim_id": {"type": "string"}, "b": {"type": "string"}},
        "required": ["claim_id", "b"],
        "additionalProperties": False,
    },
}


def test_key_order_whitespace_and_required_order_hash_equal():
    variant = {
        "inputSchema": {
            "additionalProperties": False,
            "required": ["b", "claim_id"],
            "properties": {"b": {"type": "string"}, "claim_id": {"type": "string"}},
            "type": "object",
        },
        "description": "Returns the status of a claim.",
        "name": "get_claim_status",
    }
    assert pin_hash(BASE) == pin_hash(variant)


def test_nfc_nfd_equal():
    nfc = "caf\u00e9"
    nfd = "cafe\u0301"
    assert nfc != nfd
    assert pin_hash({**BASE, "description": nfc}) == pin_hash(
        {**BASE, "description": nfd}
    )


def test_nfkc_not_applied():  # fullwidth A must not fold to A
    assert pin_hash({**BASE, "description": "\uff21"}) != pin_hash(
        {**BASE, "description": "A"}
    )


def test_cf_characters_change_hash():
    assert pin_hash({**BASE, "description": "ok\u200b"}) != pin_hash(
        {**BASE, "description": "ok"}
    )
    assert pin_hash({**BASE, "description": "ok\U000e0049"}) != pin_hash(
        {**BASE, "description": "ok"}
    )


def test_enum_order_preserved():
    a = {**BASE, "inputSchema": {"type": "string", "enum": ["a", "b"]}}
    b = {**BASE, "inputSchema": {"type": "string", "enum": ["b", "a"]}}
    assert pin_hash(a) != pin_hash(b)


def test_meta_excluded_and_none_dropped():
    assert pin_hash({**BASE, "_meta": {"x": 1}, "title": None}) == pin_hash(BASE)


def test_tool_object_and_dict_hash_equal():  # Review Focus 1
    tool = mcp.types.Tool(
        name=BASE["name"],
        description=BASE["description"],
        inputSchema=BASE["inputSchema"],
    )
    assert pin_hash(tool) == pin_hash(BASE)


def test_hash_format():
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", pin_hash(BASE))


def test_property_keys_kept_verbatim():
    def with_props(props):
        return {**BASE, "inputSchema": {"type": "object", "properties": props}}

    one = with_props({"a b": {"type": "string"}})
    two = with_props({"a b": {"type": "string"}, "a  b": {"type": "integer"}})
    assert pin_hash(one) != pin_hash(two)
    nfc = with_props({"caf\u00e9": {"type": "string"}})
    nfd = with_props({"cafe\u0301": {"type": "string"}})
    assert pin_hash(nfc) != pin_hash(nfd)


def test_nested_none_dropped_tool_and_dict_equal():
    ann = {"readOnlyHint": True, "title": None}
    tool = mcp.types.Tool(
        name=BASE["name"],
        description=BASE["description"],
        inputSchema=BASE["inputSchema"],
        annotations=mcp.types.ToolAnnotations(readOnlyHint=True),
    )
    assert pin_hash({**BASE, "annotations": ann}) == pin_hash(tool)


def _with_prop(prop):
    return {
        **BASE,
        "inputSchema": {"type": "object", "properties": {"p": prop}},
    }


def test_schema_null_const_differs_from_absent():
    assert pin_hash(_with_prop({"const": None})) != pin_hash(_with_prop({}))
    assert pin_hash(_with_prop({"default": None})) != pin_hash(_with_prop({}))


def test_schema_null_tool_and_dict_equal():
    schema = {"type": "object", "properties": {"p": {"default": None}}}
    tool = mcp.types.Tool(
        name=BASE["name"], description=BASE["description"], inputSchema=schema
    )
    assert pin_hash(tool) == pin_hash({**BASE, "inputSchema": schema})
