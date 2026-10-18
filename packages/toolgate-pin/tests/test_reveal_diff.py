from __future__ import annotations

import io

from toolgate_pin.difftext import diff
from toolgate_pin.reveal import decode_tag_text, reveal, safe_print


def test_reveal_tag_and_zero_width():
    assert "\u27e6U+E0049 TAG LATIN CAPITAL LETTER I\u27e7" in reveal("a\U000e0049")
    assert "\u27e6U+200B ZERO WIDTH SPACE\u27e7" in reveal("a\u200b")
    assert reveal("plain text") == "plain text"


def test_reveal_bidi_variation_and_ascii_only():
    assert "U+202E" in reveal("a\u202eb")
    assert "U+FE0F" in reveal("a\ufe0f")
    assert "U+E0100" in reveal("a\U000e0100")
    assert reveal("a\u200b", ascii_only=True) == "a[[U+200B ZERO WIDTH SPACE]]"


def test_decode_tag_text():
    hidden = "".join(chr(0xE0000 + ord(c)) for c in "Hi there")
    assert decode_tag_text("x" + hidden) == "Hi there"
    assert decode_tag_text("none") is None


def test_diff_shows_hidden_chars():
    d = diff({"description": "ok"}, {"description": "ok\U000e0049"})
    assert "\u27e6U+E0049" in d and d.startswith("--- pinned")


def test_diff_equal_empty_and_none_cases():
    assert diff({"a": 1}, {"a": 1}) == ""
    assert diff(None, None) == ""
    assert diff(None, {"a": 1}) != ""
    assert diff({"a": 1}, None) != ""
    assert diff({}, None) != ""


def test_diff_zero_width_only_change_is_visible():
    d = diff({"d": "ab"}, {"d": "a\u200bb"})
    assert d and "U+200B" in d


def test_safe_print_cp1252():
    buf = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    safe_print("\u27e6x\u27e7 a\U000e0049", file=buf)
    buf.flush()
    out = buf.buffer.getvalue()
    assert b"[[U+E0049" in out
    assert rb"\u27E6" in out


def test_safe_print_utf8_passthrough():
    buf = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", newline="\n")
    safe_print("caf\u00e9", file=buf)
    buf.flush()
    assert buf.buffer.getvalue() == "caf\u00e9\n".encode()


def test_reveal_line_separators():
    assert "\u27e6U+2028 LINE SEPARATOR\u27e7" in reveal("a\u2028b")
    assert "\u27e6U+2029 PARAGRAPH SEPARATOR\u27e7" in reveal("a\u2029b")
    assert "U+0085" in reveal("a\u0085b")


def test_diff_line_separator_swap_is_not_empty():
    for sep in ("\u2028", "\u2029", "\u0085"):
        d = diff({"d": "a b"}, {"d": f"a{sep}b"})
        assert d, sep
        assert f"U+{ord(sep):04X}" in d
