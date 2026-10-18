"""Make hidden Unicode visible for human approvers."""

from __future__ import annotations

import sys
import unicodedata
from typing import TextIO


def _is_hidden(ch: str) -> bool:
    cp = ord(ch)
    return (
        unicodedata.category(ch) == "Cf"  # includes bidi controls, zero-width, tags
        or 0xE0000 <= cp <= 0xE007F  # tag characters
        or 0xFE00 <= cp <= 0xFE0F  # variation selectors
        or 0xE0100 <= cp <= 0xE01EF  # variation selectors supplement
        or cp in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF)  # zero-width
        or cp in (0x2028, 0x2029, 0x0085)  # line/paragraph separators, NEL
    )


def reveal(text: str, *, ascii_only: bool = False) -> str:
    open_, close = ("[[", "]]") if ascii_only else ("⟦", "⟧")
    out: list[str] = []
    for ch in text:
        if _is_hidden(ch):
            name = unicodedata.name(ch, "UNKNOWN")
            out.append(f"{open_}U+{ord(ch):04X} {name}{close}")
        else:
            out.append(ch)
    return "".join(out)


def decode_tag_text(text: str) -> str | None:
    if not any(0xE0000 <= ord(c) <= 0xE007F for c in text):
        return None
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


def _can_encode(text: str, encoding: str) -> bool:
    try:
        text.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def safe_print(text: str, file: TextIO | None = None) -> None:
    out = file if file is not None else sys.stdout
    encoding = getattr(out, "encoding", None) or "utf-8"
    if not _can_encode(text, encoding):
        text = reveal(text, ascii_only=True)
        text = "".join(
            ch
            if _can_encode(ch, encoding)
            else (f"\\u{ord(ch):04X}" if ord(ch) <= 0xFFFF else f"\\U{ord(ch):08X}")
            for ch in text
        )
    print(text, file=out)
