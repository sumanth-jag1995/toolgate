"""Tier 1: deterministic rules over every string of a tool definition or output.

Every regex here is linear-time: no nested quantifiers, bounded lazy gaps only,
and each rule scans a string at most once.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from functools import lru_cache
from itertools import groupby
from typing import Any

from toolgate_pin.models import Finding, InventoryTool
from toolgate_pin.reveal import reveal
from toolgate_pin.scanner.config import ScanConfig

# =============================================================================
# Tunables. Task 9 adjusts severities and patterns here (dev split only), then
# freezes them. Rule IDs are stable: they are written to the lockfile.
# =============================================================================

SEVERITY: dict[str, str] = {
    "TG-UNI-001": "high",  # Unicode tag characters
    "TG-UNI-002": "high",  # bidi override / isolate controls
    "TG-UNI-003": "medium",  # zero-width / other Cf
    "TG-UNI-004": "medium",  # variation selectors
    "TG-UNI-005": "high",  # mixed-script tool or parameter name
    "TG-INS-001": "high",  # instruction aimed at the model
    "TG-INS-002": "medium",  # softer imperative to the model
    "TG-XREF-001": "high",  # names a tool on another server
    "TG-XREF-002": "high",  # ordering / redirect phrasing
    "TG-XREF-003": "low",  # names another tool on the same server
    "TG-EXF-001": "medium",  # URL or email host not allowlisted
    "TG-EXF-002": "high",  # sensitive file path
    "TG-EXF-003": "medium",  # long base64 / hex blob
    "TG-SIDE-001": "medium",  # free-text side-channel parameter
    "TG-SHADOW-001": "high",  # same / near name as a tool on another server
}

MESSAGE: dict[str, str] = {
    "TG-UNI-001": "Unicode tag characters (invisible text)",
    "TG-UNI-002": "bidi override/isolate control characters",
    "TG-UNI-003": "zero-width or other invisible format characters",
    "TG-UNI-004": "variation selector characters",
    "TG-UNI-005": "name mixes letters from several scripts",
    "TG-INS-001": "instruction aimed at the model",
    "TG-INS-002": "imperative aimed at the model",
    "TG-XREF-001": "names a tool on another server",
    "TG-XREF-002": "ordering or redirect phrasing about another tool",
    "TG-XREF-003": "names another tool on the same server",
    "TG-EXF-001": "URL or email host not on the allowlist",
    "TG-EXF-002": "sensitive file path",
    "TG-EXF-003": "long encoded blob (base64/hex)",
    "TG-SIDE-001": "free-text parameter usable as a side channel",
    "TG-SHADOW-001": "same or near name as a tool on another server",
}

# Rules that also run over tool *outputs* (scan_output).
OUTPUT_RULES = frozenset(
    {
        "TG-UNI-001",
        "TG-UNI-002",
        "TG-UNI-003",
        "TG-UNI-004",
        "TG-INS-001",
        "TG-INS-002",
        "TG-XREF-001",
        "TG-XREF-002",
        "TG-EXF-001",
    }
)
DEFINITION_RULES = frozenset(SEVERITY)

MAX_EVIDENCE = 80  # chars of matched excerpt, before reveal()
MAX_FINDINGS_PER_RULE_FIELD = 5
# Matches (duplicates included) after which a rule stops scanning a field.
MAX_MATCHES_PER_RULE_FIELD = 50

# Values under these schema keys are identifiers, not prose: only the hidden
# Unicode rules see them.
STRUCTURAL_KEYS = frozenset(
    {
        "type",
        "format",
        "$schema",
        "$id",
        "$ref",
        "required",
        "pattern",
        "contentEncoding",
        "contentMediaType",
    }
)

# TG-INS-001 (high). Case-insensitive; one alternation per rule.
INSTRUCTION_PATTERNS: tuple[str, ...] = (
    (
        r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+)?"
        r"(?:previous|prior|above|earlier|preceding|former|other|system)\s+"
        r"(?:instructions?|rules?|guidelines?|directions?|directives?|prompts?"
        r"|messages?|context|commands?|constraints?|orders?)\b"
    ),
    r"\b(?:ignore|disregard|forget)\s+(?:all\s+|everything\s+)?(?:of\s+)?the\s+above\b",
    (
        r"\b(?:do\s+not|don't|dont|never)\s+(?:tell|mention|inform|notify|reveal"
        r"|disclose|alert|show)\b[^.\n]{0,60}?\b(?:the\s+)?users?\b"
    ),
    r"\bwithout\s+(?:telling|informing|notifying|alerting|asking)\s+(?:the\s+)?users?\b",
    (
        r"<\s{0,3}/?\s{0,3}(?:important|system|instructions?|admin|assistant|secret"
        r"|hidden|critical)\b[^<>\n]{0,40}>"
    ),
    r"<\|\s{0,3}(?:im_start|im_end|system|endoftext)",
    r"\[\s{0,3}/?(?:system|inst)\s{0,3}\]",
    (
        r"\byou\s+are\s+now\b(?!\s+(?:logged|signed|connected|authenticated"
        r"|subscribed|ready|able))"
    ),
)

# TG-INS-002 (medium). Deliberately does not match "You must provide ..." or
# "Always returns ...".
SOFT_IMPERATIVE_PATTERNS: tuple[str, ...] = (
    r"\b(?:secretly|covertly)\b",
    r"\bbehind\s+the\s+user'?s\s+back\b",
    r"\bmust\s+(?:first|always)\b",
    (
        r"\balways\s+(?:call|use|invoke|run|include|pass|send|read|add|append"
        r"|prepend|attach|forward|cc|bcc|copy|upload|fetch)\b"
    ),
    r"\b(?:before|prior\s+to)\s+(?:responding|answering|replying)\b",
    r"\b(?:do\s+not|don't|never)\s+(?:ask|confirm\s+with|check\s+with)\s+(?:the\s+)?user\b",
)

# TG-XREF-002 (high). The tail is parsed in Python to find the target tool.
REDIRECT_PATTERN = (
    r"\b(?:(?P<order>before\s+(?:calling|using|invoking|running"
    r"|you\s+(?:call|use|invoke|run))|instead\s+of(?:\s+(?:calling|using|invoking))?)"
    r"|(?P<after>after\b[^.\n]{0,80}?\balso\s+(?:call|invoke|use|run)\b))"
    r"(?P<tail>[^\n.;!?]{0,60})"
)

# TG-EXF-001: URLs (scheme required) and emails.
URL_PATTERN = r"\b(?:https?|wss?|ftp)://[^\s\"'<>`]{1,2048}"
EMAIL_PATTERN = r"(?<=[\w.+-])@([A-Za-z0-9][A-Za-z0-9.-]{0,252})"

# TG-EXF-002 (high): secrets on disk.
SENSITIVE_PATH_PATTERNS: tuple[str, ...] = (
    r"(?<![\w.])\.ssh\b",
    r"\bid_(?:rsa|dsa|ecdsa|ed25519)\b",
    r"(?<![\w.])\.env\b",
    r"/etc/(?:passwd|shadow|sudoers)\b",
    r"\bmcp\.json\b",
    r"\bclaude_desktop_config\.json\b",
    r"\.aws[/\\](?:credentials|config)\b",
    r"\bapplication_default_credentials\.json\b",
    r"\.config[/\\]gcloud\b",
    r"\.azure[/\\]",
    r"\.kube[/\\]config\b",
    r"\.docker[/\\]config\.json\b",
    r"(?<![\w.])\.(?:netrc|git-credentials|npmrc|pypirc|bash_history|zsh_history)\b",
)

# TG-EXF-003: minimum blob lengths.
BASE64_MIN = 40
HEX_MIN = 64

# TG-SIDE-001: parameter-name tokens (split on _ - and camelCase).
SIDE_CHANNEL_TOKENS = frozenset(
    {
        "note",
        "notes",
        "context",
        "debug",
        "metadata",
        "extra",
        "extras",
        "sidenote",
        "sidenotes",
        "feedback",
    }
)

# TG-SHADOW-001: case-folded edit distance; fuzzy matching only for names at
# least this long (exact case-folded matches always count).
SHADOW_MAX_DISTANCE = 2
SHADOW_FUZZY_MIN_LEN = 5
SHADOW_MAX_NAME_LEN = 256

# TG-UNI-005: homoglyph-relevant scripts (Unicode name prefixes).
MIXED_SCRIPT_PREFIXES: tuple[tuple[str, str], ...] = (
    ("LATIN", "Latin"),
    ("FULLWIDTH LATIN", "Latin-compat"),
    ("MATHEMATICAL", "Latin-compat"),
    ("CYRILLIC", "Cyrillic"),
    ("GREEK", "Greek"),
)

# =============================================================================
# Compiled patterns
# =============================================================================


def _alt(patterns: Iterable[str]) -> re.Pattern[str]:
    return re.compile("|".join(f"(?:{p})" for p in patterns), re.IGNORECASE)


_INS_RE = _alt(INSTRUCTION_PATTERNS)
_SOFT_RE = _alt(SOFT_IMPERATIVE_PATTERNS)
_REDIRECT_RE = re.compile(REDIRECT_PATTERN, re.IGNORECASE)
_URL_RE = re.compile(URL_PATTERN, re.IGNORECASE)
_EMAIL_RE = re.compile(EMAIL_PATTERN)
_PATH_RE = _alt(SENSITIVE_PATH_PATTERNS)
_BLOB_RE = re.compile(rf"(?<![A-Za-z0-9+/.])[A-Za-z0-9+/]{{{BASE64_MIN},}}={{0,2}}")
_HEX_RE = re.compile(r"[0-9a-fA-F]+")
_UPPER_RE = re.compile(r"[A-Z]")
_LOWER_RE = re.compile(r"[a-z]")
_DIGIT_RE = re.compile(r"[0-9]")

# Candidate characters per hidden-Unicode rule. TG-UNI-003 holds every other
# Cf character (Unicode 15); exemptions are decided per character below.
_HIDDEN_CLASSES: dict[str, str] = {
    "TG-UNI-001": "\U000e0000-\U000e007f",
    "TG-UNI-002": "\u202a-\u202e\u2066-\u2069",
    "TG-UNI-003": (
        "\u00ad\u0600-\u0605\u061c\u06dd\u070f\u0890\u0891\u08e2\u180e"
        "\u200b-\u200f\u2060-\u2064\u206a-\u206f\ufeff\ufff9-\ufffb"
        "\U000110bd\U000110cd\U00013430-\U0001343f\U0001bca0-\U0001bca3"
        "\U0001d173-\U0001d17a"
    ),
    "TG-UNI-004": "\ufe00-\ufe0f\U000e0100-\U000e01ef",
}
_HIDDEN_RULES = tuple(_HIDDEN_CLASSES)
# TG-UNI-003 candidates once direction marks are exempt (text has RTL letters).
_UNI003_RTL_CLASS = (
    "\u00ad\u180e\u200b-\u200d\u2060-\u2064\u206a-\u206f\ufeff\ufff9-\ufffb"
    "\U000110bd\U000110cd\U00013430-\U0001343f\U0001bca0-\U0001bca3"
    "\U0001d173-\U0001d17a"
)


@lru_cache(maxsize=32)
def _hidden_re(open_rules: frozenset[str], rtl: bool) -> re.Pattern[str]:
    """Runs of candidate characters for the rules that can still report."""
    classes = (
        {**_HIDDEN_CLASSES, "TG-UNI-003": _UNI003_RTL_CLASS} if rtl else _HIDDEN_CLASSES
    )
    return re.compile(
        "[" + "".join(classes[r] for r in _HIDDEN_RULES if r in open_rules) + "]+"
    )


@lru_cache(maxsize=16)
def _rule_class_re(rule_id: str, rtl: bool) -> re.Pattern[str]:
    cls = (
        _UNI003_RTL_CLASS
        if rtl and rule_id == "TG-UNI-003"
        else _HIDDEN_CLASSES[rule_id]
    )
    return re.compile(f"[{cls}]+")


# Runs longer than this are classified by character class alone: inside a long
# run every neighbour is itself hidden, so no exemption applies.
_LONG_RUN = 256
_ANY_HIDDEN_RE = re.compile("[" + "".join(_HIDDEN_CLASSES.values()) + "]")
_RTL_RE = re.compile("[\u0590-\u08ff\ufb1d-\ufdff\ufe70-\ufefc]")
_JOINERS = frozenset({0x200B, 0x200C, 0x200D, 0x2060})
_RTL_MARKS = frozenset(
    {0x200E, 0x200F, 0x061C, 0x06DD, 0x070F, 0x0890, 0x0891, 0x08E2}
    | set(range(0x0600, 0x0606))
)

_PLAIN_WORD_RE = re.compile(r"[A-Za-z]+")
_TOOL_AFTER_RE = re.compile(r"\s{0,3}(?:tool|function)\b", re.IGNORECASE)
_TOOL_BEFORE_RE = re.compile(r"\b(?:tool|function)\s{1,3}$", re.IGNORECASE)
_QUOTES = "`'\"\u2018\u2019\u201c\u201d"
_IDENT_RE = re.compile(r"[A-Za-z_][\w.]*[A-Za-z0-9]")
_CAMEL_RE = re.compile(r"[a-z][A-Z]")
_TOKEN_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z])(?=[A-Z])")
_TAIL_STRIP = "`'\"()[]{},:\u201c\u201d\u2018\u2019"
_ARTICLES = frozenset({"the", "a", "an", "any"})


# =============================================================================
# Plumbing
# =============================================================================


def _esc(segment: str) -> str:
    return segment.replace("~", "~0").replace("/", "~1")


def _walk(root: Any, base: str) -> Iterator[tuple[str, str, str | None, bool]]:
    """Yield (json_pointer, text, parent_key, is_key) for every string, pre-order.

    Iterative, so hostile nesting depth cannot raise RecursionError.
    """
    stack: list[tuple[str, Any, str | None, bool]] = [(base, root, None, False)]
    seen: set[int] = set()
    while stack:
        ptr, node, pkey, is_key = stack.pop()
        if isinstance(node, str):
            yield ptr, node, pkey, is_key
        elif isinstance(node, Mapping):
            if id(node) in seen:
                continue
            seen.add(id(node))
            children: list[tuple[str, Any, str | None, bool]] = []
            for key, val in node.items():
                skey = key if isinstance(key, str) else str(key)
                cptr = f"{ptr}/{_esc(skey)}"
                if isinstance(key, str):
                    children.append((cptr, key, None, True))
                children.append((cptr, val, skey, False))
            stack.extend(reversed(children))
        elif isinstance(node, (list, tuple)):
            if id(node) in seen:
                continue
            seen.add(id(node))
            stack.extend(
                (f"{ptr}/{i}", val, pkey, False)
                for i, val in reversed(list(enumerate(node)))
            )


class _Collector:
    def __init__(self, rules: frozenset[str]) -> None:
        self.rules = rules
        self.findings: list[Finding] = []
        self._seen: set[tuple[str, str, str]] = set()
        self._count: dict[tuple[str, str], int] = {}
        self._attempts: dict[tuple[str, str], int] = {}

    def full(self, rule_id: str, ptr: str) -> bool:
        key = (rule_id, ptr)
        return (
            self._count.get(key, 0) >= MAX_FINDINGS_PER_RULE_FIELD
            or self._attempts.get(key, 0) >= MAX_MATCHES_PER_RULE_FIELD
        )

    def add(self, rule_id: str, ptr: str, excerpt: str, detail: str = "") -> bool:
        """Record a finding; return False once the rule is full for this field."""
        if rule_id not in self.rules or self.full(rule_id, ptr):
            return False
        key = (rule_id, ptr)
        self._attempts[key] = self._attempts.get(key, 0) + 1
        evidence = reveal(excerpt[:MAX_EVIDENCE])
        if (rule_id, ptr, evidence) not in self._seen:
            self._seen.add((rule_id, ptr, evidence))
            self._count[key] = self._count.get(key, 0) + 1
            message = MESSAGE[rule_id]
            if detail:
                message = f"{message}: {reveal(detail[:200])}"
            self.findings.append(
                Finding(rule_id, SEVERITY[rule_id], ptr, evidence, message)  # type: ignore[arg-type]
            )
        return not self.full(rule_id, ptr)


@dataclass(frozen=True)
class _Ctx:
    own_name: str
    siblings: frozenset[str]  # same-server tools, excluding this one
    others: Mapping[str, tuple[str, ...]]  # other-server tool name -> server ids
    names: tuple[str, ...]  # every name worth looking for in text
    allowlist: tuple[str, ...]


def _context(
    server_id: str,
    own_name: str,
    inventory: Iterable[InventoryTool],
    config: ScanConfig,
) -> _Ctx:
    siblings: set[str] = set()
    others: dict[str, list[str]] = {}
    for item in inventory:
        name = getattr(item, "name", None)
        sid = getattr(item, "server_id", None)
        if not isinstance(name, str) or not name:
            continue
        if sid == server_id:
            if name != own_name:
                siblings.add(name)
        elif sid not in others.setdefault(name, []):
            others[name].append(str(sid))
    names = tuple(n for n in sorted(siblings | set(others)) if n != own_name)
    allow = tuple(e.lower().strip(".") for e in config.url_allowlist if e.strip("."))
    return _Ctx(
        own_name,
        frozenset(siblings),
        {k: tuple(v) for k, v in others.items()},
        names,
        allow,
    )


# =============================================================================
# Hidden Unicode (TG-UNI-001..004)
# =============================================================================


def _emoji_base(ch: str) -> bool:
    return ch in "#*0123456789" or unicodedata.category(ch).startswith("S")


def _visible_non_ascii(ch: str) -> bool:
    return bool(ch) and not ch.isascii() and _ANY_HIDDEN_RE.match(ch) is None


def _hidden_rule(ch: str, prev: str, nxt: str, rtl: bool) -> str | None:
    cp = ord(ch)
    if 0xE0000 <= cp <= 0xE007F:
        return "TG-UNI-001"
    if 0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069:
        return "TG-UNI-002"
    if 0xFE00 <= cp <= 0xFE0F:
        # VS15/VS16 after an emoji or keycap base is ordinary emoji presentation.
        if cp in (0xFE0E, 0xFE0F) and prev and _emoji_base(prev):
            return None
        return "TG-UNI-004"
    if 0xE0100 <= cp <= 0xE01EF:
        return "TG-UNI-004"
    if (
        cp in _JOINERS
        and (_visible_non_ascii(prev) or prev in ("\ufe0e", "\ufe0f"))
        and _visible_non_ascii(nxt)
    ):
        return None  # a single ZWNJ/ZWJ inside a non-Latin word or emoji sequence
    if cp in _RTL_MARKS and rtl:
        return None  # direction marks inside right-to-left text
    return "TG-UNI-003"


def _hidden(text: str, ptr: str, col: _Collector) -> None:
    if text.isascii():
        return
    rtl = _RTL_RE.search(text) is not None
    open_rules = frozenset(r for r in _HIDDEN_RULES if not col.full(r, ptr))
    pos = 0
    while open_rules:
        m = _hidden_re(open_rules, rtl).search(text, pos)
        if m is None:
            return
        run, start = m.group(), m.start()
        pos = m.end()
        if len(run) == 1:  # fast path: the common single hidden character
            prev = text[start - 1] if start > 0 else ""
            nxt = text[pos] if pos < len(text) else ""
            rule = _hidden_rule(run, prev, nxt, rtl)
            if rule is not None and not col.add(rule, ptr, run):
                open_rules = frozenset(r for r in open_rules if not col.full(r, ptr))
            continue
        if len(run) > _LONG_RUN:
            for rule in _HIDDEN_RULES:
                hit = (
                    _rule_class_re(rule, rtl).search(run)
                    if rule in open_rules
                    else None
                )
                if hit is not None:
                    col.add(rule, ptr, hit.group())
            open_rules = frozenset(r for r in open_rules if not col.full(r, ptr))
            continue
        # Segments of (rule, length); identical neighbours are classified once,
        # so a 100 KB run costs one C-level pass.
        segments: list[tuple[str | None, int]] = []
        offset = 0
        for ch, grp in groupby(run):
            n = len(list(grp))
            at = start + offset
            prev = text[at - 1] if at > 0 else ""
            nxt = text[at + 1] if at + 1 < len(text) else ""
            segments.append((_hidden_rule(ch, prev, nxt, rtl), 1))
            if n > 1:  # the rest are preceded by the same hidden character
                segments.append((_hidden_rule(ch, ch, ch, rtl), n - 1))
            offset += n
        cursor = 0
        for rule, seg in groupby(segments, key=lambda x: x[0]):
            length = sum(n for _, n in seg)
            if rule is not None:
                col.add(rule, ptr, run[cursor : cursor + length])
            cursor += length
        open_rules = frozenset(r for r in open_rules if not col.full(r, ptr))


# =============================================================================
# Text rules (INS, XREF, EXF)
# =============================================================================


def _regex_rule(
    rx: re.Pattern[str], rule_id: str, text: str, ptr: str, col: _Collector
) -> None:
    if rule_id not in col.rules:
        return
    for m in rx.finditer(text):
        if not col.add(rule_id, ptr, m.group()):
            return


@lru_cache(maxsize=256)
def _names_re(names: tuple[str, ...]) -> re.Pattern[str]:
    alts = "|".join(re.escape(n) for n in names)
    return re.compile(rf"(?<![\w-])(?:{alts})(?![\w-])")


def _tool_context(text: str, start: int, end: int) -> bool:
    before = text[start - 1] if start > 0 else ""
    after = text[end] if end < len(text) else ""
    if before and after and before in _QUOTES and after in _QUOTES:
        return True
    if _TOOL_AFTER_RE.match(text, end):
        return True
    return _TOOL_BEFORE_RE.search(text[max(0, start - 12) : start]) is not None


def _xref_mentions(text: str, ptr: str, ctx: _Ctx, col: _Collector) -> None:
    if not ({"TG-XREF-001", "TG-XREF-003"} & col.rules):
        return
    present = tuple(n for n in ctx.names if n in text)
    if not present:
        return
    ordered = tuple(sorted(present, key=lambda n: (-len(n), n)))
    for m in _names_re(ordered).finditer(text):
        name = m.group()
        # A plain English word ("search") counts only when it reads as a tool.
        if _PLAIN_WORD_RE.fullmatch(name) and not _tool_context(
            text, m.start(), m.end()
        ):
            continue
        if name in ctx.siblings:
            col.add("TG-XREF-003", ptr, name, f"{name} (same server)")
        else:
            servers = ", ".join(ctx.others.get(name, ()))
            col.add("TG-XREF-001", ptr, name, f"{name} on server {servers}")
        if col.full("TG-XREF-001", ptr) and col.full("TG-XREF-003", ptr):
            return


def _identifier_like(token: str) -> bool:
    return (
        len(token) >= 4
        and _IDENT_RE.fullmatch(token) is not None
        and ("_" in token or "." in token or _CAMEL_RE.search(token) is not None)
    )


def _redirect_target(tail: str, ctx: _Ctx) -> str | None:
    known = ctx.siblings | ctx.others.keys() | {ctx.own_name}
    tokens = [t.strip(_TAIL_STRIP) for t in tail.split()[:5]]
    for tok in tokens:
        if not tok or tok.lower() in _ARTICLES:
            continue
        if tok in known or _identifier_like(tok):
            return tok
    return None


def _redirects(text: str, ptr: str, ctx: _Ctx, col: _Collector) -> None:
    if "TG-XREF-002" not in col.rules:
        return
    for m in _REDIRECT_RE.finditer(text):
        target = _redirect_target(m.group("tail"), ctx)
        if m.group("after") is not None:
            # "after ... also call X": flag unless X is a sibling on this server.
            if target is not None and target in ctx.siblings:
                continue
        elif target is None or target == ctx.own_name or target in ctx.siblings:
            # "before calling X" / "instead of X" need X to be another tool.
            continue
        if not col.add("TG-XREF-002", ptr, m.group().strip(), target or ""):
            return


def _allowed(host: str, allow: tuple[str, ...]) -> bool:
    return any(host == e or host.endswith("." + e) for e in allow)


def _url_host(url: str) -> str:
    rest = url.split("://", 1)[1]
    auth = re.split(r"[/?#\\]", rest, maxsplit=1)[0].rsplit("@", 1)[-1]
    host = auth[1:].split("]", 1)[0] if auth.startswith("[") else auth.split(":", 1)[0]
    return host.rstrip(".,;:!?)]}").lower()


def _urls(text: str, ptr: str, ctx: _Ctx, col: _Collector) -> None:
    if "TG-EXF-001" not in col.rules:
        return
    spans: list[tuple[int, int]] = []
    if "://" in text:
        for m in _URL_RE.finditer(text):
            spans.append(m.span())
            url = m.group().rstrip(".,;:!?)]}")
            host = _url_host(url)
            if not _allowed(host, ctx.allowlist) and not col.add(
                "TG-EXF-001", ptr, url, host
            ):
                return
    if "@" not in text:
        return
    for m in _EMAIL_RE.finditer(text):
        pos = m.start()
        if any(s <= pos < e for s, e in spans):
            continue
        host = m.group(1).rstrip(".-").lower()
        tld = host.rsplit(".", 1)[-1]
        if "." not in host or len(tld) < 2 or not tld.isalpha():
            continue
        if _allowed(host, ctx.allowlist):
            continue
        local_start = pos
        while local_start > max(0, pos - 64) and (
            text[local_start - 1].isalnum() or text[local_start - 1] in "._+-"
        ):
            local_start -= 1
        if not col.add("TG-EXF-001", ptr, text[local_start:pos] + "@" + host, host):
            return


def _blobs(text: str, ptr: str, col: _Collector) -> None:
    if "TG-EXF-003" not in col.rules:
        return
    for m in _BLOB_RE.finditer(text):
        run = m.group()
        core = run.rstrip("=")
        if len(core) >= HEX_MIN and _HEX_RE.fullmatch(core):
            kind = "hex"
        elif (
            len(core) >= BASE64_MIN
            and core.count("/") * 16 <= len(core)
            and _UPPER_RE.search(core)
            and _LOWER_RE.search(core)
            and _DIGIT_RE.search(core)
        ):
            kind = "base64"
        else:
            continue
        if not col.add("TG-EXF-003", ptr, run, f"{kind}, {len(run)} chars"):
            return


def _text_rules(text: str, ptr: str, ctx: _Ctx, col: _Collector) -> None:
    _regex_rule(_INS_RE, "TG-INS-001", text, ptr, col)
    _regex_rule(_SOFT_RE, "TG-INS-002", text, ptr, col)
    _xref_mentions(text, ptr, ctx, col)
    _redirects(text, ptr, ctx, col)
    _urls(text, ptr, ctx, col)
    _regex_rule(_PATH_RE, "TG-EXF-002", text, ptr, col)
    _blobs(text, ptr, col)


# =============================================================================
# Name and schema rules (UNI-005, SIDE-001, SHADOW-001)
# =============================================================================


def _scripts(name: str) -> set[str]:
    found: set[str] = set()
    for ch in name:
        if ch.isascii():
            if ch.isalpha():
                found.add("Latin")
            continue
        if not ch.isalpha():
            continue
        uname = unicodedata.name(ch, "")
        for prefix, script in MIXED_SCRIPT_PREFIXES:
            if uname.startswith(prefix):
                found.add(script)
                break
    return found


def _mixed_script(name: str, ptr: str, col: _Collector) -> None:
    if name.isascii():
        return
    scripts = _scripts(name)
    if len(scripts) > 1:
        col.add("TG-UNI-005", ptr, name, " + ".join(sorted(scripts)))


def _iter_params(schema: Any, base: str) -> Iterator[tuple[str, str, Any]]:
    """Yield (pointer, name, subschema) for every `properties` entry, any depth."""
    # (pointer, node, node is a `properties` container rather than a schema)
    stack: list[tuple[str, Any, bool]] = [(base, schema, False)]
    seen: set[int] = set()
    while stack:
        ptr, node, is_props = stack.pop()
        if not isinstance(node, (Mapping, list, tuple)) or id(node) in seen:
            continue
        seen.add(id(node))
        items: list[tuple[str, Any, bool]]
        if isinstance(node, Mapping):
            if is_props:
                for key, sub in node.items():
                    if isinstance(key, str):
                        yield f"{ptr}/{_esc(key)}", key, sub
            items = [
                (f"{ptr}/{_esc(str(k))}", v, not is_props and k == "properties")
                for k, v in node.items()
            ]
        else:
            items = [(f"{ptr}/{i}", v, False) for i, v in enumerate(node)]
        stack.extend(reversed(items))


def _is_free_text(sub: Any) -> bool:
    if not isinstance(sub, Mapping):
        return False
    if any(k in sub for k in ("enum", "pattern", "const")):
        return False
    typ = sub.get("type")
    if typ is None:
        return True
    if isinstance(typ, str):
        return typ == "string"
    if isinstance(typ, (list, tuple)):
        return "string" in typ
    return False


def _side_channel(name: str, sub: Any, ptr: str, col: _Collector) -> None:
    tokens = {t.lower() for t in _TOKEN_SPLIT_RE.split(name) if t}
    joined = re.sub(r"[^a-z0-9]", "", name.lower())
    if (
        tokens & SIDE_CHANNEL_TOKENS or joined in SIDE_CHANNEL_TOKENS
    ) and _is_free_text(sub):
        col.add("TG-SIDE-001", ptr, name)


def bounded_levenshtein(a: str, b: str, k: int) -> int:
    """Edit distance between a and b, or k + 1 if it exceeds k (banded DP)."""
    la, lb = len(a), len(b)
    big = k + 1
    if abs(la - lb) > k:
        return big
    prev = [j if j <= k else big for j in range(lb + 1)]
    for i in range(1, la + 1):
        cur = [big] * (lb + 1)
        if i <= k:
            cur[0] = i
        best = cur[0]
        ca = a[i - 1]
        for j in range(max(1, i - k), min(lb, i + k) + 1):
            v = prev[j - 1] + (ca != b[j - 1])
            v = min(v, prev[j] + 1)
            v = min(v, cur[j - 1] + 1)
            cur[j] = min(v, big)
            best = min(best, cur[j])
        if best > k:
            return big
        prev = cur
    return min(prev[lb], big)


def _shadowing(own: str, ctx: _Ctx, col: _Collector) -> None:
    if not own or "TG-SHADOW-001" not in col.rules:
        return
    a = own.casefold()
    hits: list[str] = []
    for other in sorted(ctx.others):
        b = other.casefold()
        if a == b:
            near = True
        elif (
            min(len(a), len(b)) >= SHADOW_FUZZY_MIN_LEN
            and max(len(a), len(b)) <= SHADOW_MAX_NAME_LEN
        ):
            near = bounded_levenshtein(a, b, SHADOW_MAX_DISTANCE) <= SHADOW_MAX_DISTANCE
        else:
            near = False
        if near:
            hits.extend(f"{other} on {sid}" for sid in ctx.others[other])
    if hits:
        col.add("TG-SHADOW-001", "/name", own, "; ".join(hits))


# =============================================================================
# Entry points
# =============================================================================


def definition_findings(
    definition: Mapping[str, Any],
    *,
    server_id: str,
    inventory: Iterable[InventoryTool],
    config: ScanConfig,
) -> tuple[Finding, ...]:
    raw_name = definition.get("name")
    own = raw_name if isinstance(raw_name, str) else ""
    ctx = _context(server_id, own, inventory, config)
    col = _Collector(DEFINITION_RULES)
    for ptr, text, pkey, is_key in _walk(definition, ""):
        _hidden(text, ptr, col)
        if is_key or ptr == "/name" or pkey in STRUCTURAL_KEYS:
            continue
        _text_rules(text, ptr, ctx, col)
    if own:
        _mixed_script(own, "/name", col)
    schema = definition.get("inputSchema")
    for ptr, pname, sub in _iter_params(schema, "/inputSchema"):
        _mixed_script(pname, ptr, col)
        _side_channel(pname, sub, ptr, col)
    _shadowing(own, ctx, col)
    return tuple(col.findings)


def output_findings(
    roots: Iterable[tuple[str, Any]],
    *,
    server_id: str,
    inventory: Iterable[InventoryTool],
    config: ScanConfig,
) -> tuple[Finding, ...]:
    ctx = _context(server_id, "", inventory, config)
    col = _Collector(OUTPUT_RULES)
    for base, node in roots:
        for ptr, text, _pkey, is_key in _walk(node, base):
            _hidden(text, ptr, col)
            if not is_key:
                _text_rules(text, ptr, ctx, col)
    return tuple(col.findings)
