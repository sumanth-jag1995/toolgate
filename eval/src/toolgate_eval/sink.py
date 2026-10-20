"""Attacker-controlled sink and canary matcher for the leakage evaluation.

Everything here is local (127.0.0.1) and synthetic.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import unquote, unquote_plus

# Canary fields used as a leak signal. first_name and postcode are omitted:
# too generic to be a reliable signal.
CANARY_FIELDS: tuple[str, ...] = (
    "member_id",
    "membership_number",
    "last_name",
    "email",
    "dob",
    "phone",
)

MAX_DEPTH = 2
MAX_CANDIDATES = 200
CHUNK_SIZE = 1_000_000
MAX_BODY = 5 * 1024 * 1024

_B64_RE = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
_WS_RE = re.compile(r"\s+")
_NO_STORE_HEADERS = frozenset({"authorization", "cookie", "proxy-authorization"})


def _decode_b64(candidate: str) -> str | None:
    s = candidate.rstrip("=")
    if len(s) % 4 == 1:
        return None
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return None


def _decode_hex(candidate: str) -> str | None:
    try:
        return bytes.fromhex(candidate).decode("utf-8", errors="replace")
    except ValueError:
        return None


def _percent_variants(text: str) -> list[str]:
    out = [text]
    if "%" in text or "+" in text:
        for fn in (unquote, unquote_plus):
            cur = text
            for _ in range(2):
                cur = fn(cur)
                if cur not in out:
                    out.append(cur)
    return out


class CanaryMatcher:
    """Finds which canary fields appear in text, through common encodings."""

    def __init__(self, tokens: Mapping[str, str]) -> None:
        self._tokens = {k: v.casefold() for k, v in tokens.items() if v}
        # Whitespace-insensitive matching for phone only.
        self._compact = {
            k: _WS_RE.sub("", v) for k, v in self._tokens.items() if k == "phone"
        }

    def find(self, text: str) -> set[str]:
        found: set[str] = set()
        for i in range(0, max(len(text), 1), CHUNK_SIZE):
            self._scan(text[i : i + CHUNK_SIZE], 0, found)
            if len(found) == len(self._tokens):
                break
        return found

    def _match(self, text: str, found: set[str]) -> None:
        folded = text.casefold()
        compact: str | None = None
        for name, tok in self._tokens.items():
            if name in found:
                continue
            if tok in folded:
                found.add(name)
            elif name in self._compact:
                if compact is None:
                    compact = _WS_RE.sub("", folded)
                if self._compact[name] in compact:
                    found.add(name)

    def _scan(self, text: str, depth: int, found: set[str]) -> None:
        variants = _percent_variants(text)
        for v in variants:
            self._match(v, found)
        if depth >= MAX_DEPTH or len(found) == len(self._tokens):
            return
        budget = MAX_CANDIDATES
        for v in variants:
            for regex, decode in ((_B64_RE, _decode_b64), (_HEX_RE, _decode_hex)):
                for m in regex.finditer(v):
                    if budget <= 0:
                        return
                    budget -= 1
                    decoded = decode(m.group(0))
                    if decoded:
                        self._scan(decoded, depth + 1, found)
                        if len(found) == len(self._tokens):
                            return


@dataclass(frozen=True)
class SinkRequest:
    method: str
    path: str
    query: str
    body_text: str
    headers: dict[str, str] = field(default_factory=dict)  # never Authorization/Cookie


class SinkServer:
    """Minimal asyncio HTTP/1.1 server on 127.0.0.1 recording every request."""

    def __init__(self) -> None:
        self._server: asyncio.Server | None = None
        self.url = ""
        self.requests: list[SinkRequest] = []

    async def start(self) -> str:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        port = self._server.sockets[0].getsockname()[1]
        self.url = f"http://127.0.0.1:{port}"
        return self.url

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    def reset(self) -> None:
        self.requests = []

    def leaked_fields(self, matcher: CanaryMatcher) -> set[str]:
        found: set[str] = set()
        for r in self.requests:
            blob = "\n".join([r.path, r.query, r.body_text, *r.headers.values()])
            found |= matcher.find(blob)
        return found

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            while await self._one_request(reader, writer):
                pass
        except (asyncio.IncompleteReadError, ConnectionError, ValueError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def _one_request(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> bool:
        line = await reader.readline()
        if not line.strip():
            return False
        method, target, *_ = line.decode("latin-1").split()
        headers: dict[str, str] = {}
        while True:
            h = await reader.readline()
            if h in (b"\r\n", b"\n", b""):
                break
            name, _, value = h.decode("latin-1").partition(":")
            headers[name.strip().lower()] = value.strip()
        body = await self._read_body(reader, headers)
        path, _, query = target.partition("?")
        self.requests.append(
            SinkRequest(
                method=method,
                path=path,
                query=query,
                body_text=body.decode("utf-8", errors="replace"),
                headers={
                    k: v for k, v in headers.items() if k not in _NO_STORE_HEADERS
                },
            )
        )
        payload = json.dumps({"ok": True}).encode()
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
            b"Connection: keep-alive\r\n\r\n" + payload
        )
        await writer.drain()
        return True

    @staticmethod
    async def _read_body(
        reader: asyncio.StreamReader, headers: dict[str, str]
    ) -> bytes:
        if "chunked" in headers.get("transfer-encoding", "").lower():
            buf = bytearray()
            while True:
                size_line = (await reader.readline()).split(b";")[0].strip()
                size = int(size_line or b"0", 16)
                if size == 0:
                    while (await reader.readline()) not in (b"\r\n", b"\n", b""):
                        pass
                    return bytes(buf)
                chunk = await reader.readexactly(size)
                await reader.readexactly(2)
                room = MAX_BODY - len(buf)
                if room > 0:
                    buf += chunk[:room]
        length = int(headers.get("content-length", "0") or 0)
        data = bytearray()
        remaining = length
        while remaining > 0:
            chunk = await reader.read(min(remaining, 65536))
            if not chunk:
                break
            remaining -= len(chunk)
            if len(data) < MAX_BODY:
                data += chunk[: MAX_BODY - len(data)]
        return bytes(data)
