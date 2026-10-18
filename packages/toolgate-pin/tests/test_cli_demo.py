from __future__ import annotations

import asyncio
import io
import socket

from toolgate_pin import cli
from toolgate_pin.connect import in_memory_session
from toolgate_pin.demo_server import HIDDEN_INSTRUCTION, build_demo_server

NAMES = {
    "get_claim_status",
    "get_member_profile",
    "check_coverage",
    "send_member_message",
}


def test_demo_exits_1_and_reveals(capsys):
    assert cli.main(["demo"]) == 1
    out = capsys.readouterr().out
    assert "quarantined get_claim_status (drift)" in out
    assert "⟦U+E0042 TAG LATIN CAPITAL LETTER B⟧" in out  # 'B' of "Before"
    assert HIDDEN_INSTRUCTION in out
    assert "TG-UNI-001" in out
    assert "toolgate-pin approve" in out
    assert "pinned 4 tools" in out


def test_demo_no_fail():
    assert cli.main(["demo", "--no-fail"]) == 0


def test_demo_offline(monkeypatch):
    real_connect = socket.socket.connect

    def guarded_connect(self, address):
        # The Windows event loop's self-pipe connects over loopback; allow that only.
        if not (isinstance(address, tuple) and address[0] in ("127.0.0.1", "::1")):
            raise AssertionError(f"network used: {address!r}")
        return real_connect(self, address)

    def boom(*a, **k):
        raise AssertionError("network used")

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket, "create_connection", boom)
    assert cli.main(["demo"]) == 1


def test_demo_on_cp1252_stdout(monkeypatch):
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1252")
    monkeypatch.setattr("sys.stdout", stream)
    assert cli.main(["demo"]) == 1
    stream.flush()
    text = raw.getvalue().decode("cp1252")
    assert "[[U+E0042" in text
    assert "\u2713" not in text and "\u2717" not in text
    assert "[ok] pinned 4 tools" in text
    assert "[x] quarantined get_claim_status (drift)" in text


async def _tools(mutated: bool):
    async with in_memory_session(build_demo_server(mutated=mutated)) as s:
        return {t.name: t for t in (await s.list_tools()).tools}


def test_demo_server_tools_listed():
    clean = asyncio.run(_tools(False))
    mutated = asyncio.run(_tools(True))
    assert set(clean) == NAMES == set(mutated)
    differing = [n for n in NAMES if clean[n].model_dump() != mutated[n].model_dump()]
    assert differing == ["get_claim_status"]
    assert (
        clean["get_claim_status"].description != mutated["get_claim_status"].description
    )


def test_demo_restores_mcp_logger_level():
    import logging

    lg = logging.getLogger("mcp")
    lg.setLevel(logging.DEBUG)
    cli.main(["demo"])
    assert lg.level == logging.DEBUG
