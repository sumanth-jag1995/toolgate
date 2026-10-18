from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import textwrap
from types import SimpleNamespace

import mcp.types
import pytest
from toolgate_pin import cli, connect


def test_cli_runs_without_mcp_124_http_names():
    # mcp 1.12-1.23 lacks streamable_http_client (and may lack the private
    # create_mcp_http_client). `mcp` itself imports mcp.client.streamable_http,
    # so simulate the older API by deleting the names before toolgate_pin
    # loads: importing the CLI and running `demo` must still work.
    code = textwrap.dedent(
        """
        import mcp.client.streamable_http as sh
        import mcp.shared._httpx_utils as hu
        del sh.streamable_http_client
        del hu.create_mcp_http_client
        from toolgate_pin import cli
        raise SystemExit(cli.main(["demo", "--no-fail"]))
        """
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "quarantined get_claim_status (drift)" in proc.stdout


class _FakeSession:
    def __init__(self, cursors):
        self._cursors = iter(cursors)
        self.calls = 0

    async def list_tools(self, params=None):
        self.calls += 1
        tool = mcp.types.Tool(name=f"t{self.calls}", inputSchema={"type": "object"})
        return SimpleNamespace(tools=[tool], nextCursor=next(self._cursors))


def test_pagination_follows_cursors():
    session = _FakeSession(["a", "b", None])
    tools = asyncio.run(connect.list_all_tools(session))
    assert [t.name for t in tools] == ["t1", "t2", "t3"]


def test_pagination_repeated_cursor_fails():
    session = _FakeSession(["a", "b", "a", "c"])
    with pytest.raises(connect.ToolListError, match="repeated"):
        asyncio.run(connect.list_all_tools(session))
    assert session.calls == 3


def test_pagination_page_cap(monkeypatch):
    monkeypatch.setattr(connect, "MAX_TOOL_PAGES", 5)
    session = _FakeSession(f"c{i}" for i in range(100))
    with pytest.raises(connect.ToolListError, match="5 pages"):
        asyncio.run(connect.list_all_tools(session))
    assert session.calls == 5


def test_check_repeated_cursor_server_exit_2(tmp_path, capsys):
    script = tmp_path / "loop_server.py"
    script.write_text(
        textwrap.dedent(
            """
            import anyio
            import mcp.types as t
            from mcp.server.lowlevel import Server
            from mcp.server.stdio import stdio_server

            srv = Server("looper")

            @srv.list_tools()
            async def _tools(req: t.ListToolsRequest) -> t.ListToolsResult:
                tool = t.Tool(name="x", description="x", inputSchema={"type": "object"})
                return t.ListToolsResult(tools=[tool], nextCursor="same")

            async def main():
                async with stdio_server() as (r, w):
                    await srv.run(r, w, srv.create_initialization_options())

            anyio.run(main)
            """
        ),
        encoding="utf-8",
    )
    lock = tmp_path / "toolgate.lock.json"
    code = cli.main(
        ["check", "--lockfile", str(lock), "--stdio", "--", sys.executable, str(script)]
    )
    out = capsys.readouterr()
    assert code == 2
    assert "repeated" in out.out + out.err
