from __future__ import annotations

import json
import socket
import subprocess
import sys
import textwrap
import threading
import time

import pytest
from toolgate_pin import cli
from toolgate_pin.models import PinSet, ServerPin, Target
from toolgate_pin.store import LockfileStore

DEMO = [sys.executable, "-m", "toolgate_pin.cli", "demo-server"]
SECRET = "s3cr3t-value"


def _run(capsys, *argv: str) -> tuple[int, str]:
    code = cli.main(list(argv))
    cap = capsys.readouterr()
    return code, cap.out + cap.err


def _approve(lock, *extra: str, cmd=DEMO) -> int:
    return cli.main(
        ["approve", "--lockfile", str(lock), "--yes", "--as", "tester", *extra]
        + ["--stdio", "--", *cmd]
    )


def _tools(lock) -> dict:
    return json.loads(lock.read_text(encoding="utf-8"))["servers"]["insurer-demo"][
        "tools"
    ]


def test_approve_then_check_clean_stdio(tmp_path, capsys):
    lock = tmp_path / "toolgate.lock.json"
    assert _approve(lock) == 0
    tools = _tools(lock)
    assert len(tools) == 4
    assert {t["approved_by"] for t in tools.values()} == {"tester"}
    assert all("+00:00" in t["approved_at"] for t in tools.values())
    capsys.readouterr()
    code, out = _run(capsys, "check", "--lockfile", str(lock), "--stdio", "--", *DEMO)
    assert code == 0, out


def test_check_detects_mutation_stdio(tmp_path, capsys):
    lock = tmp_path / "toolgate.lock.json"
    assert _approve(lock) == 0
    capsys.readouterr()
    code, out = _run(
        capsys,
        "check",
        "--lockfile",
        str(lock),
        "--name",
        "insurer-demo",
        "--stdio",
        "--",
        *DEMO,
        "--mutated",
    )
    assert code == 1
    assert "drift" in out
    assert "⟦U+E0042" in out


def test_bare_check_uses_lockfile_targets(tmp_path, capsys):
    lock = tmp_path / "toolgate.lock.json"
    assert _approve(lock) == 0
    capsys.readouterr()
    code, out = _run(capsys, "check", "--lockfile", str(lock))
    assert code == 0, out
    assert "insurer-demo" in out


def test_bare_check_empty_lockfile_exit_2(tmp_path, capsys):
    code, out = _run(capsys, "check", "--lockfile", str(tmp_path / "missing.json"))
    assert code == 2
    assert "approve" in out


def test_target_change_is_not_drift(tmp_path, capsys):
    lock = tmp_path / "toolgate.lock.json"
    assert _approve(lock) == 0
    capsys.readouterr()
    other = [sys.executable, "-X", "utf8", "-m", "toolgate_pin.cli", "demo-server"]
    code, out = _run(capsys, "check", "--lockfile", str(lock), "--stdio", "--", *other)
    assert code == 0, out


def test_approve_blocked_exit_3(tmp_path, capsys):
    lock = tmp_path / "toolgate.lock.json"
    assert _approve(lock, cmd=[*DEMO, "--mutated"]) == 3
    assert not lock.exists()
    out = capsys.readouterr()
    assert "TG-UNI-001" in out.out + out.err
    assert "--override" in out.out + out.err


def test_approve_override_records_reason(tmp_path):
    lock = tmp_path / "toolgate.lock.json"
    assert _approve(lock, "--override", "demo test", cmd=[*DEMO, "--mutated"]) == 0
    tools = _tools(lock)
    reason = tools["get_claim_status"]["override_reason"]
    assert reason.startswith("demo test")
    assert reason == "demo test [tiers: rules]"
    assert tools["check_coverage"]["override_reason"] is None


def test_reapprove_keeps_unchanged_approvals(tmp_path):
    lock = tmp_path / "toolgate.lock.json"
    assert _approve(lock) == 0
    first = _tools(lock)
    assert (
        cli.main(
            ["approve", "--lockfile", str(lock), "--yes", "--as", "second"]
            + ["--override", "accepted", "--stdio", "--", *DEMO, "--mutated"]
        )
        == 0
    )
    second = _tools(lock)
    assert second["check_coverage"] == first["check_coverage"]
    assert second["get_claim_status"]["approved_by"] == "second"
    assert second["get_claim_status"]["hash"] != first["get_claim_status"]["hash"]


def test_approve_unavailable_tiers_reported(tmp_path, capsys, monkeypatch):
    from toolgate_pin.scanner import classifier

    monkeypatch.setattr(classifier, "available", lambda: False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    lock = tmp_path / "toolgate.lock.json"
    assert _approve(lock, "--judge", "--classifier") == 0
    out = capsys.readouterr()
    assert "unavailable" in out.out + out.err
    tools = _tools(lock)
    assert all(t["scan"]["tiers"] == ["rules"] for t in tools.values())


def test_approve_non_tty_without_yes_exit_2(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    lock = tmp_path / "toolgate.lock.json"
    code, out = _run(
        capsys,
        "approve",
        "--lockfile",
        str(lock),
        "--as",
        "tester",
        "--stdio",
        "--",
        *DEMO,
    )
    assert code == 2
    assert "--yes" in out
    assert not lock.exists()


def test_approve_without_approver_exit_2(tmp_path, capsys, monkeypatch):
    def no_git(*a, **k):
        raise FileNotFoundError("git")

    monkeypatch.setattr("toolgate_pin.commands.approve.subprocess.run", no_git)
    lock = tmp_path / "toolgate.lock.json"
    code, out = _run(
        capsys, "approve", "--lockfile", str(lock), "--yes", "--stdio", "--", *DEMO
    )
    assert code == 2
    assert "--as" in out


def test_approve_refuses_duplicate_tool_names(tmp_path, capsys):
    script = tmp_path / "dupes_server.py"
    script.write_text(
        textwrap.dedent(
            """
            import anyio
            import mcp.types as t
            from mcp.server.lowlevel import Server
            from mcp.server.stdio import stdio_server

            srv = Server("dupes")

            @srv.list_tools()
            async def _tools():
                schema = {"type": "object"}
                return [
                    t.Tool(name="lookup", description="a", inputSchema=schema),
                    t.Tool(name="lookup", description="b", inputSchema=schema),
                ]

            async def main():
                async with stdio_server() as (r, w):
                    await srv.run(r, w, srv.create_initialization_options())

            anyio.run(main)
            """
        ),
        encoding="utf-8",
    )
    lock = tmp_path / "toolgate.lock.json"
    code = _approve(lock, cmd=[sys.executable, str(script)])
    out = capsys.readouterr()
    assert code == 2
    assert "lookup" in out.out + out.err
    assert not lock.exists()


def test_literal_header_refused(tmp_path, capsys):
    lock = tmp_path / "toolgate.lock.json"
    code, out = _run(
        capsys,
        "approve",
        "http://127.0.0.1:9/mcp",
        "--header",
        "Authorization: Bearer abc123",
        "--lockfile",
        str(lock),
        "--yes",
        "--as",
        "tester",
    )
    assert code == 2
    assert "abc123" not in out
    assert "${" in out
    assert not lock.exists()


def _http_lock(lock, url: str, sid: str = "remote") -> None:
    sp = ServerPin(
        server_id=sid,
        server_name="insurer-demo",
        target=Target(url=url, headers=("Authorization: Bearer ${TG_TOKEN}",)),
        tools={},
    )
    LockfileStore(lock).save(PinSet({}).with_server(sp))


def test_missing_env_var_exit_2(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("TG_TOKEN", raising=False)
    lock = tmp_path / "toolgate.lock.json"
    _http_lock(lock, "http://127.0.0.1:9/mcp")
    code, out = _run(capsys, "check", "--lockfile", str(lock))
    assert code == 2
    assert "TG_TOKEN" in out


def test_one_server_error_others_still_checked(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("TG_TOKEN", raising=False)
    lock = tmp_path / "toolgate.lock.json"
    assert _approve(lock) == 0
    store = LockfileStore(lock)
    sp = ServerPin(
        server_id="remote",
        server_name="insurer-demo",
        target=Target(
            url="http://127.0.0.1:9/mcp",
            headers=("Authorization: Bearer ${TG_TOKEN}",),
        ),
        tools={},
    )
    store.save(store.load().with_server(sp))
    capsys.readouterr()
    code, out = _run(capsys, "check", "--lockfile", str(lock), "--format", "json")
    assert code == 2
    report = json.loads(out)
    assert report["ok"] is False
    by_id = {s["server_id"]: s for s in report["servers"]}
    assert by_id["insurer-demo"]["error"] is None
    assert by_id["insurer-demo"]["quarantined"] == []
    assert "TG_TOKEN" in by_id["remote"]["error"]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def http_demo():
    """The demo server over streamable HTTP; requests without the token get 401."""
    import uvicorn
    from toolgate_pin.demo_server import build_demo_server

    inner = build_demo_server().streamable_http_app()
    seen: list[str] = []

    async def app(scope, receive, send):
        if scope["type"] == "http":
            auth = dict(scope["headers"]).get(b"authorization", b"").decode()
            seen.append(auth)
            if auth != f"Bearer {SECRET}":
                await send(
                    {"type": "http.response.start", "status": 401, "headers": []}
                )
                await send({"type": "http.response.body", "body": b"unauthorized"})
                return
        await inner(scope, receive, send)

    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        assert time.monotonic() < deadline, "uvicorn did not start"
        time.sleep(0.05)
    try:
        yield f"http://127.0.0.1:{port}/mcp", seen
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def test_header_value_never_written(tmp_path, capsys, monkeypatch, http_demo):
    url, seen = http_demo
    monkeypatch.setenv("TG_TOKEN", SECRET)
    lock = tmp_path / "toolgate.lock.json"
    code, out = _run(
        capsys,
        "approve",
        url,
        "--header",
        "Authorization: Bearer ${TG_TOKEN}",
        "--lockfile",
        str(lock),
        "--yes",
        "--as",
        "tester",
    )
    assert code == 0, out
    text = lock.read_text(encoding="utf-8")
    assert "${TG_TOKEN}" in text
    assert SECRET not in text
    assert SECRET not in out
    assert seen and all(a == f"Bearer {SECRET}" for a in seen)

    code, out = _run(capsys, "check", "--lockfile", str(lock))
    assert code == 0, out
    assert SECRET not in out


def test_http_connect_error_exit_2(tmp_path, capsys, monkeypatch, http_demo):
    url, _ = http_demo
    monkeypatch.setenv("TG_TOKEN", "wrong-token-value")
    lock = tmp_path / "toolgate.lock.json"
    code, out = _run(
        capsys,
        "approve",
        url,
        "--header",
        "Authorization: Bearer ${TG_TOKEN}",
        "--lockfile",
        str(lock),
        "--yes",
        "--as",
        "tester",
    )
    assert code == 2
    assert "127.0.0.1" in out
    assert "wrong-token-value" not in out
    assert not lock.exists()


def test_corrupt_lockfile_exit_2(tmp_path, capsys):
    lock = tmp_path / "toolgate.lock.json"
    lock.write_text("{not json", encoding="utf-8")
    code = cli.main(["check", "--lockfile", str(lock)])
    cap = capsys.readouterr()
    assert code == 2
    assert cap.out == ""
    lines = cap.err.strip().splitlines()
    assert len(lines) == 1
    assert "toolgate.lock.json" in lines[0]


def test_json_format(tmp_path, capsys):
    lock = tmp_path / "toolgate.lock.json"
    assert _approve(lock) == 0
    capsys.readouterr()
    code = cli.main(
        ["check", "--lockfile", str(lock), "--format", "json", "--name"]
        + ["insurer-demo", "--stdio", "--", *DEMO, "--mutated"]
    )
    out = capsys.readouterr().out
    assert code == 1
    report = json.loads(out)
    assert report["ok"] is False
    [server] = report["servers"]
    assert server["server_id"] == "insurer-demo" and server["error"] is None
    [q] = server["quarantined"]
    assert q["reason"] == "drift" and q["tool_name"] == "get_claim_status"
    assert set(q) == {"tool_name", "reason", "observed_hash", "pinned_hash", "diff"}


def test_module_entry_point_runs_demo_server():
    # `python -m toolgate_pin.cli` must reach main() (stdio tests rely on it).
    proc = subprocess.run(
        [sys.executable, "-m", "toolgate_pin.cli", "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0
    assert "approve" in proc.stdout and "check" in proc.stdout


@pytest.mark.parametrize(
    ("mutate", "secrets"),
    [
        (lambda u: u.replace("//", "//usr:pwsecret@"), ("pwsecret", "usr:")),
        (lambda u: u + "?key=qsecret", ("qsecret",)),
        (
            lambda u: u.replace("//", "//usr:pwsecret@") + "?key=qsecret",
            ("pwsecret", "qsecret"),
        ),
        (lambda u: u + "?key=${TG_TOKEN}", ()),
    ],
)
def test_url_secrets_refused(tmp_path, capsys, monkeypatch, http_demo, mutate, secrets):
    # A live, reachable server: refusal must come from validation, not a failed
    # connection, and no request may be made at all.
    url, seen = http_demo
    monkeypatch.setenv("TG_TOKEN", SECRET)
    lock = tmp_path / "toolgate.lock.json"
    code, out = _run(
        capsys,
        "approve",
        mutate(url),
        "--header",
        "Authorization: Bearer ${TG_TOKEN}",
        "--lockfile",
        str(lock),
        "--yes",
        "--as",
        "tester",
    )
    assert code == 2
    assert "refused" in out or "credentials" in out
    assert not lock.exists()
    assert seen == []
    for s in (*secrets, SECRET):
        assert s not in out


def test_check_explicit_url_with_credentials_refused(tmp_path, capsys):
    lock = tmp_path / "toolgate.lock.json"
    _http_lock(lock, "http://127.0.0.1:9/mcp")
    code, out = _run(
        capsys,
        "check",
        "http://usr:pwsecret@127.0.0.1:9/mcp",
        "--lockfile",
        str(lock),
    )
    assert code == 2
    assert "pwsecret" not in out


def _approve_http(capsys, lock, url) -> None:
    code, out = _run(
        capsys,
        "approve",
        url,
        "--header",
        "Authorization: Bearer ${TG_TOKEN}",
        "--lockfile",
        str(lock),
        "--yes",
        "--as",
        "tester",
    )
    assert code == 0, out


def test_named_check_reuses_headers_same_origin(
    tmp_path, capsys, monkeypatch, http_demo
):
    url, seen = http_demo
    monkeypatch.setenv("TG_TOKEN", SECRET)
    lock = tmp_path / "toolgate.lock.json"
    _approve_http(capsys, lock, url)
    seen.clear()
    code, out = _run(
        capsys, "check", url, "--name", "insurer-demo", "--lockfile", str(lock)
    )
    assert code == 0, out
    assert seen and all(a == f"Bearer {SECRET}" for a in seen)
    assert SECRET not in out


def test_named_check_refuses_cross_origin_headers(
    tmp_path, capsys, monkeypatch, http_demo
):
    url, seen = http_demo
    monkeypatch.setenv("TG_TOKEN", SECRET)
    lock = tmp_path / "toolgate.lock.json"
    _approve_http(capsys, lock, url)
    seen.clear()
    # Same server, different origin (host spelled differently): must not get the token.
    other = url.replace("127.0.0.1", "localhost")
    code, out = _run(
        capsys, "check", other, "--name", "insurer-demo", "--lockfile", str(lock)
    )
    assert code == 2
    assert "origin" in out
    assert SECRET not in out
    assert all(SECRET not in a for a in seen)
    assert seen == []


def test_http_falls_back_to_deprecated_client(tmp_path, capsys, monkeypatch, http_demo):
    """mcp < 1.24 has only streamablehttp_client(url, headers=...)."""
    import warnings
    from contextlib import asynccontextmanager

    import httpx
    import mcp.client.streamable_http as sh

    url, seen = http_demo
    new_client = sh.streamable_http_client
    monkeypatch.delattr(sh, "streamable_http_client")
    calls: list[tuple[str, dict]] = []

    @asynccontextmanager
    async def _streams(u, headers):
        async with (
            httpx.AsyncClient(headers=headers) as client,
            new_client(u, http_client=client) as streams,
        ):
            yield streams

    def old_client(u, headers=None):
        warnings.warn("fallback-sentinel deprecated", DeprecationWarning, stacklevel=2)
        calls.append((u, dict(headers or {})))
        return _streams(u, headers)

    monkeypatch.setattr(sh, "streamablehttp_client", old_client, raising=False)
    monkeypatch.setenv("TG_TOKEN", SECRET)
    lock = tmp_path / "toolgate.lock.json"
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        _approve_http(capsys, lock, url)
    assert calls == [(url, {"Authorization": f"Bearer {SECRET}"})]
    assert seen and all(a == f"Bearer {SECRET}" for a in seen)
    assert not [w for w in caught if "fallback-sentinel" in str(w.message)]


def test_check_name_only_checks_that_server(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("TG_TOKEN", raising=False)
    lock = tmp_path / "toolgate.lock.json"
    assert _approve(lock) == 0
    store = LockfileStore(lock)
    broken = ServerPin(
        server_id="remote",
        server_name="insurer-demo",
        target=Target(
            url="http://127.0.0.1:9/mcp",
            headers=("Authorization: Bearer ${TG_TOKEN}",),
        ),
        tools={},
    )
    store.save(store.load().with_server(broken))
    capsys.readouterr()
    code, out = _run(capsys, "check", "--lockfile", str(lock), "--name", "insurer-demo")
    assert code == 0, out
    assert "insurer-demo: ok" in out
    assert "remote" not in out and "TG_TOKEN" not in out


def test_check_name_unknown_exit_2(tmp_path, capsys):
    lock = tmp_path / "toolgate.lock.json"
    assert _approve(lock) == 0
    capsys.readouterr()
    code, out = _run(
        capsys, "check", "--lockfile", str(lock), "--name", "does-not-exist"
    )
    assert code == 2
    assert "server does-not-exist is not pinned" in out
    assert "check passed" not in out


class _FakeJudge:
    model = "fake/model"

    def __init__(self, verdicts=None, error=None):
        self.verdicts = verdicts or {}
        self.error = error
        self.last_error: str | None = None

    def judge(self, tool, *, prior):
        from toolgate_pin.models import JudgeResult

        if self.error:
            self.last_error = self.error
            return None
        verdict, reasons = self.verdicts.get(tool["name"], ("benign", ()))
        return JudgeResult(verdict, reasons, self.model)


class _FakeClassifier:
    load_error: str | None = None

    def score(self, tool):
        return 0.1234


def _with_fake_tiers(monkeypatch, judge, clf_cls=_FakeClassifier) -> None:
    from toolgate_pin.scanner import classifier
    from toolgate_pin.scanner.judge import Judge

    monkeypatch.setattr(Judge, "from_env", classmethod(lambda cls, **k: judge))
    monkeypatch.setattr(classifier, "available", lambda: True)
    monkeypatch.setattr(classifier, "Classifier", clf_cls)


def test_approve_prints_classifier_and_judge_evidence(tmp_path, capsys, monkeypatch):
    long_reason = "y" * 2000
    judge = _FakeJudge(
        {
            "get_claim_status": (
                "malicious",
                ("asks to\x1b[2J exfiltrate\u200b data", long_reason),
            )
        }
    )
    _with_fake_tiers(monkeypatch, judge)
    lock = tmp_path / "toolgate.lock.json"
    assert _approve(lock, "--judge", "--classifier") == 3
    cap = capsys.readouterr()
    out = cap.out + cap.err
    assert "classifier score: 0.1234" in out
    assert "judge (fake/model): malicious" in out
    assert "judge (fake/model): benign" in out
    assert "\x1b" not in out and "\u27e6U+001B\u27e7" in out
    assert "\u27e6U+200B ZERO WIDTH SPACE\u27e7" in out
    assert long_reason not in out and "y" * 100 in out
    assert "blocked: get_claim_status (judge) judged malicious" in cap.err
    assert not lock.exists()


def test_approve_blocked_names_rules_tier(tmp_path, capsys):
    lock = tmp_path / "toolgate.lock.json"
    assert _approve(lock, cmd=[*DEMO, "--mutated"]) == 3
    assert "blocked: get_claim_status (rules) judged malicious" in (
        capsys.readouterr().err
    )


def test_approve_unavailable_note_names_the_cause(tmp_path, capsys, monkeypatch):
    class _BrokenClassifier:
        load_error = "OSError"

        def score(self, tool):
            raise RuntimeError("model failed to load")

    _with_fake_tiers(monkeypatch, _FakeJudge(error="HTTP 429"), _BrokenClassifier)
    lock = tmp_path / "toolgate.lock.json"
    assert _approve(lock, "--judge", "--classifier") == 0
    out = capsys.readouterr().out
    assert "note: the judge tier is unavailable (HTTP 429); it did not run" in out
    assert "note: the classifier tier is unavailable (OSError); it did not run" in out
