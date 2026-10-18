from __future__ import annotations

import pytest
from toolgate_pin.models import PinSet, ServerPin, Target, ToolPin
from toolgate_pin.store import InMemoryStore, LockfileError, LockfileStore


def _pinset() -> PinSet:
    tp = ToolPin(
        name="t",
        hash="sha256:abc",
        definition={"name": "t", "description": "caf\u00e9"},
        approved_by="me",
        approved_at="2026-10-18T00:00:00Z",
        scan={"verdict": "benign", "rule_ids": [], "tiers": ["rules"]},
    )
    sp = ServerPin(
        server_id="s",
        server_name="Server",
        target=Target(command=("npx", "srv"), headers=("Authorization: Bearer ${T}",)),
        tools={"t": tp},
    )
    return PinSet({}).with_server(sp)


def test_roundtrip_and_byte_stable(tmp_path):
    p = tmp_path / "sub" / "l.json"
    store = LockfileStore(p)
    pins = _pinset()
    store.save(pins)
    first = p.read_bytes()
    loaded = store.load()
    assert loaded == pins
    store.save(loaded)
    assert p.read_bytes() == first
    assert first.endswith(b"\n") and b"\r" not in first
    assert '"version": 1' in first.decode("utf-8")
    assert "caf\u00e9".encode() in first  # ensure_ascii=False, UTF-8


def test_missing_file_is_empty(tmp_path):
    assert LockfileStore(tmp_path / "x.json").load().servers == {}


@pytest.mark.parametrize(
    "content",
    [
        "{not json",
        '{"version": 2, "servers": {}}',
        '{"version": 1}',
        "[]",
        '{"version": 1, "servers": {"s": {"server_name": "x"}}}',
        '{"version": 1, "servers": {"s": {"server_name": "x", "target": {}, "tools": {"t": {}}}}}',
    ],
)
def test_bad_lockfile_raises(tmp_path, content):
    p = tmp_path / "l.json"
    p.write_text(content)
    with pytest.raises(LockfileError) as exc:
        LockfileStore(p).load()
    assert str(p) in str(exc.value)
    assert content not in str(exc.value)


def test_with_server_does_not_mutate():
    a = PinSet({})
    b = _pinset()
    c = a.with_server(b.servers["s"])
    assert a.servers == {} and c.get("s") is not None and c.get("zz") is None


def test_in_memory_store():
    s = InMemoryStore()
    assert s.load().servers == {}
    s.save(_pinset())
    assert s.load().get("s") is not None


def test_deeply_nested_lockfile_raises_lockfile_error(tmp_path):
    p = tmp_path / "l.json"
    p.write_text("[" * 100000)
    with pytest.raises(LockfileError) as exc:
        LockfileStore(p).load()
    assert str(p) in str(exc.value)
