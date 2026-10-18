import os

from toolgate_gateway.pins import PinSource
from toolgate_pin import LockfileStore, PinSet, ServerPin, Target, ToolPin


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _pinset(tool_hash: str = "h1", server_name: str = "srv") -> PinSet:
    tp = ToolPin(
        name="t",
        hash=tool_hash,
        definition={"name": "t"},
        approved_by="test",
        approved_at="2026-10-18T00:00:00+00:00",
        scan={"verdict": "clean", "rule_ids": [], "tiers": ["rules"]},
    )
    return PinSet({"s": ServerPin("s", server_name, Target(url="u"), {"t": tp})})


def _write(path, pins: PinSet) -> None:
    LockfileStore(path).save(pins)


def _bump(path) -> None:
    """Force a distinct mtime so tests never depend on timestamp granularity."""
    st = path.stat()
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 10_000_000))


def test_missing_lockfile_is_empty_pinset(tmp_path):
    src = PinSource(tmp_path / "toolgate.lock.json")
    assert src.current() == PinSet({})
    assert src.pinner() is not None


def test_reads_pins_and_caches_until_file_changes(tmp_path):
    path = tmp_path / "toolgate.lock.json"
    _write(path, _pinset("h1"))
    src = PinSource(path)
    first = src.current()
    pinner = src.pinner()
    assert first.get("s").tools["t"].hash == "h1"
    assert src.current() is first  # unchanged file: no re-read
    assert src.pinner() is pinner

    _write(path, _pinset("h2-longer"))
    _bump(path)
    assert src.current().get("s").tools["t"].hash == "h2-longer"
    assert src.pinner() is not pinner


def test_corrupt_keeps_last_good_until_stale(tmp_path):
    path = tmp_path / "toolgate.lock.json"
    _write(path, _pinset("h1"))
    clock = FakeClock()
    src = PinSource(path, stale_after_s=300.0, clock=clock)
    good = src.current()

    path.write_text("{not json", encoding="utf-8")
    _bump(path)
    clock.now += 10
    assert src.current() is good
    assert src.pinner() is not None
    clock.now += 300  # 300 s since the corruption was first seen
    assert src.current() is good  # exactly at the bound: still served
    clock.now += 1
    assert src.current() is None
    assert src.pinner() is None

    _write(path, _pinset("h3"))
    _bump(path)
    assert src.current().get("s").tools["t"].hash == "h3"


def test_corrupt_at_startup_lists_nothing(tmp_path):
    path = tmp_path / "toolgate.lock.json"
    path.write_text("[]", encoding="utf-8")
    src = PinSource(path)
    assert src.current() is None
    assert src.pinner() is None


def test_same_size_rewrite_with_identical_mtime_is_picked_up(tmp_path):
    path = tmp_path / "toolgate.lock.json"
    _write(path, _pinset("h1"))
    before = path.stat()
    src = PinSource(path)
    assert src.current().get("s").tools["t"].hash == "h1"

    _write(path, _pinset("h2"))  # same size, atomic replace
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    after = path.stat()
    assert (after.st_size, after.st_mtime_ns) == (before.st_size, before.st_mtime_ns)
    assert src.current().get("s").tools["t"].hash == "h2"
