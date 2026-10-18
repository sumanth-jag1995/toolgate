from __future__ import annotations

import importlib.resources
import json
import re
from collections import Counter

import pytest
from toolgate_pin.canon import pin_hash
from toolgate_pin.corpus import (
    CANARY_FIELDS,
    Corpus,
    MaliciousVariant,
    load_corpus,
)
from toolgate_pin.models import InventoryTool
from toolgate_pin.scanner import scan_definition

TEST = load_corpus("test")
DEV = load_corpus("dev")
RUG_PULLS = [v for v in TEST.malicious if v.family == "rug_pull"]

# Host of every http(s)/ws/ftp URL and every email address.
_URL_HOST = re.compile(r"(?:https?|wss?|ftp)://([^/\s\"'<>`:]+)", re.IGNORECASE)
_EMAIL_HOST = re.compile(r"[\w.+-]+@([A-Za-z0-9][A-Za-z0-9.-]+)")


def _active(v: MaliciousVariant) -> dict:
    """The live attacker definition: the mutated one for rug pulls."""
    return v.mutated if v.mutated is not None else v.approved


def _inventory(v: MaliciousVariant) -> tuple[InventoryTool, ...]:
    return tuple(
        InventoryTool(server_id=e.server_id, name=e.name, definition=e.definition)
        for e in v.inventory
    )


def _corpus_files() -> list:
    root = importlib.resources.files("toolgate_pin.corpus")
    out: list = []

    def walk(node):
        for child in node.iterdir():
            if child.is_dir():
                walk(child)
            elif child.name.endswith(".json"):
                out.append(child)

    walk(root)
    return out


def test_counts():
    assert isinstance(TEST, Corpus)
    assert Counter(v.family for v in TEST.malicious) == {
        "description_poisoning": 10,
        "rug_pull": 10,
        "shadowing": 5,
        "unicode_schema": 5,
    }


def test_dev_counts():
    assert len(DEV.malicious) == 8


def test_rug_pulls_mutate_and_hash_differs():
    assert len(RUG_PULLS) == 10
    assert all(
        v.mutated is not None and pin_hash(v.mutated) != pin_hash(v.approved)
        for v in RUG_PULLS
    )


def test_mutated_iff_rug_pull():
    for v in TEST.malicious + DEV.malicious:
        assert (v.mutated is not None) == (v.family == "rug_pull"), v.id


def test_rug_pull_approved_is_not_malicious():
    for v in RUG_PULLS:
        report = scan_definition(
            v.approved,
            server_id=v.server_id,
            inventory=_inventory(v),
            tiers=("rules",),
        )
        assert report.verdict != "malicious", f"{v.id}: {report.verdict}"


def test_carrier_param_exists():
    for v in TEST.malicious + DEV.malicious:
        props = _active(v).get("inputSchema", {}).get("properties", {})
        assert v.exfil.carrier_param in props, v.id


def test_exfil_targets_are_canary_fields():
    for v in TEST.malicious + DEV.malicious:
        assert v.exfil.targets
        assert all(t in CANARY_FIELDS for t in v.exfil.targets), v.id


def test_shadowing_has_cross_server_inventory():
    shadows = [v for v in TEST.malicious if v.family == "shadowing"]
    assert len(shadows) == 5
    for v in shadows:
        assert any(e.server_id != v.server_id for e in v.inventory), v.id


def test_output_samples_at_least_3():
    assert sum(1 for v in TEST.malicious if v.output_sample) >= 3


def test_techniques_unique_per_family():
    for split in (TEST, DEV):
        by_family: dict[str, list[str]] = {}
        for v in split.malicious:
            by_family.setdefault(v.family, []).append(v.technique)
        for family, techniques in by_family.items():
            assert len(techniques) == len(set(techniques)), family


def test_only_reserved_hosts():
    # The reserved-host rule covers attack files only; benign definitions are
    # real public MCP tools and legitimately carry real documentation URLs.
    for f in _corpus_files():
        if "benign" in f.parts:
            continue
        text = f.read_text(encoding="utf-8")
        for host in _URL_HOST.findall(text) + _EMAIL_HOST.findall(text):
            host = host.rstrip(".").lower()
            assert host.endswith((".example", ".invalid")), f"{f.name}: {host}"


def test_split_field_matches_directory():
    for f in _corpus_files():
        data = json.loads(f.read_text(encoding="utf-8"))
        expected = "dev" if "dev" in f.parts else "test"
        assert data["split"] == expected, f.name


def test_ids_well_formed():
    ids = {v.id for v in TEST.malicious}
    for prefix, n in (("dp", 10), ("rp", 10), ("sh", 5), ("us", 5)):
        assert {f"{prefix}-{i:02d}" for i in range(1, n + 1)} <= ids
    assert {v.id for v in DEV.malicious} == {f"dv-m-{i:02d}" for i in range(1, 9)}


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _sample_variant(vid="dp-01"):
    v = next(x for x in TEST.malicious if x.id == vid)
    return v.model_dump(mode="json")


def test_missing_malicious_dir_raises(tmp_path):
    from toolgate_pin.corpus import _load_corpus

    # empty root: no malicious/ directory at all
    with pytest.raises(FileNotFoundError):
        _load_corpus(tmp_path, "test")


def test_missing_benign_dir_tolerated(tmp_path):
    from toolgate_pin.corpus import _load_corpus

    _write(
        tmp_path / "malicious" / "description_poisoning" / "dp-01.json",
        _sample_variant("dp-01"),
    )
    corpus = _load_corpus(tmp_path, "test")  # no benign/ dir
    assert [v.id for v in corpus.malicious] == ["dp-01"]
    assert corpus.benign == []


def test_family_must_match_directory(tmp_path):
    from toolgate_pin.corpus import _load_corpus

    data = _sample_variant("dp-01")
    # a description_poisoning variant filed under the rug_pull directory
    _write(tmp_path / "malicious" / "rug_pull" / "dp-01.json", data)
    with pytest.raises(ValueError, match="family"):
        _load_corpus(tmp_path, "test")


def test_id_must_match_filename(tmp_path):
    from toolgate_pin.corpus import _load_corpus

    data = _sample_variant("dp-01")
    _write(tmp_path / "malicious" / "description_poisoning" / "wrong-name.json", data)
    with pytest.raises(ValueError, match="filename"):
        _load_corpus(tmp_path, "test")


def test_split_must_match_requested(tmp_path):
    from toolgate_pin.corpus import _load_corpus

    data = _sample_variant("dp-01")  # split == "test"
    _write(tmp_path / "dev" / "malicious" / "dp-01.json", data)
    with pytest.raises(ValueError, match="split"):
        _load_corpus(tmp_path, "dev")


def test_benign_count_and_sources():
    c = load_corpus("test")
    assert len(c.benign) == 50 and all(b.source for b in c.benign)


def test_benign_repo_diversity():
    assert len({b.source.repo for b in load_corpus().benign}) >= 6


def test_sources_md_lists_every_id():
    root = importlib.resources.files("toolgate_pin.corpus")
    text = (root / "benign" / "SOURCES.md").read_text(encoding="utf-8")
    for b in load_corpus().benign:
        assert b.id in text, b.id
        assert b.source.repo in text and b.source.license in text, b.id


def test_dev_benign_count():
    assert len(load_corpus("dev").benign) == 15
    assert all(b.source is None for b in load_corpus("dev").benign)


def test_no_duplicate_definitions_across_splits():
    test_hashes = {pin_hash(b.definition) for b in load_corpus("test").benign}
    dev_hashes = {pin_hash(b.definition) for b in load_corpus("dev").benign}
    assert test_hashes.isdisjoint(dev_hashes)
    assert len(test_hashes) == 50 and len(dev_hashes) == 15


def test_benign_inventory_shares_server_id():
    for b in TEST.benign + DEV.benign:
        assert all(e.server_id == b.server_id for e in b.inventory), b.id


def test_dev_benign_has_hard_negative_kinds():
    descs = [b.definition["description"] for b in DEV.benign]
    assert any(
        re.search(r"\b(must|should|always|never|important)\b", d, re.IGNORECASE)
        for d in descs
    )
    assert any("https://" in d for d in descs)
    assert any(b.inventory for b in DEV.benign)
    assert any(not d.isascii() for d in descs)


def test_test_benign_hard_negative_kinds():
    descs = [b.definition["description"] for b in TEST.benign]
    assert any(re.search(r"\b(must|should)\b", d, re.IGNORECASE) for d in descs)
    assert any("https://" in d for d in descs)
    assert sum(1 for b in TEST.benign if b.inventory) >= 4
    by_id = {b.id: b.definition["description"] for b in TEST.benign}
    assert "grafo" in by_id["bn-20"] and "conocimiento" in by_id["bn-20"]  # Spanish
    assert "Zeigt" in by_id["bn-22"] and "Commit-Protokoll" in by_id["bn-22"]  # German
    assert "page précédente" in by_id["bn-37"] and by_id["bn-37"].isascii() is False
    for i in ("bn-20", "bn-22", "bn-37"):
        assert not re.search(r"\b(the|of|to|go|back)\b", by_id[i], re.IGNORECASE), i


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
