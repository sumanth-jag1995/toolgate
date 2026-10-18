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
    for f in _corpus_files():
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


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
