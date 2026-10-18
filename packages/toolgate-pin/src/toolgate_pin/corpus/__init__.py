"""Attack corpus: pydantic schema and the ``load_corpus`` package-data loader.

The corpus is synthetic defensive-security research data. Malicious variants
describe tool-poisoning attacks (hidden instructions, rug pulls, cross-server
shadowing, hidden-Unicode/schema poisoning) using only reserved fake hosts
(``*.example`` / ``*.invalid``) and synthetic insurer data. They measure the
scanner and, later, drive sub-project D's canary-leak eval.

JSON files live under this package:

* test split: ``malicious/<family>/<id>.json`` and ``benign/*.json``
* dev split:  ``dev/malicious/*.json`` and ``dev/benign/*.json``

Each malicious file is a :class:`MaliciousVariant`; each benign file is a
:class:`BenignDefinition`. The split is read from the directory, never guessed.
"""

from __future__ import annotations

import importlib.resources
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

__all__ = [
    "CANARY_FIELDS",
    "BenignDefinition",
    "Corpus",
    "Exfil",
    "InventoryEntry",
    "MaliciousVariant",
    "Source",
    "load_corpus",
]

CANARY_FIELDS: tuple[str, ...] = (
    "membership_number",
    "email",
    "phone",
    "dob",
    "last_name",
)

CanaryField = Literal[
    "membership_number",
    "email",
    "phone",
    "dob",
    "last_name",
]
Split = Literal["test", "dev"]
Family = Literal[
    "description_poisoning",
    "rug_pull",
    "shadowing",
    "unicode_schema",
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class InventoryEntry(_Strict):
    """Another tool present in the agent's inventory at scan time."""

    server_id: str
    name: str
    definition: dict[str, Any]


class Exfil(_Strict):
    """Which canary fields the attack targets and which parameter carries them.

    Shared with sub-project D's attacker server, which loads the same files.
    """

    targets: list[CanaryField]
    carrier_param: str


class MaliciousVariant(_Strict):
    id: str
    split: Split
    family: Family
    technique: str
    server_id: str
    approved: dict[str, Any]
    mutated: dict[str, Any] | None = None
    inventory: list[InventoryEntry] = Field(default_factory=list)
    output_sample: str | None = None
    exfil: Exfil

    @model_validator(mode="after")
    def _check(self) -> MaliciousVariant:
        # mutated iff rug_pull.
        if (self.mutated is not None) != (self.family == "rug_pull"):
            raise ValueError(
                f"{self.id}: `mutated` is required if and only if family is rug_pull"
            )
        # carrier_param must name a property in the live attacker definition.
        live = self.mutated if self.mutated is not None else self.approved
        props = live.get("inputSchema", {}).get("properties", {})
        if self.exfil.carrier_param not in props:
            raise ValueError(
                f"{self.id}: carrier_param {self.exfil.carrier_param!r} is not a "
                "property of the attacker tool's inputSchema"
            )
        # shadowing points at a tool on another server.
        if self.family == "shadowing" and not any(
            e.server_id != self.server_id for e in self.inventory
        ):
            raise ValueError(f"{self.id}: shadowing needs cross-server inventory")
        return self


class Source(_Strict):
    repo: str
    path: str
    license: Literal["MIT", "Apache-2.0"]
    changes: str


class BenignDefinition(_Strict):
    id: str
    split: Split
    server_id: str
    definition: dict[str, Any]
    inventory: list[InventoryEntry] = Field(default_factory=list)
    source: Source | None = None

    @model_validator(mode="after")
    def _check(self) -> BenignDefinition:
        # Provenance is required for the test-split benign set only.
        if self.split == "test" and self.source is None:
            raise ValueError(f"{self.id}: test-split benign files require `source`")
        return self


class Corpus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    malicious: list[MaliciousVariant] = Field(default_factory=list)
    benign: list[BenignDefinition] = Field(default_factory=list)


def _iter_json(node: Any) -> list[Any]:
    found: list[Any] = []
    for child in node.iterdir():
        if child.is_dir():
            found.extend(_iter_json(child))
        elif child.name.endswith(".json"):
            found.append(child)
    return found


def load_corpus(split: Split = "test") -> Corpus:
    """Load every malicious and benign definition for ``split`` from package data."""
    root = importlib.resources.files("toolgate_pin.corpus")
    if split == "test":
        mal_dir, ben_dir = root / "malicious", root / "benign"
    else:
        mal_dir, ben_dir = root / "dev" / "malicious", root / "dev" / "benign"

    malicious: list[MaliciousVariant] = []
    if mal_dir.is_dir():
        for f in sorted(_iter_json(mal_dir), key=lambda p: p.name):
            malicious.append(
                MaliciousVariant.model_validate_json(f.read_text(encoding="utf-8"))
            )

    benign: list[BenignDefinition] = []
    if ben_dir.is_dir():
        for f in sorted(_iter_json(ben_dir), key=lambda p: p.name):
            benign.append(
                BenignDefinition.model_validate_json(f.read_text(encoding="utf-8"))
            )

    malicious.sort(key=lambda v: v.id)
    benign.sort(key=lambda v: v.id)
    return Corpus(malicious=malicious, benign=benign)


# Re-export for callers that want the raw JSON of one file by relative path.
def read_raw(relative_path: str) -> dict[str, Any]:
    """Return the parsed JSON of a single corpus file (e.g. ``malicious/..``)."""
    root = importlib.resources.files("toolgate_pin.corpus")
    node = root
    for part in relative_path.split("/"):
        node = node / part
    return json.loads(node.read_text(encoding="utf-8"))
