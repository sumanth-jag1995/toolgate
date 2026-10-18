from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path

import yaml


class PolicyError(Exception):
    def __init__(self, path: Path | str, reason: str) -> None:
        self.path = str(path)
        self.reason = reason
        super().__init__(f"{self.path}: {reason}")


def load_yaml_mapping(path: Path | str) -> dict:
    p = Path(path)
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except OSError as e:
        raise PolicyError(p, f"cannot read file ({type(e).__name__})") from e
    except yaml.YAMLError as e:
        raise PolicyError(p, "invalid YAML") from e
    if not isinstance(data, dict):
        raise PolicyError(p, "top level must be a mapping")
    return data


class Allowlist:
    def __init__(self, agents: dict[str, tuple[str, ...]]) -> None:
        self._agents = agents

    @classmethod
    def load(cls, path: Path | str) -> Allowlist:
        data = load_yaml_mapping(path)
        agents = data.get("agents")
        if not isinstance(agents, dict):
            raise PolicyError(path, "'agents' must be a mapping")
        out: dict[str, tuple[str, ...]] = {}
        for client, patterns in agents.items():
            if not isinstance(client, str) or not isinstance(patterns, list):
                raise PolicyError(path, "each agent must map to a list of patterns")
            if not all(isinstance(p, str) for p in patterns):
                raise PolicyError(path, f"patterns for {client!r} must be strings")
            out[client] = tuple(patterns)
        return cls(out)

    @property
    def clients(self) -> frozenset[str]:
        return frozenset(self._agents)

    def allowed(self, client_id: str, namespaced: str) -> bool:
        return any(fnmatchcase(namespaced, p) for p in self._agents.get(client_id, ()))
