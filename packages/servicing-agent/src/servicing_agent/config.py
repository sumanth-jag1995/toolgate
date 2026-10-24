"""Model configuration for the servicing agent."""

from __future__ import annotations

from dataclasses import dataclass, fields
from pathlib import Path
from typing import Literal

import yaml

PROVIDERS = ("openrouter", "bedrock")


class ConfigError(Exception):
    """Configuration problem. Messages name a path, variable or reason, never a value."""

    def __init__(self, path: str | Path | None, reason: str) -> None:
        self.path = None if path is None else str(path)
        self.reason = reason
        super().__init__(f"{self.path}: {reason}" if self.path else reason)


@dataclass(frozen=True)
class ModelConfig:
    provider: Literal["openrouter", "bedrock"]
    model: str
    temperature: float = 0.0
    base_url: str | None = None
    api_key_env: str = "OPENROUTER_API_KEY"
    max_tokens: int = 1024
    region: str | None = None  # bedrock only; AWS credentials come from the AWS chain


def load_models(path: str | Path) -> dict[str, ModelConfig]:
    """Load named model configs from a YAML mapping of name -> fields."""
    p = Path(path)
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(p, f"cannot read file ({type(exc).__name__})") from None
    except yaml.YAMLError:
        raise ConfigError(p, "malformed YAML") from None
    if not isinstance(raw, dict):
        raise ConfigError(p, "expected a mapping of model name to settings")
    allowed = {f.name for f in fields(ModelConfig)}
    out: dict[str, ModelConfig] = {}
    for name, entry in raw.items():
        if not isinstance(entry, dict):
            raise ConfigError(p, f"model {name!r}: expected a mapping")
        unknown = set(entry) - allowed
        if unknown:
            raise ConfigError(p, f"model {name!r}: unknown fields {sorted(unknown)}")
        if entry.get("provider") not in PROVIDERS:
            raise ConfigError(p, f"model {name!r}: unknown provider")
        if not isinstance(entry.get("model"), str):
            raise ConfigError(p, f"model {name!r}: 'model' must be a string")
        try:
            out[str(name)] = ModelConfig(**entry)
        except TypeError:
            raise ConfigError(p, f"model {name!r}: invalid settings") from None
    return out
