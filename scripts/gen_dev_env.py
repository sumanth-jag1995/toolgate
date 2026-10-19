"""Generate local-only dev secrets (.env) and the rendered Keycloak realm.

    uv run python scripts/gen_dev_env.py                # first run: writes .env
    uv run python scripts/gen_dev_env.py --add-missing  # later: append new keys only

``--add-missing`` keeps every existing line of ``.env`` untouched and appends
only the keys that ``.env.example`` gained since, with fresh random values for
placeholders. Secret values are never printed.
"""

import argparse
import re
import secrets
from pathlib import Path

PLACEHOLDER = "change-me"
_UNRESOLVED = re.compile(r"\$\{[^}]*\}")
_ROOT = Path(__file__).resolve().parent.parent


def _pairs(text: str) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        env[key] = value
    return env


def _fill(value: str) -> str:
    return secrets.token_urlsafe(32) if value == PLACEHOLDER else value


def generate_env(
    example: Path, out: Path, *, overwrite: bool = False, add_missing: bool = False
) -> dict[str, str]:
    if overwrite and add_missing:
        raise ValueError("overwrite and add_missing are mutually exclusive")
    if out.exists() and add_missing:
        return _add_missing(example, out)
    if out.exists() and not overwrite:
        raise FileExistsError(f"{out} already exists; pass overwrite=True to replace")
    env: dict[str, str] = {}
    lines: list[str] = []
    for line in example.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#") or "=" not in line:
            lines.append(line)
            continue
        key, _, value = line.partition("=")
        value = _fill(value)
        env[key] = value
        lines.append(f"{key}={value}")
    out.write_text("\n".join(lines) + "\n")
    return env


def _add_missing(example: Path, out: Path) -> dict[str, str]:
    existing_text = out.read_text()
    env = _pairs(existing_text)
    new_lines: list[str] = []
    for key, value in _pairs(example.read_text()).items():
        if key in env:
            continue
        env[key] = _fill(value)
        new_lines.append(f"{key}={env[key]}")
    if new_lines:
        prefix = existing_text
        if prefix and not prefix.endswith("\n"):
            prefix += "\n"
        out.write_text(prefix + "\n".join(new_lines) + "\n")
    return env


def render_realm(template: Path, out: Path, env: dict[str, str]) -> None:
    text = template.read_text()
    for key, value in env.items():
        text = text.replace("${" + key + "}", value)
    left = _UNRESOLVED.findall(text)
    if left:
        raise ValueError(f"unresolved placeholders: {sorted(set(left))}")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--add-missing",
        action="store_true",
        help="keep an existing .env and append only keys new in .env.example",
    )
    args = parser.parse_args(argv)
    env = generate_env(
        _ROOT / ".env.example", _ROOT / ".env", add_missing=args.add_missing
    )
    render_realm(
        _ROOT / "infra" / "keycloak" / "toolgate-realm.template.json",
        _ROOT / "infra" / "keycloak" / "generated" / "toolgate-realm.json",
        env,
    )
    print("wrote .env and infra/keycloak/generated/toolgate-realm.json")


if __name__ == "__main__":
    main()
