"""Generate local-only dev secrets (.env) and the rendered Keycloak realm."""

import re
import secrets
from pathlib import Path

PLACEHOLDER = "change-me"
_UNRESOLVED = re.compile(r"\$\{[^}]*\}")
_ROOT = Path(__file__).resolve().parent.parent


def generate_env(
    example: Path, out: Path, *, overwrite: bool = False
) -> dict[str, str]:
    if out.exists() and not overwrite:
        raise FileExistsError(f"{out} already exists; pass overwrite=True to replace")
    env: dict[str, str] = {}
    lines: list[str] = []
    for line in example.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#") or "=" not in line:
            lines.append(line)
            continue
        key, _, value = line.partition("=")
        if value == PLACEHOLDER:
            value = secrets.token_urlsafe(32)
        env[key] = value
        lines.append(f"{key}={value}")
    out.write_text("\n".join(lines) + "\n")
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


def main() -> None:
    env = generate_env(_ROOT / ".env.example", _ROOT / ".env")
    render_realm(
        _ROOT / "infra" / "keycloak" / "toolgate-realm.template.json",
        _ROOT / "infra" / "keycloak" / "generated" / "toolgate-realm.json",
        env,
    )
    print("wrote .env and infra/keycloak/generated/toolgate-realm.json")


if __name__ == "__main__":
    main()
