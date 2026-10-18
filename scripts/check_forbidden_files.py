"""Fail if secret-bearing files are about to be committed."""

import sys
from fnmatch import fnmatchcase
from pathlib import PurePosixPath

FORBIDDEN_PATTERNS = (".env", "*.pem", "*.key", "*.tfstate", "*.tfstate.*", "*.tfvars")


def find_forbidden(paths: list[str]) -> list[str]:
    """Return the paths whose basename matches a forbidden pattern."""
    offenders = []
    for path in paths:
        name = PurePosixPath(path.replace("\\", "/")).name
        if name.endswith(".example"):
            continue
        if any(fnmatchcase(name, pattern) for pattern in FORBIDDEN_PATTERNS):
            offenders.append(path)
    return offenders


def main(argv: list[str]) -> int:
    offenders = find_forbidden(argv)
    if offenders:
        print("Forbidden secret files staged:", file=sys.stderr)
        for path in offenders:
            print(f"  {path}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
