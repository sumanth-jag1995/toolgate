"""Check whether PyPI project names are free (read-only GET per name)."""

import sys
import urllib.error
import urllib.request
from typing import Literal

Status = Literal["free", "taken", "error"]


def pypi_status(name: str, opener=urllib.request.urlopen) -> Status:
    """404 means free, 200 means taken, anything else is an error (never free)."""
    url = f"https://pypi.org/pypi/{name}/json"
    try:
        with opener(url, timeout=10) as resp:
            return "taken" if resp.status == 200 else "error"
    except urllib.error.HTTPError as exc:
        return "free" if exc.code == 404 else "error"
    except (urllib.error.URLError, OSError):
        return "error"


def main(argv: list[str]) -> int:
    any_free = False
    for name in argv:
        status = pypi_status(name)
        print(f"{name}: {status}")
        any_free = any_free or status == "free"
    return 0 if any_free else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
