"""Scanner configuration: URL allowlist and classifier thresholds.

Rule severities and patterns live in the "Tunables" block at the top of
``scanner/rules.py``. Task 9 tunes both files on the dev split only, then
freezes them.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanConfig:
    # Hosts allowed in URLs and email addresses. An entry matches the host
    # exactly or as a dot-suffix: "example.com" allows "docs.example.com".
    url_allowlist: tuple[str, ...] = ()
    classifier_high: float = 0.9
    classifier_grey: float = 0.5


# Documentation and code hosts that legitimate tool descriptions link to.
# Starting values; Task 9 tunes them on the dev split only, then freezes them.
DEFAULT_URL_ALLOWLIST: tuple[str, ...] = (
    "github.com",
    "gitlab.com",
    "modelcontextprotocol.io",
    "json-schema.org",
    "schema.org",
    "w3.org",
    "ietf.org",
    "python.org",
    "pypi.org",
    "npmjs.com",
    "readthedocs.io",
    "mozilla.org",
    "wikipedia.org",
)

DEFAULT_CONFIG = ScanConfig(url_allowlist=DEFAULT_URL_ALLOWLIST)
