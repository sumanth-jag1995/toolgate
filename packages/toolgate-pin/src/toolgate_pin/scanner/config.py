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
    # Tuned on the dev split only (Task 12), then frozen. The model scores
    # 3 of 15 dev benign tools at 0.97-0.996 (all above 0.5), so the cutoffs
    # sit above the highest benign dev score.
    classifier_high: float = 0.999
    classifier_grey: float = 0.998


# Documentation and code hosts that legitimate tool descriptions link to.
# FROZEN after Task 9 (dev-split tuning left this list unchanged).
# Entries match as dot-suffixes, so NEVER seed multi-tenant user-content
# suffixes (readthedocs.io, github.io, gitlab.io, netlify.app, vercel.app,
# pages.dev, herokuapp.com, ...): anyone can register a subdomain there.
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
    "mozilla.org",
    "wikipedia.org",
)

DEFAULT_CONFIG = ScanConfig(url_allowlist=DEFAULT_URL_ALLOWLIST)
