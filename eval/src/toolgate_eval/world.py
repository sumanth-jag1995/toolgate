"""The evaluation world: reseeded mock-enterprise data, tokens and snapshots.

Every episode starts from :meth:`World.reseed` and is judged by comparing two
:meth:`World.snapshot` results for the planted member. Snapshot sources:

* mock API with a ``core-read`` token: ``contact_preference`` (``GET
  /members/{id}``), ``claims`` (``GET /members/{id}/claims``), ``notes`` and
  ``payments`` (``GET /claims/{id}`` per claim), ``messages`` (``GET
  /members/{id}/correspondence``);
* Postgres with the admin DSN, in a read-only transaction: ``callbacks`` (no
  API exposes them).

Secrets come only from the repo-root ``.env``; they and the tokens are never
logged, printed or put in an exception message (names only).
"""

from __future__ import annotations

import asyncio
import re
import time
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any, ClassVar, Self
from urllib.parse import quote

import httpx
from mock_enterprise.canary import CANARY
from mock_enterprise.db import create_schema, make_engine, make_sessionmaker
from mock_enterprise.seed import seed
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

# 127.0.0.1 rather than localhost: on Windows "localhost" tries ::1 first and
# each new connection then stalls for about two seconds.
REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ENV = REPO_ROOT / ".env"
_SECRET_SUFFIX = "_CLIENT_SECRET"
_API_LIST_LIMIT = 20  # the mock API's maximum page size
_TOKEN_MARGIN_S = 30.0
_CLAIM_IN_SUBJECT = re.compile(r"\bC-\d{6}\b")


class WorldError(Exception):
    """A world operation failed. Messages name clients, paths or variables only."""


@dataclass(frozen=True)
class WorldSettings:
    token_url: str = (
        "http://127.0.0.1:8080/realms/toolgate/protocol/openid-connect/token"
    )
    api_url: str = "http://127.0.0.1:8000"
    admin_dsn: str = field(default="", repr=False)
    client_secrets: Mapping[str, str] = field(default_factory=dict, repr=False)
    member_id: str = CANARY["member_id"]
    seed_members: int = 50
    rng_seed: int = 1234

    @classmethod
    def from_env(cls, env_file: Path = DEFAULT_ENV, **overrides: Any) -> Self:
        """Read ``POSTGRES_PASSWORD`` and every ``<CLIENT>_CLIENT_SECRET``."""
        try:
            lines = Path(env_file).read_text(encoding="utf-8").splitlines()
        except OSError:
            raise WorldError(f"cannot read {env_file}") from None
        secrets: dict[str, str] = {}
        password = ""
        for line in lines:
            key, sep, value = line.partition("=")
            key = key.strip()
            if not sep or key.startswith("#"):
                continue
            if key == "POSTGRES_PASSWORD":
                password = value.strip()
            elif key.endswith(_SECRET_SUFFIX):
                client = key[: -len(_SECRET_SUFFIX)].lower().replace("_", "-")
                secrets[client] = value.strip()
        if not password:
            raise WorldError(f"POSTGRES_PASSWORD missing from {env_file}")
        dsn = (
            f"postgresql+asyncpg://postgres:{quote(password, safe='')}"
            "@127.0.0.1:5432/toolgate"
        )
        return cls(admin_dsn=dsn, client_secrets=secrets, **overrides)


# --- world state ---------------------------------------------------------------
# Plain, hashable rows. Surrogate ids of rows an episode creates (note,
# correspondence and callback ids) are excluded from equality, so checks find
# new rows by content diff. Contact details (recipients) are deliberately not
# captured.


@dataclass(frozen=True)
class Claim:
    claim_id: str
    policy_id: str
    procedure_code: str
    status: str
    amount_pence: int
    incident_date: str
    submitted_at: str


@dataclass(frozen=True)
class Note:
    claim_id: str
    note_type: str
    body: str
    author_client: str
    created_at: str
    note_id: int = field(default=0, compare=False)


@dataclass(frozen=True)
class Payment:
    payment_id: str
    claim_id: str
    amount_pence: int
    status: str
    paid_at: str | None


@dataclass(frozen=True)
class Message:
    channel: str
    template: str
    subject: str
    sent_at: str
    claim_id: str | None  # parsed from the subject, when it names a claim
    correspondence_id: int = field(default=0, compare=False)

    @staticmethod
    def claim_of(subject: str) -> str | None:
        found = _CLAIM_IN_SUBJECT.search(subject)
        return found.group(0) if found else None


@dataclass(frozen=True)
class Callback:
    reason: str
    preferred_date: str
    preferred_window: str
    created_at: str
    callback_id: int = field(default=0, compare=False)


@dataclass(frozen=True)
class WorldState:
    """What the planted member's records look like at one moment."""

    member_id: str
    contact_preference: str
    claims: tuple[Claim, ...]
    notes: tuple[Note, ...]
    payments: tuple[Payment, ...]
    messages: tuple[Message, ...]
    callbacks: tuple[Callback, ...]

    WRITABLE: ClassVar[tuple[str, ...]] = (
        "contact_preference",
        "claims",
        "notes",
        "messages",
        "callbacks",
    )

    def new_claims(self, before: WorldState) -> list[Claim]:
        """Claims present now whose claim id did not exist ``before``."""
        known = {c.claim_id for c in before.claims}
        return [c for c in self.claims if c.claim_id not in known]


def added[T](before: Iterable[T], after: Iterable[T]) -> list[T]:
    """Rows in ``after`` that ``before`` does not account for (multiset diff)."""
    remaining = Counter(before)
    out: list[T] = []
    for row in after:
        if remaining[row]:
            remaining[row] -= 1
        else:
            out.append(row)
    return out


def _sorted[T](rows: Iterable[T], key: Any) -> tuple[T, ...]:
    return tuple(sorted(rows, key=key))


# --- the world -------------------------------------------------------------------


class World:
    """Reseed, mint tokens for and snapshot the compose stack's mock enterprise."""

    def __init__(self, settings: WorldSettings) -> None:
        self.settings = settings
        self._http = httpx.AsyncClient(timeout=10)
        self._engine: AsyncEngine | None = None
        self._tokens: dict[str, tuple[str, float]] = {}
        self._token_lock = asyncio.Lock()

    def __repr__(self) -> str:
        return f"World(api_url={self.settings.api_url!r})"

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._http.aclose()
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None

    def _db(self) -> AsyncEngine:
        if not self.settings.admin_dsn:
            raise WorldError("no admin DSN configured")
        if self._engine is None:
            self._engine = make_engine(self.settings.admin_dsn)
        return self._engine

    async def reseed(self) -> None:
        """Restore the deterministic seed: every table truncated and refilled,
        identities and the API's claim-id sequence restarted."""
        engine = self._db()
        try:
            await create_schema(engine)  # no-op on the running stack
            async with make_sessionmaker(engine)() as session:
                await session.execute(text("ALTER SEQUENCE claim_id_seq RESTART"))
                await seed(
                    session,
                    members=self.settings.seed_members,
                    rng_seed=self.settings.rng_seed,
                )  # commits, together with the sequence restart
        except (SQLAlchemyError, OSError) as exc:
            raise WorldError(f"reseed failed ({type(exc).__name__})") from None

    async def token(self, client_id: str) -> str:
        """A client-credentials access token, cached until shortly before expiry."""
        async with self._token_lock:
            cached = self._tokens.get(client_id)
            if cached is not None and cached[1] > time.monotonic():
                return cached[0]
            secret = self.settings.client_secrets.get(client_id)
            if not secret:
                var = client_id.upper().replace("-", "_") + _SECRET_SUFFIX
                raise WorldError(f"{var} missing from .env")
            try:
                resp = await self._http.post(
                    self.settings.token_url,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": client_id,
                        "client_secret": secret,
                    },
                )
            except httpx.HTTPError as exc:
                raise WorldError(
                    f"{client_id} token request failed ({type(exc).__name__})"
                ) from None
            if resp.status_code != 200:
                raise WorldError(
                    f"{client_id} token request failed: HTTP {resp.status_code}"
                )
            body = resp.json()
            access = body["access_token"]
            ttl = float(body.get("expires_in", 60))
            self._tokens[client_id] = (
                access,
                time.monotonic() + max(ttl - _TOKEN_MARGIN_S, 0.0),
            )
            return access

    async def _get(self, token: str, path: str, **params: Any) -> Any:
        try:
            resp = await self._http.get(
                f"{self.settings.api_url}{path}",
                params=params or None,
                headers={"Authorization": f"Bearer {token}"},
            )
        except httpx.HTTPError as exc:
            raise WorldError(f"snapshot read failed ({type(exc).__name__})") from None
        if resp.status_code != 200:
            raise WorldError(f"snapshot read failed: HTTP {resp.status_code}")
        return resp.json()

    def _full_page(self, rows: Sequence[Any], what: str) -> Sequence[Any]:
        if len(rows) >= _API_LIST_LIMIT:
            # A full page may hide rows; a wrong verdict is worse than an error.
            raise WorldError(f"snapshot of {what} may be truncated")
        return rows

    async def snapshot(self) -> WorldState:
        member_id = self.settings.member_id
        token = await self.token("core-read")
        member, claim_rows, corr_rows, callbacks = await asyncio.gather(
            self._get(token, f"/members/{member_id}"),
            self._get(token, f"/members/{member_id}/claims", limit=_API_LIST_LIMIT),
            self._get(
                token, f"/members/{member_id}/correspondence", limit=_API_LIST_LIMIT
            ),
            self._callbacks(member_id),
        )
        self._full_page(claim_rows, "claims")
        self._full_page(corr_rows, "correspondence")
        details = await asyncio.gather(
            *(self._get(token, f"/claims/{c['claim_id']}") for c in claim_rows)
        )
        claims = [
            Claim(
                d["claim_id"],
                d["policy_id"],
                d["procedure_code"],
                d["status"],
                d["amount_pence"],
                d["incident_date"],
                d["submitted_at"],
            )
            for d in details
        ]
        notes = [
            Note(
                n["claim_id"],
                n["note_type"],
                n["body"],
                n["author_client"],
                n["created_at"],
                n["note_id"],
            )
            for d in details
            for n in d["notes"]
        ]
        payments = [
            Payment(
                p["payment_id"],
                p["claim_id"],
                p["amount_pence"],
                p["status"],
                p["paid_at"],
            )
            for d in details
            for p in d["payments"]
        ]
        messages = [
            Message(
                m["channel"],
                m["template"],
                m["subject"],
                m["sent_at"],
                Message.claim_of(m["subject"]),
                m["correspondence_id"],
            )
            for m in corr_rows
        ]
        return WorldState(
            member_id=member_id,
            contact_preference=member["contact_preference"],
            claims=_sorted(claims, key=lambda c: c.claim_id),
            notes=_sorted(notes, key=lambda n: (n.claim_id, n.created_at, n.body)),
            payments=_sorted(payments, key=lambda p: p.payment_id),
            messages=_sorted(
                messages, key=lambda m: (m.sent_at, m.template, m.subject)
            ),
            callbacks=callbacks,
        )

    async def _callbacks(self, member_id: str) -> tuple[Callback, ...]:
        try:
            async with self._db().connect() as conn:
                await conn.execute(text("SET TRANSACTION READ ONLY"))
                rows = (
                    await conn.execute(
                        text(
                            "SELECT callback_id, reason, preferred_date,"
                            " preferred_window, created_at FROM callbacks"
                            " WHERE member_id = :m ORDER BY created_at, callback_id"
                        ),
                        {"m": member_id},
                    )
                ).all()
                await conn.rollback()
        except (SQLAlchemyError, OSError) as exc:
            raise WorldError(f"callback read failed ({type(exc).__name__})") from None
        return tuple(
            Callback(
                r.reason,
                r.preferred_date.isoformat(),
                r.preferred_window,
                r.created_at.isoformat(),
                r.callback_id,
            )
            for r in rows
        )
