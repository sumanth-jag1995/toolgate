# Sub-project A: Mock Enterprise Systems + 3 MCP Servers — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `docker compose up` stack with a synthetic UK health-insurer API (FastAPI + Postgres, including the canary member) and three authenticated MCP servers exposing the 12 task-shaped tools over streamable HTTP.

**Architecture:** `mock-enterprise` is a FastAPI service over Postgres that validates Keycloak JWTs and enforces per-endpoint scopes. Three MCP servers (`core-read`, `core-write`, `comms`), built with the official MCP Python SDK's `FastMCP`, each validate inbound JWTs for their own audience and call the mock API with their own client-credentials token. Tools are task-shaped with strict schemas; no generic tools.

**Tech Stack:** Python 3.12, uv workspace, FastAPI, SQLAlchemy 2.0 (async) + asyncpg, pydantic / pydantic-settings, PyJWT[crypto], httpx, MCP Python SDK (`mcp`), Faker (`en_GB`), pytest + pytest-asyncio + testcontainers[postgres], ruff, pre-commit + gitleaks, Keycloak 26, Postgres 16, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-10-18-toolgate-design.md` (sections 2, 3 "Approver UX" excluded, 4 "Authentication and credentials", 6 "Canary", 8 "Secrets protection").

## Global Constraints

- Python `>=3.12`; one uv workspace at repo root; every package uses `src/` layout.
- MCP Python SDK `mcp>=1.12` (needs structured output / `outputSchema` and `TokenVerifier`); record the exact resolved version in `uv.lock`.
- All data synthetic. Faker locale `en_GB`, fixed seed `1234`.
- 12 tools exactly: core-read (7) `get_member_profile`, `get_policy_details`, `check_coverage`, `get_claim_status`, `list_member_claims`, `get_payment_history`, `get_correspondence_history`; core-write (3) `log_claim`, `add_claim_note`, `update_contact_preference`; comms (2) `send_member_message`, `schedule_callback`.
- Every tool input schema: strict JSON schema, enums where the domain is closed, `additionalProperties: false` at every object level.
- Every write tool takes `idempotency_key` (UUID string).
- `send_member_message` has no free-text recipient or body; messages go only to the contact on file.
- No token passthrough: MCP servers never forward the inbound token; they call the mock API with their own client-credentials token.
- `core-read` Keycloak client holds only `*:read` scopes.
- Canary member: `member_id` `M-900001`, membership number `TG-CANARY-7Q4X9`, unique email and DOB (values fixed in Task 2).
- Secrets never committed: `.env` and generated Keycloak realm are gitignored; committed realm template holds placeholders only; gitleaks runs in pre-commit.
- Ports: Postgres 5432, Keycloak 8080, mock API 8000, core-read 8101, core-write 8102, comms 8103.
- Money is integer pence (`amount_pence`) everywhere; never floats.

## Review Focus

1. **Seed re-run on an existing database** — running the seed twice must leave identical row counts (no duplicates, no crash). Test added in Task 2.
2. **Malformed or hostile IDs** (`"M-12"`, `"M-000001' OR 1=1"`, empty string) — rejected by schema as a tool error / HTTP 422, never a 500. Tests added in Tasks 3 and 7.
3. **Idempotency key reuse** — same key + same payload returns the original result; same key + different payload returns 409; two concurrent requests with one key create exactly one row. Tests added in Task 4.
4. **Wrong token** — expired token or wrong `aud` → 401; valid token missing a scope (read client calling a write endpoint) → 403. Tests added in Task 3 (API) and Task 6 (MCP verifier).
5. **Mock API slow or down** — an MCP tool returns an `isError` result with a clear message within the 5 s timeout, not a hang or unhandled exception. Test added in Task 6.

---

## File Structure

```
pyproject.toml                         # uv workspace root, ruff + pytest config
.pre-commit-config.yaml                # gitleaks + forbidden-files hook + ruff
.env.example                           # placeholder values only
.gitignore                             # + generated realm, tfstate, tfvars
scripts/check_forbidden_files.py       # pre-commit hook: refuse .env, *.pem, *.key, *.tfstate*, *.tfvars
scripts/gen_dev_env.py                 # .env.example → .env with random secrets; renders realm
scripts/smoke_a.py                     # end-to-end smoke over compose stack
tests/test_check_forbidden_files.py
tests/test_gen_dev_env.py
infra/docker-compose.yml
infra/keycloak/toolgate-realm.template.json
services/mock-enterprise/
  pyproject.toml, Dockerfile
  src/mock_enterprise/
    settings.py        # pydantic-settings
    db.py              # engine/session factory
    models.py          # SQLAlchemy tables
    enums.py           # closed domains (procedure codes, statuses, templates…)
    canary.py          # CANARY constants (consumed by sub-project D)
    seed.py            # deterministic seed, CLI entry
    auth.py            # JWT verification + require_scope dependency
    schemas.py         # API request/response pydantic models
    idempotency.py     # key/request-hash handling
    routes_read.py
    routes_write.py
    app.py             # create_app()
  tests/ conftest.py, test_seed.py, test_auth.py, test_read_routes.py, test_write_routes.py
services/mcp-servers/
  pyproject.toml, Dockerfile
  src/toolgate_mcp_servers/
    settings.py
    api_client.py      # client-credentials token cache + error mapping
    auth.py            # JwtTokenVerifier (mcp TokenVerifier)
    hardening.py       # harden_schemas(): additionalProperties false
    models.py          # tool output models
    app_factory.py     # build_server(name, port, register_fn)
    core_read.py, core_write.py, comms.py   # each: register(mcp, api) + __main__
  tests/ conftest.py, test_api_client.py, test_auth.py, test_hardening.py,
         test_core_read.py, test_core_write.py, test_comms.py, test_task_shapes.py
```

---

### Task 1: Workspace scaffold and secrets guardrails

**Files:**
- Create: `pyproject.toml`, `.pre-commit-config.yaml`, `.env.example`, `scripts/check_forbidden_files.py`, `tests/test_check_forbidden_files.py`, `services/mock-enterprise/pyproject.toml`, `services/mcp-servers/pyproject.toml`, empty `src/<pkg>/__init__.py` for both
- Modify: `.gitignore` (append)

**Interfaces:**
- Produces: `scripts/check_forbidden_files.py: find_forbidden(paths: list[str]) -> list[str]`; CLI `python scripts/check_forbidden_files.py <paths...>` exits 1 and prints offenders if any. Workspace members `mock-enterprise` (import `mock_enterprise`) and `toolgate-mcp-servers` (import `toolgate_mcp_servers`, depends on `mock-enterprise` as a **dev** dependency only).

- [ ] **Step 1: Write the failing test**

```python
from scripts.check_forbidden_files import find_forbidden


def test_flags_secret_files():
    paths = [
        ".env",
        "infra/a.pem",
        "x/id.key",
        "infra/terraform/terraform.tfstate",
        "infra/terraform/terraform.tfstate.backup",
        "prod.tfvars",
    ]
    assert find_forbidden(paths) == paths


def test_allows_examples_and_code():
    assert (
        find_forbidden(
            [
                ".env.example",
                "prod.tfvars.example",
                "src/keys.py",
                "infra/keycloak/toolgate-realm.template.json",
            ]
        )
        == []
    )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_check_forbidden_files.py -v`
Expected: FAIL (module not found).

- [ ] **Step 3: Implement**

Root `pyproject.toml`: `[tool.uv.workspace] members = ["services/*", "packages/*"]`; dev deps `pytest`, `pytest-asyncio` (`asyncio_mode = "auto"`), `ruff`, `pre-commit`; `pythonpath = ["."]` so `scripts` imports in tests. `find_forbidden` matches basenames by glob: `.env`, `*.pem`, `*.key`, `*.tfstate`, `*.tfstate.*`, `*.tfvars` (and not names ending `.example`). `.pre-commit-config.yaml`: `gitleaks/gitleaks` hook (`gitleaks`), a local hook running the script on staged files, `ruff` + `ruff-format`. `.gitignore` append: `infra/keycloak/generated/`, `*.tfstate*`, `.terraform/`, `*.tfvars`, `!*.tfvars.example`. `.env.example` keys: `POSTGRES_PASSWORD`, `KEYCLOAK_ADMIN_PASSWORD`, `CORE_READ_CLIENT_SECRET`, `CORE_WRITE_CLIENT_SECRET`, `COMMS_CLIENT_SECRET`, `DEV_TESTER_CLIENT_SECRET`, each set to `change-me`.

- [ ] **Step 4: Verify**

Run: `uv sync --all-packages && uv run pytest tests/test_check_forbidden_files.py -v && uv run pre-commit run --all-files`
Expected: 2 passed; all hooks pass.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "chore: uv workspace scaffold with secrets guardrails"
```

---

### Task 2: Data model, deterministic seed, canary member

**Files:**
- Create: `services/mock-enterprise/src/mock_enterprise/{settings,db,models,enums,canary,seed}.py`, `services/mock-enterprise/tests/{conftest,test_seed}.py`

**Interfaces:**
- Consumes: workspace from Task 1.
- Produces:
  - `enums.py`: `ProcedureCode` (`MRI_SCAN, CT_SCAN, PHYSIOTHERAPY, CONSULTATION_SPECIALIST, CATARACT_SURGERY, HIP_REPLACEMENT, KNEE_ARTHROSCOPY, MENTAL_HEALTH_THERAPY, DERMATOLOGY, BLOOD_TESTS`), `Product` (`CORE, PLUS, PREMIER`), `PolicyStatus` (`ACTIVE, LAPSED, CANCELLED`), `ClaimStatus` (`RECEIVED, IN_REVIEW, APPROVED, REJECTED, PAID`), `PaymentStatus` (`SCHEDULED, SENT, FAILED`), `ContactPreference` (`EMAIL, SMS, POST, PHONE`), `NoteType` (`CUSTOMER_CONTACT, DOCUMENT_RECEIVED, ESCALATION`), `MessageTemplate` (`CLAIM_STATUS_UPDATE, PAYMENT_CONFIRMATION, DOCUMENTS_REQUIRED, CALLBACK_CONFIRMATION, POLICY_RENEWAL_REMINDER`), `CallbackReason` (`CLAIM_QUERY, PAYMENT_QUERY, POLICY_QUERY, COMPLAINT`), `CallbackWindow` (`MORNING, AFTERNOON`). All `StrEnum`, values lowercase snake.
  - `models.py` tables: `members(member_id PK "M-NNNNNN", membership_number unique "TG-XXXXXXXX", first_name, last_name, dob, email, phone, address_line, postcode, contact_preference)`, `policies(policy_id PK "P-NNNNNN", member_id FK, product, status, start_date, renewal_date, excess_pence, annual_limit_pence)`, `coverage_rules(product, procedure_code, covered, requires_preauth, limit_pence; PK(product, procedure_code))`, `claims(claim_id PK "C-NNNNNN", policy_id FK, member_id FK, procedure_code, status, amount_pence, incident_date, submitted_at)`, `claim_notes(note_id PK, claim_id FK, note_type, body, author_client, created_at)`, `payments(payment_id PK "PAY-NNNNNN", claim_id FK, member_id FK, amount_pence, status, paid_at nullable)`, `correspondence(correspondence_id PK, member_id FK, channel, template, recipient, subject, sent_at)`, `callbacks(callback_id PK, member_id FK, reason, preferred_date, preferred_window, created_at)`, `idempotency_records(client_id, key, request_hash, response_json, status_code, created_at; PK(client_id, key))`.
  - `db.py`: `make_engine(url: str) -> AsyncEngine`, `make_sessionmaker(engine) -> async_sessionmaker[AsyncSession]`, `async def create_schema(engine) -> None`.
  - `canary.py`: `CANARY: Final[dict[str, str]]` = `member_id "M-900001"`, `membership_number "TG-CANARY-7Q4X9"`, `first_name "Ada"`, `last_name "Quillfeather"`, `email "ada.quillfeather.7q4x9@members.example"`, `dob "1960-02-29"`, `phone "+44 7700 900479"`, `postcode "SW1A 9ZZ"`; plus `CANARY_TOKENS: tuple[str, ...]` (membership_number, email, phone, the `"Quillfeather"` surname).
  - `seed.py`: `async def seed(session: AsyncSession, *, members: int = 500, rng_seed: int = 1234) -> SeedSummary` (dataclass of row counts per table); CLI `python -m mock_enterprise.seed --reset`. Seed truncates all tables before inserting (this is how re-runs stay idempotent). The canary member gets one ACTIVE `PREMIER` policy, two claims (one `IN_REVIEW`, one `PAID` with a `SENT` payment), and one correspondence row. Coverage rules: every `Product × ProcedureCode` pair present (30 rows), `PREMIER` covers all.
  - `tests/conftest.py`: session-scoped fixture `pg_url` (testcontainers `postgres:16-alpine`, asyncpg URL), fixture `session` (fresh schema + seed per module).

- [ ] **Step 1: Write the failing tests** (`test_seed.py`)

```python
async def test_seed_counts(session):
    s = await seed(session, members=50)
    assert s.members == 51  # 50 + canary
    assert s.coverage_rules == 30
    assert s.claims >= 51


async def test_seed_is_deterministic(session):
    a = await seed(session, members=20)
    rows_a = await dump_members(session)
    b = await seed(session, members=20)
    rows_b = await dump_members(session)
    assert a == b and rows_a == rows_b  # Review Focus 1: re-run, no duplicates


async def test_canary_present_and_complete(session):
    await seed(session, members=10)
    m = await session.get(Member, CANARY["member_id"])
    assert m.membership_number == "TG-CANARY-7Q4X9"
    assert m.email == CANARY["email"]
    claims = (
        await session.scalars(select(Claim).where(Claim.member_id == "M-900001"))
    ).all()
    assert {c.status for c in claims} == {ClaimStatus.IN_REVIEW, ClaimStatus.PAID}


async def test_no_synthetic_member_collides_with_canary_tokens(session):
    await seed(session, members=500)
    rows = await dump_members(session)
    non_canary = [r for r in rows if r["member_id"] != "M-900001"]
    assert not any(tok in str(r) for r in non_canary for tok in CANARY_TOKENS)
```

(`dump_members` is a test helper returning members ordered by `member_id` as dicts.)

- [ ] **Step 2: Run to verify failure**

Run: `uv run --package mock-enterprise pytest services/mock-enterprise/tests/test_seed.py -v`
Expected: FAIL (imports missing).

- [ ] **Step 3: Implement** the modules above. Use `Faker("en_GB")` seeded with `rng_seed` and a `random.Random(rng_seed)` for all choices, so output is independent of global state. Synthetic member IDs are `M-000001…`; the canary's `M-900001` is out of that range.

- [ ] **Step 4: Run tests**

Run: same as Step 2. Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add services/mock-enterprise && git commit -m "feat(mock-enterprise): data model, deterministic seed and canary member"
```

---

### Task 3: API auth and read endpoints

**Files:**
- Create: `services/mock-enterprise/src/mock_enterprise/{auth,schemas,routes_read,app}.py`, `services/mock-enterprise/tests/{test_auth,test_read_routes}.py`
- Modify: `services/mock-enterprise/tests/conftest.py` (add `rsa_key`, `make_token`, `client` fixtures)

**Interfaces:**
- Consumes: Task 2 models, `make_sessionmaker`.
- Produces:
  - `settings.py: Settings(database_url, jwt_issuer, jwks_url, jwt_audience="mock-enterprise")`.
  - `auth.py`: `class Principal(BaseModel): client_id: str; scopes: frozenset[str]`; `def get_principal(...) -> Principal` (FastAPI dependency); `def require_scope(scope: str) -> Callable` (dependency factory). Uses `jwt.PyJWKClient(jwks_url, cache_keys=True)`; checks `iss`, `aud`, `exp`; `client_id` from `azp`; scopes from space-separated `scope` claim. Missing/invalid → 401 with `WWW-Authenticate: Bearer`; missing scope → 403.
  - `app.py: create_app(settings: Settings, *, jwk_client: PyJWKClient | None = None, sessionmaker=None) -> FastAPI` (injection points for tests).
  - Scopes: `members:read`, `policies:read`, `claims:read`, `payments:read`, `comms:read`, `claims:write`, `members:write`, `comms:write`.
  - Read endpoints (all JSON; IDs validated by path regex `^M-\d{6}$`, `^P-\d{6}$`, `^C-\d{6}$` → 422 on mismatch; unknown → 404 `{"detail": "member not found"}` etc.):

| Method/path | Scope | Response model (`schemas.py`) |
|---|---|---|
| `GET /members/{member_id}` | members:read | `MemberOut` (all member fields + `policy_ids: list[str]`) |
| `GET /policies/{policy_id}` | policies:read | `PolicyOut` |
| `GET /coverage?policy_id=&procedure_code=` | policies:read | `CoverageOut(policy_id, procedure_code, covered, requires_preauth, limit_pence, policy_status)` |
| `GET /claims/{claim_id}` | claims:read | `ClaimOut` (+ `notes: list[NoteOut]`, `payments: list[PaymentOut]`) |
| `GET /members/{member_id}/claims?status=&limit=` | claims:read | `list[ClaimSummaryOut]`, `limit` 1–20 default 10, newest first |
| `GET /members/{member_id}/payments?limit=` | payments:read | `list[PaymentOut]` |
| `GET /members/{member_id}/correspondence?limit=` | comms:read | `list[CorrespondenceOut]` |

- [ ] **Step 1: Write the failing tests**

`test_auth.py` (Review Focus 4):
```python
async def test_missing_token_401(client):
    r = await client.get("/members/M-900001")
    assert r.status_code == 401
    assert r.headers["www-authenticate"].startswith("Bearer")


async def test_expired_token_401(client, make_token):
    r = await client.get(
        "/members/M-900001", headers=make_token(["members:read"], exp_delta=-60)
    )
    assert r.status_code == 401


async def test_wrong_audience_401(client, make_token):
    r = await client.get(
        "/members/M-900001", headers=make_token(["members:read"], aud="core-read")
    )
    assert r.status_code == 401


async def test_missing_scope_403(client, make_token):
    r = await client.get("/members/M-900001", headers=make_token(["claims:read"]))
    assert r.status_code == 403
```

`test_read_routes.py`:
```python
async def test_get_canary_member(client, read_headers):
    r = await client.get("/members/M-900001", headers=read_headers)
    assert r.status_code == 200 and r.json()["membership_number"] == "TG-CANARY-7Q4X9"


@pytest.mark.parametrize("bad", ["M-12", "M-000001' OR 1=1", "x"])
async def test_malformed_member_id_422(client, read_headers, bad):  # Review Focus 2
    r = await client.get(f"/members/{quote(bad)}", headers=read_headers)
    assert r.status_code == 422


async def test_unknown_member_404(client, read_headers):
    assert (
        await client.get("/members/M-999999", headers=read_headers)
    ).status_code == 404


async def test_coverage_premier_mri(client, read_headers, canary_policy_id):
    r = await client.get(
        "/coverage",
        params={"policy_id": canary_policy_id, "procedure_code": "mri_scan"},
        headers=read_headers,
    )
    assert r.json()["covered"] is True


async def test_list_claims_limit_and_order(client, read_headers):
    r = await client.get(
        "/members/M-900001/claims", params={"limit": 1}, headers=read_headers
    )
    assert len(r.json()) == 1


async def test_limit_out_of_range_422(client, read_headers):
    assert (
        await client.get(
            "/members/M-900001/claims", params={"limit": 21}, headers=read_headers
        )
    ).status_code == 422
```
(`read_headers` = token with all five `*:read` scopes; `canary_policy_id` fixture reads it from DB.)

- [ ] **Step 2: Run to verify failure**

Run: `uv run --package mock-enterprise pytest services/mock-enterprise/tests/test_auth.py services/mock-enterprise/tests/test_read_routes.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement** the modules. Test fixtures: generate an RSA key with `cryptography`, wrap it in a stub object exposing `get_signing_key_from_jwt(token)` and pass it as `jwk_client`; issue tokens with `jwt.encode(..., algorithm="RS256", headers={"kid": "test"})`. Client: `httpx.AsyncClient(transport=ASGITransport(app=create_app(...)), base_url="http://test")`.

- [ ] **Step 4: Run tests** — same command. Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add services/mock-enterprise && git commit -m "feat(mock-enterprise): JWT scope auth and read endpoints"
```

---

### Task 4: Write endpoints with idempotency

**Files:**
- Create: `services/mock-enterprise/src/mock_enterprise/{idempotency,routes_write}.py`, `services/mock-enterprise/tests/test_write_routes.py`
- Modify: `app.py` (include router), `schemas.py` (request/response models)

**Interfaces:**
- Consumes: Task 3 `require_scope`, `Principal`.
- Produces (all require header `Idempotency-Key: <uuid>`; missing/invalid → 422):

| Method/path | Scope | Body → Response |
|---|---|---|
| `POST /claims` | claims:write | `ClaimCreate(member_id, policy_id, procedure_code, incident_date, amount_pence 1..5_000_000)` → 201 `ClaimOut` (status `received`). 422 if policy not owned by member or not `active`; 422 if `incident_date` in future. |
| `POST /claims/{claim_id}/notes` | claims:write | `NoteCreate(note_type, body ≤1000 chars, non-empty)` → 201 `NoteOut` (`author_client` = principal.client_id) |
| `PUT /members/{member_id}/contact-preference` | members:write | `ContactPreferenceUpdate(preference)` → 200 `MemberOut` |
| `POST /members/{member_id}/messages` | comms:write | `MessageCreate(template, claim_id: str \| None)` → 201 `CorrespondenceOut`. Recipient and channel derived from member's `contact_preference` (`email`→email, `sms`/`phone`→phone, `post`→address+postcode); `subject` rendered from template. `claim_id` required for `claim_status_update`, `payment_confirmation`, `documents_required` and must belong to the member, else 422. |
| `POST /members/{member_id}/callbacks` | comms:write | `CallbackCreate(reason, preferred_date (today..+30d), preferred_window)` → 201 `CallbackOut` |

  - `idempotency.py`: `async def run_idempotent(session, *, client_id: str, key: UUID, request_body: dict, handler: Callable[[], Awaitable[tuple[int, dict]]]) -> tuple[int, dict]`. `request_hash` = sha256 of `json.dumps(body, sort_keys=True, separators=(",", ":"))` plus method+path. Same key + same hash → stored `(status_code, response_json)`; different hash → 409 `{"detail": "idempotency key reused with different payload"}`. Concurrency: insert the record row first (`INSERT … ON CONFLICT DO NOTHING`), then run the handler in the same transaction; the loser of a race re-reads and returns the stored response (or 409).

- [ ] **Step 1: Write the failing tests** (Review Focus 3)

```python
async def test_log_claim_201(client, write_headers, canary_policy_id):
    r = await post_claim(client, write_headers, key=uuid4(), policy_id=canary_policy_id)
    assert r.status_code == 201 and r.json()["status"] == "received"


async def test_same_key_same_payload_replays(client, write_headers, canary_policy_id):
    k = uuid4()
    a = await post_claim(client, write_headers, key=k, policy_id=canary_policy_id)
    b = await post_claim(client, write_headers, key=k, policy_id=canary_policy_id)
    assert b.status_code == 201 and a.json()["claim_id"] == b.json()["claim_id"]


async def test_same_key_different_payload_409(client, write_headers, canary_policy_id):
    k = uuid4()
    await post_claim(
        client, write_headers, key=k, policy_id=canary_policy_id, amount_pence=1000
    )
    r = await post_claim(
        client, write_headers, key=k, policy_id=canary_policy_id, amount_pence=2000
    )
    assert r.status_code == 409


async def test_concurrent_same_key_creates_one_row(
    client, write_headers, canary_policy_id, session
):
    k = uuid4()
    rs = await asyncio.gather(
        *[
            post_claim(client, write_headers, key=k, policy_id=canary_policy_id)
            for _ in range(5)
        ]
    )
    assert {r.json()["claim_id"] for r in rs} and len(
        {r.json()["claim_id"] for r in rs}
    ) == 1
    assert await count_claims_with_amount(session, DEFAULT_AMOUNT, "M-900001") == 1


async def test_missing_idempotency_key_422(client, write_headers, canary_policy_id): ...
async def test_read_scope_cannot_write_403(
    client, read_headers, canary_policy_id
):  # Review Focus 4
    r = await post_claim(client, read_headers, key=uuid4(), policy_id=canary_policy_id)
    assert r.status_code == 403


async def test_claim_policy_not_owned_422(
    client, write_headers, other_member_policy_id
): ...


@pytest.mark.parametrize(
    "pref,channel,recipient_field",
    [
        ("email", "email", "email"),
        ("sms", "sms", "phone"),
        ("post", "post", "postcode"),
    ],
)
async def test_message_goes_to_contact_on_file(
    client, write_headers, pref, channel, recipient_field
): ...
async def test_message_body_has_no_free_text_fields(client, write_headers):
    r = await client.post(
        "/members/M-900001/messages",
        headers={**write_headers, "Idempotency-Key": str(uuid4())},
        json={"template": "callback_confirmation", "recipient": "evil@x.test"},
    )
    assert r.status_code == 422  # extra fields forbidden (model_config extra="forbid")


async def test_claim_status_update_requires_member_claim(
    client, write_headers, other_member_claim_id
): ...
async def test_callback_date_out_of_window_422(client, write_headers): ...
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run --package mock-enterprise pytest services/mock-enterprise/tests/test_write_routes.py -v` — Expected: FAIL.

- [ ] **Step 3: Implement.** All request models use `model_config = ConfigDict(extra="forbid")`. New claim IDs: `C-` + six digits from a Postgres sequence starting at `800000` (above the seed range).

- [ ] **Step 4: Run all mock-enterprise tests** — `uv run --package mock-enterprise pytest services/mock-enterprise -v`. Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add services/mock-enterprise && git commit -m "feat(mock-enterprise): write endpoints with idempotency"
```

---

### Task 5: Keycloak realm, dev secrets and compose for the API

**Files:**
- Create: `infra/keycloak/toolgate-realm.template.json`, `scripts/gen_dev_env.py`, `tests/test_gen_dev_env.py`, `infra/docker-compose.yml`, `services/mock-enterprise/Dockerfile`
- Modify: `services/mock-enterprise/src/mock_enterprise/app.py` (add `__main__` / uvicorn entry reading `Settings` from env)

**Interfaces:**
- Produces:
  - Realm `toolgate`. Client scopes (with "include in token scope"): the 8 scopes from Task 3. Audience mapper on each `*:read`/`*:write` scope adding `aud=mock-enterprise`. Confidential clients, service accounts enabled, standard flow disabled, access-token lifespan 600 s:
    - `core-read` → default scopes: 5 `*:read`
    - `core-write` → `claims:write`, `members:write`
    - `comms` → `comms:write`
    - `dev-tester` → hardcoded audience mappers for `core-read`, `core-write`, `comms` (used by the smoke test to call the MCP servers; sub-project B replaces it with gateway clients)
  - Secrets in the template are `${CORE_READ_CLIENT_SECRET}` style placeholders.
  - `gen_dev_env.py`: `def generate_env(example: Path, out: Path, *, overwrite: bool = False) -> dict[str, str]` (replaces every `change-me` with `secrets.token_urlsafe(32)`; refuses to overwrite an existing `.env` unless `overwrite`); `def render_realm(template: Path, out: Path, env: dict[str, str]) -> None` (raises `ValueError` if any `${…}` remains). CLI writes `.env` and `infra/keycloak/generated/toolgate-realm.json`.
  - Compose services: `postgres` (16-alpine, healthcheck), `keycloak` (`quay.io/keycloak/keycloak:26.0`, `start-dev --import-realm`, mounts `generated/`, `KC_HOSTNAME=http://localhost:8080`, `KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true`), `mock-api` (port 8000, runs `python -m mock_enterprise.seed --reset` then uvicorn), all reading `../.env`.
  - **Issuer decision:** tokens carry `iss=http://localhost:8080/realms/toolgate` everywhere; containers fetch JWKS via `http://keycloak:8080/realms/toolgate/protocol/openid-connect/certs`. Every service's settings therefore have separate `jwt_issuer` and `jwks_url`.

- [ ] **Step 1: Write the failing tests**

```python
def test_generate_env_replaces_placeholders(tmp_path):
    ex = tmp_path / ".env.example"
    ex.write_text("A=change-me\nB=change-me\nC=fixed\n")
    env = generate_env(ex, tmp_path / ".env")
    assert (
        env["C"] == "fixed"
        and env["A"] != "change-me"
        and env["A"] != env["B"]
        and len(env["A"]) >= 32
    )


def test_generate_env_refuses_overwrite(tmp_path): ...  # raises FileExistsError


def test_render_realm_fails_on_unresolved(tmp_path):
    t = tmp_path / "t.json"
    t.write_text('{"secret": "${MISSING}"}')
    with pytest.raises(ValueError):
        render_realm(t, tmp_path / "o.json", {})


def test_committed_template_has_no_literal_secrets():
    data = json.loads(Path("infra/keycloak/toolgate-realm.template.json").read_text())
    secrets_ = [c["secret"] for c in data["clients"] if "secret" in c]
    assert secrets_ and all(s.startswith("${") and s.endswith("}") for s in secrets_)
```

- [ ] **Step 2: Run to verify failure** — `uv run pytest tests/test_gen_dev_env.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the script, template, Dockerfile (python:3.12-slim + uv, `uv sync --package mock-enterprise --frozen`), compose file.
- [ ] **Step 4: Verify tests and the live stack**

Run: `uv run pytest tests/test_gen_dev_env.py -v` → 4 passed. Then:
```bash
uv run python scripts/gen_dev_env.py
docker compose -f infra/docker-compose.yml up -d --build postgres keycloak mock-api
```
Fetch a `core-read` token (`curl -s -d grant_type=client_credentials -d client_id=core-read -d client_secret=$CORE_READ_CLIENT_SECRET http://localhost:8080/realms/toolgate/protocol/openid-connect/token`) and call `GET http://localhost:8000/members/M-900001` → 200 with `TG-CANARY-7Q4X9`. Same token on `POST /claims` → 403.

- [ ] **Step 5: Commit**

```bash
git add infra scripts tests services/mock-enterprise/Dockerfile services/mock-enterprise/src && git commit -m "feat(infra): keycloak realm, dev secret generation, compose for mock API"
```

---

### Task 6: MCP server foundation — API client, inbound auth, schema hardening

**Files:**
- Create: `services/mcp-servers/src/toolgate_mcp_servers/{settings,api_client,auth,hardening,app_factory}.py`, `services/mcp-servers/tests/{conftest,test_api_client,test_auth,test_hardening}.py`

**Interfaces:**
- Produces:
  - `settings.py: ServerSettings(mock_api_url, token_url, client_id, client_secret, jwt_issuer, jwks_url, mcp_audience, host="0.0.0.0", port, api_timeout_s=5.0)`.
  - `api_client.py`:
    - `class ApiError(Exception): status: int; detail: str`
    - `class TokenProvider(Protocol): async def token(self) -> str`
    - `class StaticTokenProvider(token: str)` (tests)
    - `class ApiClient` with `__init__(self, base_url: str, token_provider: TokenProvider, *, timeout_s: float = 5.0, transport: httpx.AsyncBaseTransport | None = None)`; `async get(path: str, params: dict | None = None) -> Any`; `async post(path: str, json: dict, idempotency_key: str) -> Any`; `async put(path: str, json: dict, idempotency_key: str) -> Any`. Non-2xx → `ApiError(status, detail)`; `httpx.TimeoutException` / `ConnectError` → `ApiError(503, "enterprise API unavailable")`.
    - `class ClientCredentialsTokenProvider(token_url, client_id, client_secret, *, transport=None)`: `async token() -> str`; caches until 30 s before `expires_in`; single-flight via `asyncio.Lock`.
  - `api_errors_to_tool_errors` — context manager/decorator converting `ApiError` into `mcp.server.fastmcp.exceptions.ToolError` with messages: 404 → `"<resource> not found"` (pass through API detail), 409 → `"idempotency key reused with different arguments"`, 422 → `"invalid request: <detail>"`, 403 → `"not permitted"`, 503/other → `"enterprise API unavailable, retry later"`. Never include tokens or URLs in messages.
  - `auth.py: class JwtTokenVerifier(TokenVerifier)` — `__init__(issuer, audience, jwks_url, *, jwk_client=None)`; `async verify_token(token: str) -> AccessToken | None` (None on bad signature, wrong `iss`/`aud`, expiry). `AccessToken.client_id` from `azp`, `scopes` from `scope` claim.
  - `hardening.py: def harden_schemas(mcp: FastMCP) -> None` — for every registered tool, recursively set `additionalProperties: false` on every object schema node in the input schema (including `$defs`). Implementation note: FastMCP stores tool input schemas on its tool manager (in recent SDKs `mcp._tool_manager._tools[name].parameters`); verify the attribute path against the installed SDK and keep the access isolated in this one function.
  - `app_factory.py: def build_server(name: str, settings: ServerSettings, register: Callable[[FastMCP, ApiClient], None], *, api_client: ApiClient | None = None, with_auth: bool = True) -> FastMCP` — constructs `FastMCP(name, host, port, token_verifier=JwtTokenVerifier(...), auth=AuthSettings(issuer_url=settings.jwt_issuer, resource_server_url=f"http://localhost:{port}", required_scopes=[]))` when `with_auth`, calls `register`, then `harden_schemas`. Tests use `with_auth=False` with the in-memory transport.

- [ ] **Step 1: Write the failing tests**

```python
# test_api_client.py
async def test_token_cached_until_near_expiry(): ...  # MockTransport counts token calls: 2 api calls → 1 token call
async def test_token_refreshed_when_near_expiry(): ...  # expires_in=20 → refetch on next call
async def test_404_maps_to_api_error(): ...
async def test_timeout_maps_to_503(): ...  # Review Focus 5: transport sleeps > timeout_s=0.1
async def test_post_sends_idempotency_header(): ...


# test_auth.py (Review Focus 4)
async def test_valid_token_accepted(verifier, make_token):
    at = await verifier.verify_token(make_token(aud="core-read", scopes=[]))
    assert at is not None and at.client_id == "dev-tester"


async def test_wrong_audience_rejected(verifier, make_token):
    assert await verifier.verify_token(make_token(aud="core-write")) is None


async def test_expired_rejected(verifier, make_token): ...
async def test_garbage_rejected(verifier):
    assert await verifier.verify_token("not-a-jwt") is None


# test_hardening.py
def test_harden_sets_additional_properties_false_recursively():
    mcp = FastMCP("t")

    @mcp.tool()
    def f(a: Nested) -> str: ...  # Nested is a pydantic model with a nested model field

    harden_schemas(mcp)
    schema = tool_input_schema(mcp, "f")
    assert all(
        node.get("additionalProperties") is False for node in iter_object_nodes(schema)
    )
```

- [ ] **Step 2: Run to verify failure** — `uv run --package toolgate-mcp-servers pytest services/mcp-servers/tests/test_api_client.py services/mcp-servers/tests/test_auth.py services/mcp-servers/tests/test_hardening.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Tests use `httpx.MockTransport`; timeout test uses an async handler that `await asyncio.sleep(1)`.
- [ ] **Step 4: Run tests** — same command. Expected: all pass.
- [ ] **Step 5: Commit**

```bash
git add services/mcp-servers && git commit -m "feat(mcp-servers): API client, JWT verifier, schema hardening"
```

---

### Task 7: core-read server (7 tools)

**Files:**
- Create: `services/mcp-servers/src/toolgate_mcp_servers/{models,core_read}.py`, `services/mcp-servers/tests/test_core_read.py`
- Modify: `services/mcp-servers/tests/conftest.py` — fixture `api_client` (ApiClient over `ASGITransport` to `mock_enterprise.create_app` with the testcontainers DB and a static token provider minted with all `*:read` and write scopes), fixtures `core_read_session`, `core_write_session`, `comms_session` (each `build_server(..., with_auth=False, api_client=api_client)` wrapped in `mcp.shared.memory.create_connected_server_and_client_session(server._mcp_server)`), `sessions` (dict of the three keyed `"core-read"`, `"core-write"`, `"comms"`), and data fixtures `canary_policy_id`, `canary_in_review_claim_id` read from the seeded DB.

**Interfaces:**
- Consumes: Task 6 `build_server`, `ApiClient`, `api_errors_to_tool_errors`; Task 3 endpoints.
- Produces: `core_read.register(mcp: FastMCP, api: ApiClient) -> None`; `python -m toolgate_mcp_servers.core_read` serves streamable HTTP on 8101, `mcp_audience="core-read"`.
- Tool contracts (inputs use `Annotated[..., Field(...)]`; ID patterns `^M-\d{6}$` / `^P-\d{6}$` / `^C-\d{6}$`; closed domains reuse `mock_enterprise`-equivalent `Literal`s defined in `models.py` — the MCP package does **not** import `mock_enterprise` at runtime). Each returns a pydantic model from `models.py` so `outputSchema` is generated. Annotations: `readOnlyHint=True, openWorldHint=False`. Descriptions: one or two plain sentences stating what the tool returns and when to use it; no instructions about other tools.

| Tool | Inputs | Returns |
|---|---|---|
| `get_member_profile` | `member_id` | `MemberProfile` (member_id, membership_number, name, dob, email, phone, postcode, contact_preference, policy_ids) |
| `get_policy_details` | `policy_id` | `PolicyDetails` |
| `check_coverage` | `policy_id`, `procedure_code` (enum of 10) | `CoverageResult` |
| `get_claim_status` | `claim_id` | `ClaimStatusResult` (status, amount_pence, dates, last 3 notes, payments) |
| `list_member_claims` | `member_id`, `status` (enum, optional), `limit` (1–20, default 10) | `ClaimList(claims: list[ClaimSummary])` |
| `get_payment_history` | `member_id`, `limit` (1–20, default 10) | `PaymentList` |
| `get_correspondence_history` | `member_id`, `limit` (1–20, default 10) | `CorrespondenceList` |

- [ ] **Step 1: Write the failing tests**

```python
async def test_lists_exactly_seven_tools(core_read_session):
    names = {t.name for t in (await core_read_session.list_tools()).tools}
    assert names == {
        "get_member_profile",
        "get_policy_details",
        "check_coverage",
        "get_claim_status",
        "list_member_claims",
        "get_payment_history",
        "get_correspondence_history",
    }


async def test_every_tool_is_strict_and_read_only(core_read_session):
    for t in (await core_read_session.list_tools()).tools:
        assert t.inputSchema["additionalProperties"] is False
        assert t.outputSchema is not None
        assert t.annotations.readOnlyHint is True


async def test_get_member_profile_canary(core_read_session):
    r = await core_read_session.call_tool(
        "get_member_profile", {"member_id": "M-900001"}
    )
    assert (
        not r.isError and r.structuredContent["membership_number"] == "TG-CANARY-7Q4X9"
    )


@pytest.mark.parametrize("bad", ["M-12", "M-000001' OR 1=1", ""])
async def test_bad_member_id_is_tool_error(core_read_session, bad):  # Review Focus 2
    r = await core_read_session.call_tool("get_member_profile", {"member_id": bad})
    assert r.isError


async def test_unknown_member_is_not_found(core_read_session):
    r = await core_read_session.call_tool(
        "get_member_profile", {"member_id": "M-999999"}
    )
    assert r.isError and "not found" in r.content[0].text


async def test_check_coverage_enum_enforced(core_read_session, canary_policy_id):
    r = await core_read_session.call_tool(
        "check_coverage",
        {"policy_id": canary_policy_id, "procedure_code": "brain_transplant"},
    )
    assert r.isError


async def test_list_member_claims_status_filter(core_read_session): ...
async def test_payment_and_correspondence_history_canary(core_read_session): ...
async def test_api_down_returns_tool_error(
    core_read_session_api_down,
): ...  # Review Focus 5 end-to-end
```

- [ ] **Step 2: Run to verify failure** — `uv run --package toolgate-mcp-servers pytest services/mcp-servers/tests/test_core_read.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `models.py` (output models + shared `Literal` enums + ID `Annotated` types) and `core_read.py`.
- [ ] **Step 4: Run tests** — same. Expected: all pass.
- [ ] **Step 5: Commit**

```bash
git add services/mcp-servers && git commit -m "feat(mcp-servers): core-read server with 7 tools"
```

---

### Task 8: core-write server (3 tools)

**Files:**
- Create: `services/mcp-servers/src/toolgate_mcp_servers/core_write.py`, `services/mcp-servers/tests/test_core_write.py`
- Modify: `models.py` (write result models)

**Interfaces:**
- Consumes: Task 6, Task 7 `models.py` types, Task 4 endpoints.
- Produces: `core_write.register(mcp, api)`; entry point on 8102, `mcp_audience="core-write"`. Annotations: `readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False`. Every tool has required `idempotency_key: Annotated[str, Field(json_schema_extra={"format": "uuid"}, pattern=UUID_RE)]`.

| Tool | Inputs | Returns |
|---|---|---|
| `log_claim` | `member_id`, `policy_id`, `procedure_code`, `incident_date` (date), `amount_pence` (int 1–5,000,000), `idempotency_key` | `ClaimCreated(claim_id, status)` |
| `add_claim_note` | `claim_id`, `note_type` (enum), `body` (1–1000 chars), `idempotency_key` | `NoteAdded(note_id, claim_id)` |
| `update_contact_preference` | `member_id`, `preference` (enum), `idempotency_key` | `ContactPreferenceUpdated(member_id, contact_preference)` |

- [ ] **Step 1: Write the failing tests**

```python
async def test_lists_exactly_three_tools_all_require_idempotency_key(core_write_session):
    tools = (await core_write_session.list_tools()).tools
    assert {t.name for t in tools} == {"log_claim", "add_claim_note", "update_contact_preference"}
    for t in tools:
        assert "idempotency_key" in t.inputSchema["required"]
        assert t.inputSchema["additionalProperties"] is False

async def test_log_claim_replay_returns_same_claim(core_write_session, canary_policy_id): ...
async def test_log_claim_key_reuse_different_args_is_tool_error(core_write_session, canary_policy_id):
    ...; assert r.isError and "idempotency key reused" in r.content[0].text
async def test_amount_must_be_integer_pence(core_write_session, canary_policy_id):
    r = await core_write_session.call_tool("log_claim", {..., "amount_pence": 12.5})
    assert r.isError
async def test_non_uuid_idempotency_key_rejected(core_write_session): ...
async def test_add_claim_note_body_too_long_rejected(core_write_session): ...
async def test_update_contact_preference_roundtrip(core_write_session, core_read_session): ...
```

- [ ] **Step 2: Run to verify failure** — `uv run --package toolgate-mcp-servers pytest services/mcp-servers/tests/test_core_write.py -v`.
- [ ] **Step 3: Implement** `core_write.py`.
- [ ] **Step 4: Run tests** — expected: all pass.
- [ ] **Step 5: Commit**

```bash
git add services/mcp-servers && git commit -m "feat(mcp-servers): core-write server with idempotent write tools"
```

---

### Task 9: comms server (2 tools)

**Files:**
- Create: `services/mcp-servers/src/toolgate_mcp_servers/comms.py`, `services/mcp-servers/tests/test_comms.py`

**Interfaces:**
- Consumes: Task 6, Task 7 types, Task 4 `/messages` and `/callbacks`.
- Produces: `comms.register(mcp, api)`; entry point on 8103, `mcp_audience="comms"`. Same write annotations as Task 8.

| Tool | Inputs | Returns |
|---|---|---|
| `send_member_message` | `member_id`, `template_id` (enum of 5 templates), `claim_id` (optional), `idempotency_key` | `MessageSent(correspondence_id, channel, sent_at)` — **recipient is not returned and is never an input** |
| `schedule_callback` | `member_id`, `reason` (enum), `preferred_date` (date), `preferred_window` (enum), `idempotency_key` | `CallbackScheduled(callback_id, preferred_date, preferred_window)` |

- [ ] **Step 1: Write the failing tests**

```python
async def test_send_member_message_schema_has_no_recipient_or_body(comms_session):
    t = next(
        t
        for t in (await comms_session.list_tools()).tools
        if t.name == "send_member_message"
    )
    props = set(t.inputSchema["properties"])
    assert props == {"member_id", "template_id", "claim_id", "idempotency_key"}
    assert t.inputSchema["additionalProperties"] is False


async def test_extra_recipient_argument_rejected(comms_session):
    r = await comms_session.call_tool(
        "send_member_message",
        {
            "member_id": "M-900001",
            "template_id": "callback_confirmation",
            "idempotency_key": str(uuid4()),
            "recipient": "evil@attacker.test",
        },
    )
    assert r.isError


async def test_claim_status_update_for_canary(
    comms_session, canary_in_review_claim_id
): ...
async def test_template_requiring_claim_without_claim_is_error(comms_session): ...
async def test_schedule_callback_past_date_is_error(comms_session): ...
```

Note on `test_extra_recipient_argument_rejected`: FastMCP's own argument model may silently drop unknown arguments. If so, enforce in `comms.py` by validating the raw arguments against the hardened schema before the call, or by configuring the tool's argument model with `extra="forbid"` — whichever the installed SDK supports — and apply the same mechanism to every tool through `app_factory.build_server` so all 12 tools reject extras. Add the equivalent extra-argument test to Tasks 7 and 8's test files when doing so.

- [ ] **Step 2: Run to verify failure** — `uv run --package toolgate-mcp-servers pytest services/mcp-servers/tests/test_comms.py -v`.
- [ ] **Step 3: Implement** `comms.py` (and the extra-argument enforcement in `app_factory.py` if needed).
- [ ] **Step 4: Run all MCP server tests** — `uv run --package toolgate-mcp-servers pytest services/mcp-servers -v`. Expected: all pass.
- [ ] **Step 5: Commit**

```bash
git add services/mcp-servers && git commit -m "feat(mcp-servers): comms server with contact-on-file messaging"
```

---

### Task 10: Task-shape check, full compose stack and smoke test

**Files:**
- Create: `services/mcp-servers/tests/test_task_shapes.py`, `services/mcp-servers/Dockerfile`, `scripts/smoke_a.py`
- Modify: `infra/docker-compose.yml` (add `core-read`, `core-write`, `comms`), `README.md` (a "Run sub-project A locally" section: `gen_dev_env.py`, `docker compose up`, `smoke_a.py`)

**Interfaces:**
- Consumes: Tasks 5, 7, 8, 9.
- Produces: `scripts/smoke_a.py` — obtains a `dev-tester` token, connects to each server with the SDK's streamable HTTP client (`mcp.client.streamable_http.streamablehttp_client`, `Authorization: Bearer …`), asserts tool counts 7/3/2, calls `get_member_profile(M-900001)`, `log_claim`, `send_member_message`; asserts an unauthenticated connection fails with 401. Exits non-zero on any failure.

- [ ] **Step 1: Write the failing task-shape test**

Three representative servicing tasks, scripted as tool-call sequences over in-memory sessions; each must succeed in ≤ 4 calls (spec §2 target):
```python
async def test_claim_status_update_task_in_three_calls(sessions):
    calls = CallCounter(sessions)
    claims = await calls(
        "core-read",
        "list_member_claims",
        {"member_id": "M-900001", "status": "in_review"},
    )
    cid = claims["claims"][0]["claim_id"]
    await calls("core-read", "get_claim_status", {"claim_id": cid})
    await calls(
        "comms",
        "send_member_message",
        {
            "member_id": "M-900001",
            "template_id": "claim_status_update",
            "claim_id": cid,
            "idempotency_key": str(uuid4()),
        },
    )
    assert calls.count <= 4


async def test_new_claim_task(
    sessions,
): ...  # get_member_profile (policy_ids) → check_coverage → log_claim → send_member_message(documents_required)
async def test_contact_change_task(
    sessions,
): ...  # get_member_profile → update_contact_preference → send_member_message
```

- [ ] **Step 2: Run to verify failure, then implement** the `CallCounter` helper in the test file; the test passes once Tasks 7–9 exist. Run: `uv run --package toolgate-mcp-servers pytest services/mcp-servers/tests/test_task_shapes.py -v`. Expected: 3 passed.
- [ ] **Step 3: Add MCP server Dockerfile and compose services** (one image, three services with different `command` and env; each depends on `mock-api` and `keycloak` healthy).
- [ ] **Step 4: Verify the stack end to end**

```bash
docker compose -f infra/docker-compose.yml up -d --build
uv run python scripts/smoke_a.py
```
Expected: smoke script prints each check and exits 0. Then `uv run pre-commit run --all-files` passes and `git status` shows no `.env` or generated realm staged.

- [ ] **Step 5: Commit**

```bash
git add services/mcp-servers scripts/smoke_a.py infra/docker-compose.yml README.md
git commit -m "feat: compose stack for MCP servers, task-shape tests and smoke script"
```

---

## Done when

- `uv run pytest` (root, both packages) is green.
- `docker compose up` + `scripts/smoke_a.py` passes: 12 tools across 3 authenticated servers, canary readable, writes idempotent, unauthenticated access refused.
- `pre-commit run --all-files` passes; no secrets or generated realm in git history (`gitleaks detect` clean).
