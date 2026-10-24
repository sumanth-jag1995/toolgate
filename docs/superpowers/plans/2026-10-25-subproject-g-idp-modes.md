# Sub-project G: IdP modes (Keycloak and Amazon Cognito) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the identity provider a per-service configuration choice (`keycloak` default, `cognito`) so the gateway, the three MCP servers and mock-api accept Cognito access tokens with the same security properties, with Keycloak behaviour unchanged.

**Architecture:** A small shared workspace package `toolgate-idp` holds the security-critical rules once: mode-aware JWT decoding (algorithm, issuer, expiry, audience handling) and claim-to-identity conversion (`token_use`, invoke scope as the audience stand-in, client id to agent mapping, scope-prefix normalisation). Each of the three existing verifiers keeps its signature/JWKS handling and calls the package instead of its own decode and claim code. Outbound client-credentials requests gain an optional `scope` parameter (sent only in Cognito mode). Terraform and the READMEs are updated last.

**Tech Stack:** Python 3.12, PyJWT, pydantic-settings, MCP SDK `TokenVerifier`, FastAPI, uv workspace, pytest, Terraform (static tests only).

**Spec:** `docs/superpowers/specs/2026-10-25-subproject-g-idp-modes-design.md` (parent: `2026-10-18-toolgate-design.md` section 4).

## Global Constraints

- Everything runs in the uv `.venv` (`uv run ...`); `uv.lock` is regenerated and committed when workspace members or dependencies change.
- `IDP` accepts exactly `keycloak` or `cognito`, default `keycloak`; any other value fails at startup with the setting name and error type only (never the value).
- In `keycloak` mode behaviour is unchanged: RS256 only, `iss`/`exp`/`aud` required, `azp` is the caller id. Existing Keycloak tests stay unchanged and green.
- In `cognito` mode: RS256 only; `iss` and `exp` required; no `aud` check; `token_use` must equal `"access"`; the caller id is the `client_id` claim; the audience stand-in is the scope `<audience>/invoke` (gateway: `toolgate-gateway/invoke`; MCP server: `<mcp_audience>/invoke`); mock-api requires no invoke scope.
- Authentication failures return None / 401 with no reason to the caller; logs carry exception type names only, never tokens or claims.
- The gateway allowlist, audit rows and traces use the mapped agent name from `GATEWAY_AGENT_CLIENT_MAP` (JSON object, Cognito client id to agent name). An unmapped client id is rejected (401). Malformed JSON or an empty map in cognito mode fails at startup.
- Scope normalisation (mock-api, cognito mode): strip `SCOPE_PREFIX` (default `mock-enterprise/`) only when a scope starts with exactly that prefix (the prefix ends in `/`, so the match is at a segment boundary); every other scope is kept as is.
- Outbound `scope` form parameter is sent in cognito mode only (`TOKEN_SCOPE` for MCP servers, `GATEWAY_TOKEN_SCOPE` for the gateway); keycloak mode sends none.
- No real AWS or Cognito call; no secrets in code, tests or logs; test keys are generated at test time.
- Commit trailer: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` (or the implementer's own model). pre-commit (gitleaks, ruff, forbidden files) must pass; never `--no-verify`.

- Plan ruling (spec allowed either): the gateway keeps ONE outbound client-credentials token for all downstreams (its existing `ClientCredentialsAuth` is shared), so in cognito mode that token carries all three invoke scopes; audience separation between servers is therefore scope-based and weaker than per-token `aud`. Documented in the READMEs; splitting per downstream is out of scope.

## Review Focus

- `alg=none`, HS256 signed with the public key, or an RS256 token with a swapped header in cognito mode must be rejected, not just in keycloak mode.
- An ID token (`token_use=id`) or a token with no `token_use` must never authenticate in cognito mode.
- A token carrying another resource server's invoke scope (`core-write/invoke` presented to core-read) or a scope that merely contains the right text (`xcore-read/invoke`, `core-read/invoke2`) must be rejected.
- Scope prefix confusion: `mock-enterprise2/members:read`, `other/mock-enterprise/members:read` and a bare scope must not be turned into `members:read` incorrectly.
- Mode crossover: a Cognito-shaped token against a keycloak-mode service, and a Keycloak-shaped token (aud/azp, no `token_use`) against a cognito-mode service, must be rejected; an unmapped, empty or non-string `client_id` must be rejected.

---

### Task 1: The `toolgate-idp` package

**Files:**
- Create: `packages/toolgate-idp/pyproject.toml`, `packages/toolgate-idp/src/toolgate_idp/__init__.py`, `packages/toolgate-idp/src/toolgate_idp/claims.py`, `packages/toolgate-idp/tests/conftest.py`, `packages/toolgate-idp/tests/test_claims.py`
- Modify: root `pyproject.toml` (add `packages/toolgate-idp/tests` to pytest `testpaths`); `uv.lock`

**Interfaces:**
- Produces (all in `toolgate_idp`, re-exported from `__init__`):
  - `Mode = Literal["keycloak", "cognito"]`
  - `@dataclass(frozen=True) class IdpConfig`: `mode: Mode`; `issuer: str`; `audience: str` (keycloak: the `aud` value; cognito: the resource-server id, used for the invoke scope); `require_invoke_scope: bool = True` (cognito only); `scope_prefix: str = ""` (cognito only, stripped from scopes); `agent_client_map: Mapping[str, str] = field(default_factory=dict)` (cognito only; when non-empty, identities are mapped, unmapped rejected).
  - `@dataclass(frozen=True) class Identity`: `client_id: str` (the agent name when mapped), `scopes: frozenset[str]`, `subject: str | None`, `expires_at: int`.
  - `decode_token(token: str, key: Any, cfg: IdpConfig) -> dict[str, Any]`: `jwt.decode` with `algorithms=["RS256"]`, `issuer=cfg.issuer`; keycloak adds `audience=cfg.audience` and `options={"require": ["exp","iss","aud"]}`; cognito uses `options={"require": ["exp","iss"], "verify_aud": False}`. Raises PyJWT errors (callers already treat any exception as "not authenticated").
  - `identity_from_claims(claims: Mapping[str, Any], cfg: IdpConfig) -> Identity | None`: keycloak: `azp` non-empty string else None; scopes from `scope` split on whitespace. Cognito: `token_use == "access"`; `client_id` non-empty string; scopes from `scope`; if `require_invoke_scope`, `f"{cfg.audience}/invoke"` must be in the scopes (exact element match); apply `scope_prefix` normalisation; if `agent_client_map` is non-empty, `client_id` must be a key and the mapped name becomes `Identity.client_id`; `expires_at = int(claims["exp"])`; `subject` is `sub` if a string.
  - `parse_agent_client_map(raw: str) -> dict[str, str]`: JSON object of non-empty strings to non-empty strings; raises `ValueError` otherwise (message names the problem, never echoes values).
  - `validate_cognito_settings(cfg: IdpConfig) -> None`: raises `ValueError` when mode is cognito and `audience` is empty.
- Consumes: nothing.

- [ ] **Step 1: Failing tests** in `packages/toolgate-idp/tests/test_claims.py` using fixtures in `conftest.py` that generate a 2048-bit RSA key at test time and provide `make_token(claims, *, key=None, headers=None, alg="RS256")`, using PyJWT. Tests (names and the essential assertion):
  - `test_keycloak_accepts_aud_and_azp`; `test_keycloak_missing_azp_rejected`; `test_keycloak_wrong_audience_rejected`; `test_keycloak_missing_aud_rejected`; `test_keycloak_rejects_cognito_shaped_token` (no `aud`, no `azp`).
  - `test_cognito_accepts_valid_access_token` (claims `iss`, `exp`, `client_id`, `token_use="access"`, `scope="toolgate-gateway/invoke"`; returns the identity with the right scopes).
  - Cognito rejects (each asserts decode raises or identity is None): `test_cognito_id_token_rejected` (`token_use="id"`), `test_cognito_missing_token_use_rejected`, `test_cognito_missing_invoke_scope_rejected`, `test_cognito_other_resource_scope_rejected` (`core-write/invoke` for audience `core-read`), parametrised `test_cognito_lookalike_scopes_rejected` (`xcore-read/invoke`, `core-read/invoke2`, `core-read/invoke:admin`, `core-read`), `test_cognito_wrong_issuer_rejected`, `test_cognito_expired_rejected`, `test_cognito_missing_exp_rejected`, `test_cognito_alg_none_rejected`, `test_cognito_hs256_with_public_key_rejected`, `test_cognito_bad_signature_rejected`, parametrised `test_cognito_bad_client_id_rejected` (missing, empty, non-string), `test_cognito_keycloak_shaped_token_rejected` (aud/azp but no `token_use`).
  - `test_cognito_aud_claim_is_irrelevant` (wrong `aud` present, valid scope: accepted; no scope: rejected).
  - Scope normalisation: `test_scope_prefix_stripped` (`mock-enterprise/members:read` becomes `members:read`), parametrised `test_scope_prefix_not_over_stripped` (`mock-enterprise2/members:read`, `other/mock-enterprise/members:read`, `MOCK-ENTERPRISE/members:read` all stay unchanged), `test_bare_scope_kept_when_present` (documented choice: a bare scope in the token is kept as is), `test_require_invoke_scope_false_for_mock_api` (no invoke scope needed).
  - Mapping: `test_agent_mapping_applied`, `test_unmapped_client_rejected`, `test_empty_map_means_no_mapping` (client id passes through), `test_parse_agent_client_map_accepts_object`, parametrised `test_parse_agent_client_map_rejects` (not JSON, a list, non-string values, empty strings, empty object), `test_parse_error_does_not_echo_values`.
  - `test_validate_cognito_settings_requires_audience`.
- [ ] **Step 2: Run, expect FAIL** (`uv run pytest packages/toolgate-idp -q`, import error).
- [ ] **Step 3: Create the package** (`pyproject.toml` with hatchling, dependency `pyjwt[crypto]`, `src/toolgate_idp`), add to the workspace (members glob `packages/*` already covers it) and root `testpaths`; implement the interface above in `claims.py`; run `uv lock`.
- [ ] **Step 4: Run, expect PASS**; `uv run ruff check . && uv run ruff format --check .`.
- [ ] **Step 5: Commit** `feat(idp): shared claim rules for keycloak and cognito tokens`.

### Task 2: mock-api uses the shared rules

**Files:**
- Modify: `services/mock-enterprise/src/mock_enterprise/auth.py`, `services/mock-enterprise/src/mock_enterprise/settings.py`, `services/mock-enterprise/src/mock_enterprise/app.py` (only if settings wiring needs it), `services/mock-enterprise/pyproject.toml` (dependency + workspace source), `services/mock-enterprise/Dockerfile`, `services/mock-enterprise/tests/test_auth.py`, `services/mock-enterprise/tests/conftest.py`

**Interfaces:**
- Consumes: `toolgate_idp.IdpConfig`, `decode_token`, `identity_from_claims` (Task 1).
- Produces: `Settings.idp: Literal["keycloak","cognito"] = "keycloak"` (env `IDP`), `Settings.scope_prefix: str = "mock-enterprise/"` (env `SCOPE_PREFIX`); `get_principal` builds `IdpConfig` per request from settings (`require_invoke_scope=False`, `audience=settings.jwt_audience`); `Principal` is unchanged (`client_id`, `scopes`) so `require_scope` and the routes do not change.

- [ ] **Step 1: Failing tests** in `test_auth.py`: keep every existing test unchanged and passing (default keycloak). Add: `test_cognito_mode_accepts_prefixed_scopes` (app with `idp="cognito"`; token with `client_id`, `token_use="access"`, `scope="mock-enterprise/members:read"`; `GET` a members read route returns 200), `test_cognito_mode_other_prefix_scope_forbidden` (`other/members:read` gives 403), `test_cognito_mode_rejects_keycloak_shaped_token` (aud/azp only: 401), `test_cognito_mode_rejects_id_token` (401), `test_keycloak_mode_rejects_cognito_token` (401), `test_cognito_mode_write_route_needs_write_scope`.
- [ ] **Step 2: Run, expect FAIL. Step 3: Implement** the settings fields, the `IdpConfig` construction and the call into `toolgate_idp` in `get_principal` (keep the `jwt.PyJWTError` to 401 mapping; the 401 detail stays the fixed text). Add `toolgate-idp` to the service's dependencies with the workspace source, copy `packages/toolgate-idp` in the Dockerfile before `uv sync`, run `uv lock`.
- [ ] **Step 4: Run** `uv run pytest services/mock-enterprise -q` (all existing tests pass) and `docker build -f services/mock-enterprise/Dockerfile .` if Docker is available (report if skipped). **Step 5: Commit** `feat(mock-api): idp modes via toolgate-idp`.

### Task 3: MCP servers use the shared rules

**Files:**
- Modify: `services/mcp-servers/src/toolgate_mcp_servers/auth.py`, `settings.py`, `app_factory.py`, `api_client.py`, `services/mcp-servers/pyproject.toml`, `services/mcp-servers/Dockerfile`, `services/mcp-servers/tests/test_auth.py`, `services/mcp-servers/tests/test_api_client.py`, `services/mcp-servers/tests/conftest.py` as needed

**Interfaces:**
- Consumes: Task 1 package.
- Produces: `ServerSettings.idp: Literal["keycloak","cognito"] = "keycloak"` (env `IDP`); `ServerSettings.token_scope: str | None = None` (env `TOKEN_SCOPE`); `JwtTokenVerifier.__init__(self, issuer: str, audience: str, jwks_url: str, *, jwk_client: Any | None = None, mode: Mode = "keycloak")`; `ClientCredentialsTokenProvider.__init__(..., scope: str | None = None, transport=None)` sending `scope` in the form body only when set; `build_server` passes `mode=settings.idp` and `scope=settings.token_scope if settings.idp == "cognito" else None`.

- [ ] **Step 1: Failing tests:** existing `test_auth.py` tests unchanged and green; add cognito-mode tests for `JwtTokenVerifier` (valid token with `core-read/invoke` for audience `core-read` accepted, resulting `AccessToken.client_id` equals the Cognito client id; `core-write/invoke` rejected; id token rejected; keycloak-shaped token rejected; keycloak mode rejects a cognito-shaped token); `test_token_request_includes_scope_only_when_set` and `test_keycloak_provider_sends_no_scope` in `test_api_client.py` asserting the exact form body; `test_build_server_cognito_passes_mode_and_scope` (settings with `idp="cognito"`, `token_scope="mock-enterprise/members:read"`).
- [ ] **Step 2: FAIL. Step 3: Implement**; `_fetch` includes `"scope": self._scope` only when set; update dependency, Dockerfile and `uv lock`. **Step 4:** `uv run pytest services/mcp-servers -q`, plus a docker build check if available. **Step 5: Commit** `feat(mcp-servers): idp modes via toolgate-idp`.

### Task 4: Gateway uses the shared rules and maps clients to agents

**Files:**
- Modify: `packages/toolgate-gateway/src/toolgate_gateway/auth.py`, `settings.py`, `cli.py`, `packages/toolgate-gateway/pyproject.toml`, `packages/toolgate-gateway/Dockerfile`, `packages/toolgate-gateway/tests/test_auth.py`, `test_app.py`, `conftest.py` as needed
- Create: `packages/toolgate-gateway/tests/test_idp_modes.py`

**Interfaces:**
- Consumes: Task 1 package.
- Produces: `GatewaySettings.idp: Literal["keycloak","cognito"] = "keycloak"` (env `GATEWAY_IDP`); `GatewaySettings.agent_client_map: dict[str, str] = {}` (env `GATEWAY_AGENT_CLIENT_MAP`, JSON); `GatewaySettings.token_scope: str | None = None` (env `GATEWAY_TOKEN_SCOPE`); a pydantic validator: cognito mode requires a non-empty `agent_client_map` and `audience`; `AgentTokenVerifier.__init__(self, issuer, audience, jwks_url, *, jwk_client=None, refetch_interval_s=..., clock=..., mode: Mode = "keycloak", agent_client_map: Mapping[str, str] | None = None)` keeping the existing JWKS last-good/rate-limit logic untouched; `ClientCredentialsAuth.__init__(self, token_url, client_id, client_secret, *, scope: str | None = None, refresh_margin_s=30.0, transport=None)` sending `scope` only when set; `_serve` passes the new settings (scope only in cognito mode). `AccessToken.client_id` is the mapped agent name, so `core.list_tools`, `core.call_tool`, audit and traces are unchanged.

- [ ] **Step 1: Failing tests:** all existing tests stay unchanged and green. New `test_idp_modes.py`: `test_cognito_valid_token_maps_client_to_agent` (verify_token returns `client_id == "servicing"` for the mapped Cognito id); `test_cognito_unmapped_client_rejected`; `test_cognito_rejects_core_read_invoke_scope` (wrong resource scope); `test_cognito_rejects_id_token`; `test_keycloak_mode_rejects_cognito_token`; `test_cognito_jwks_last_good_still_works` (reuse the existing broken-JWKS pattern); `test_settings_cognito_requires_map` and `test_settings_reject_malformed_map_json` (startup error names the field only); `test_settings_default_is_keycloak`; `test_cc_auth_sends_scope_only_when_set` (exact form body, including that the secret never appears in an error); an in-process end-to-end `test_cognito_agent_allowlist_applies_to_mapped_agent`: build the gateway app with a fake downstream and cognito-mode verifier, call `tools/list` with a Cognito-shaped token for the client mapped to `fraud-triage` and assert only `core-read.*` tools are visible, and that a `core-write.log_claim` call is denied (reuse patterns from `test_app.py`).
- [ ] **Step 2: FAIL. Step 3: Implement** (decode through `decode_token`, claims through `identity_from_claims`; `AccessToken.resource` stays the audience); dependency, Dockerfile and `uv lock`. **Step 4:** `uv run pytest packages/toolgate-gateway -q` plus docker build check if available. **Step 5: Commit** `feat(gateway): idp modes and cognito client-to-agent mapping`.

### Task 5: Terraform wiring and documentation

**Files:**
- Modify: `infra/terraform/modules/ecs/main.tf`, `infra/terraform/modules/ecs/variables.tf`, `infra/terraform/modules/cognito/outputs.tf` (and `variables.tf` only if scope lists need exposing), `infra/terraform/main.tf`, `tests/test_terraform_static.py`, `tests/test_readmes.py`, `README.md`, `infra/terraform/README.md`

**Interfaces:**
- Consumes: Tasks 2-4 setting names. Produces: ECS task environment (plain `environment`, no secrets): gateway `GATEWAY_IDP=cognito`, `GATEWAY_AGENT_CLIENT_MAP` = `jsonencode({ for agent in ["servicing","claims-intake","fraud-triage"] : app_client_ids[agent] => agent })`, `GATEWAY_TOKEN_SCOPE="core-read/invoke core-write/invoke comms/invoke"`; each MCP server `IDP=cognito` and `TOKEN_SCOPE` equal to that server's mock-enterprise scopes (a cognito module output `server_token_scopes`, a map of server name to a space-separated string, derived from the same variable the Terraform clients use); mock-api `IDP=cognito` and `SCOPE_PREFIX=mock-enterprise/`.

- [ ] **Step 1: Failing tests** in `tests/test_terraform_static.py`: `test_gateway_task_sets_cognito_mode_and_client_map`; `test_agent_client_map_covers_exactly_the_three_agents_in_agents_yaml` (derive names from `policy/agents.yaml`); `test_every_service_task_sets_idp_cognito`; `test_server_token_scopes_match_cognito_clients` (the TOKEN_SCOPE of each server equals the scopes granted to its client); `test_no_client_secret_in_plain_environment` (extend the existing secrets test). In `tests/test_readmes.py`: `test_readmes_describe_both_idp_modes` and `test_readmes_no_longer_list_the_four_gaps_as_blocking` (the four-gap limitation text is gone; both modes and the remaining caveat "not yet verified against a real Cognito pool" appear).
- [ ] **Step 2: FAIL. Step 3: Implement** the Terraform wiring (`terraform fmt`, `validate` with `TERRAFORM_BIN` as in the existing tests) and update both READMEs: describe `IDP`, the invoke-scope audience stand-in, the client-to-agent map, the scope prefix, and that real-Cognito verification (including that Cognito returns the requested scopes for the client-credentials grant and accepts the form-encoded client secret) is an F2 step.
- [ ] **Step 4:** `uv run pytest tests/test_terraform_static.py tests/test_readmes.py -q`. **Step 5: Commit** `feat(infra): cognito idp settings for ecs tasks, docs`.

### Task 6: Whole-system verification

**Files:** none unless a defect is found.

- [ ] **Step 1:** `docker compose --env-file .env -f infra/docker-compose.yml up -d --build` (Keycloak default mode, all services rebuilt with the new package); run `uv run python scripts/smoke_a.py` and `uv run python scripts/smoke_b.py`; both must pass unchanged.
- [ ] **Step 2:** `uv run pytest -q` (full suite, integration tests included against the rebuilt stack). Report counts and any failure.
- [ ] **Step 3:** `gitleaks detect` over the history and a built-wheel artifact check are not affected; confirm the `toolgate-pin` manifest test still passes. Report results; fix anything found, otherwise no commit.
