# Sub-project G: IdP modes (Keycloak and Amazon Cognito) for the gateway, MCP servers and mock API

Parent: `2026-10-18-toolgate-design.md` section 4 (credential broker: Keycloak locally, Cognito on AWS). Prerequisite for F2 (AWS deployment): the READMEs list the four gaps below, and until they are closed a deployed stack rejects every call. No AWS spend: everything is tested with locally minted JWTs.

## Intent
The gateway, the three MCP servers and mock-api each verify bearer tokens with Keycloak assumptions. Cognito access tokens differ in four ways, so the same services cannot run on AWS as built. Make the identity provider a configuration choice (`keycloak` default, `cognito`) with identical security properties, and leave Keycloak behaviour byte-for-byte unchanged.

## The four gaps (verified against the code)
1. **No `aud`.** All three verifiers require `aud` and match it. A Cognito access token has no `aud`.
2. **No `azp`.** All three read `azp` as the caller's client id and reject tokens without it. Cognito access tokens carry `client_id` instead.
3. **Opaque client ids.** `policy/agents.yaml` is keyed by `servicing`, `claims-intake`, `fraud-triage`; the gateway uses the token's client id as that key (`allowlist.allowed(client_id, tool)`), and audit rows store it. A Cognito `client_id` is a generated string, so every agent would match nothing.
4. **Prefixed scopes.** mock-api checks bare scopes (`members:read`). Cognito issues custom scopes as `<resource-server-id>/<scope>`, for example `mock-enterprise/members:read`.

## Goals
- `IDP=keycloak|cognito` per service (env, default `keycloak`). In `keycloak` mode nothing changes, and a test pins that.
- In `cognito` mode each service verifies: RS256 signature against the pool's JWKS, `iss` equals the pool issuer, `exp` present and valid, `token_use == "access"` (id tokens rejected), and a required scope that stands in for the audience (below). Any failure means "not authenticated", as today.
- **Audience replacement.** The audience of a token is the resource-server scope `<audience>/invoke`: the gateway requires `toolgate-gateway/invoke`; each MCP server requires `<its name>/invoke` (`core-read`, `core-write`, `comms`, from its existing `mcp_audience`). A token missing it is rejected. This matches the Terraform Cognito module.
- **Client identity.** The caller identity is the `client_id` claim. The gateway maps it to an agent name through a setting `GATEWAY_AGENT_CLIENT_MAP` (JSON object, Cognito client id to agent name, built from the Terraform `app_client_ids` output). The mapped name is what the allowlist, audit log and traces use, so `agents.yaml` and the audit schema stay unchanged. A client id with no mapping is rejected (fail closed), never defaulted.
- **Scope normalisation for mock-api.** In `cognito` mode a setting `scope_prefix` (default `mock-enterprise/`) is stripped from scopes that start with exactly that prefix; scopes with any other prefix are kept unchanged and therefore never match a bare scope. `require_scope` then works as today.
- **Outbound tokens.** In `cognito` mode the client-credentials requests send an explicit `scope` parameter: the gateway asks for the single downstream's `<server>/invoke` scope per downstream where the structure allows it (otherwise one token with the three invoke scopes, documented as a weaker audience separation than `aud`); each MCP server asks for its own mock-enterprise scopes. Keycloak mode sends no `scope`, as today.
- Terraform: the ECS task definitions set `IDP=cognito`, the issuer/JWKS/token URLs from the cognito module outputs, and `GATEWAY_AGENT_CLIENT_MAP` assembled from `app_client_ids` (client ids are not secrets; client secrets stay in Secrets Manager). Static tests assert it.
- Docs: remove the four-gap limitation from `README.md` and `infra/terraform/README.md` and describe the modes. The remaining F2 caveat becomes "unverified against a real Cognito pool".

## Non-goals and anti-goals
- No real Cognito or AWS call, no new cloud resource, no spend.
- No change to Keycloak-mode behaviour, tokens, realm or the compose stack. A change that weakens a Keycloak check is a failure even if Cognito works.
- No acceptance of unsigned, `alg=none` or HS256 tokens; no silent fallback from one mode to the other; no "accept anything" development switch.
- Not user (human) login, OIDC flows, or AgentCore Identity.
- Cognito mode must not widen what an agent can do: authorisation still comes from `agents.yaml`; the IdP only authenticates.

## Constraints
- Python 3.12, PyJWT, existing MCP SDK `TokenVerifier` and FastAPI dependency patterns; uv workspace and `uv.lock` committed.
- Three services keep their current package boundaries. The claim-handling logic is security-critical and must exist once: a small shared workspace package `toolgate-idp` (no MCP or FastAPI dependency) holds the pure claim rules (`Identity`, mode settings, `normalize(claims, ...)`), and the three verifiers call it. The three Dockerfiles copy and install it. (My call; the builder confirms the Dockerfiles build and may instead keep a tested copy per service if packaging proves unreasonable, recording the ruling.)
- Error behaviour stays "None / 401" with no reason leaked to the caller; logs name the failure type only, never token contents.

## Test strategy (the heart of the work)
Tokens are minted in tests with a locally generated RSA key and a fake JWKS client (existing patterns). Parametrise every verifier over a Keycloak-shaped and a Cognito-shaped token. Required cases, per service where applicable:
- Keycloak mode: unchanged accept/reject matrix, plus Cognito-shaped tokens rejected.
- Cognito mode accept: valid access token with `client_id`, `token_use=access`, required scope, correct issuer.
- Cognito mode reject: wrong issuer; expired; missing `exp`; `token_use=id`; missing `token_use`; missing invoke scope; invoke scope of a different resource server (`core-write/invoke` presented to core-read); unmapped `client_id`; bad signature or `alg=none` or HS256 with the public key as secret; unknown `kid`; token with both `aud` and a wrong scope (aud is irrelevant in Cognito mode, scope decides); empty `client_id`.
- Scope normalisation: `mock-enterprise/members:read` becomes `members:read`; `other/members:read` stays and fails `require_scope`; a bare `members:read` in Cognito mode is accepted only if the Cognito token carries it (builder decides, records the choice and tests it); prefix must match at a segment boundary (no `mock-enterprise2/...` stripping).
- Agent mapping: allowlist and audit record the mapped agent name, never the raw Cognito client id as the allowlist key; unmapped fails closed; the mapping setting rejects malformed JSON at startup.
- Outbound: the token request body carries `scope` in Cognito mode only.
- An end-to-end in-process test: a Cognito-shaped agent token through the gateway app to a fake downstream, asserting the allowlist applies to the mapped agent.
- The live compose integration tests (Keycloak) still pass unchanged.

## Decisions and what is left to the builder
My calls (change any): env var names `IDP`, `GATEWAY_AGENT_CLIENT_MAP`, `SCOPE_PREFIX`; invoke scope name `invoke`; failing closed on unmapped clients with 401; whether the gateway mints one outbound token per downstream (preferred) or one token for all three. Left to the builder: the exact shape of the `toolgate-idp` API, startup validation messages, and how the MCP SDK's protected-resource metadata advertises the Cognito issuer (verify against `app.py`; no audience claim is advertised in Cognito mode).

## Done when
`uv run pytest -q` passes with the new matrix; Keycloak-mode tests are unchanged and green; the READMEs describe the two modes with the old four-gap limitation removed; the Terraform task definitions and their static tests carry the Cognito settings; and the final review confirms no Keycloak-mode check was weakened and that every reject case above has a test. Verification against a real Cognito pool remains an F2 step and is stated as such.
