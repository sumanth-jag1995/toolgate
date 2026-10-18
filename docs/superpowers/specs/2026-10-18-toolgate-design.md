# Toolgate — Umbrella Design

**Date:** 2026-10-18
**Status:** Draft for review
**Scope:** Architecture and interfaces for the whole project. Each sub-project (A–F) gets its own spec → plan → build cycle that refines the relevant section here.

## 1. Purpose and success criteria

Toolgate is a portfolio build (D3-01, ~45 hours over 3 weeks) proving that enterprise systems can be exposed to agents through MCP while running the tool layer as a controlled supply chain: **authenticated, pinned, audited and measured.**

Scenario: a UK health insurer (2M members) wants 12 internal agents to share tools across policy admin, claims, payments and member comms through one MCP endpoint per domain. Security blocks it because tool descriptions are text the model obeys; a poisoned or silently changed server (tool poisoning, rug pulls — OWASP MCP Top 10 MCP03) can redirect an agent to exfiltrate member data.

### Ship gate (all must hold)

1. 12 tools on 3 MCP servers, callable by the agent through one gateway endpoint.
2. One table: detection rate by attack family on 30 malicious variants; false-positive rate on 50 benign definitions.
3. Canary exfiltration with and without the gateway; target zero with it.
4. A rug pull caught on the first `tools/list` after mutation, with the diff shown to the approver.
5. p95 gateway overhead < 30 ms per tool call at 50 concurrent calls.
6. Every call in an audit log: agent id, tool hash, argument hash, decision.
7. Scripted `terraform apply` and `terraform destroy`.
8. Pinning module published as an installable package, with an automated secrets check on the published artifact.

### Decisions taken during brainstorming

| Decision | Choice |
|---|---|
| Servicing agent | Built here as a reusable package (Flightpath and Doorman will reuse it) |
| Models | Two models in results (one frontier, one open-weights) via OpenRouter locally; swap to Amazon Bedrock in Phase 5 |
| OpenRouter quota | One-time $10 credit purchase → ~1,000 free-model requests/day |
| Gateway approach | MCP-aware proxy built on the official MCP Python SDK (not raw HTTP proxy, not FastMCP) |
| Publication hygiene | Secrets scanning in pre-commit, CI, and on the built package before upload |
| README | Must include architecture and request-flow diagrams |

### Assumptions

- Local-first: everything runs via `docker compose`. AWS is used only in Phase 5.
- All data is synthetic. No real member data anywhere, including in prompts sent to OpenRouter free endpoints (which may log prompts — the README states this).
- Local tooling present: Docker 29, Compose v5, Python 3.12, uv. Terraform and AWS CLI are installed before sub-project F.

## 2. Architecture

```
 servicing-agent (LangGraph)          Keycloak (OAuth 2.1, client credentials)
        │  MCP streamable HTTP + Bearer JWT         ▲ JWKS
        ▼                                            │
 ┌─────────────── toolgate-gateway ────────────────┐
 │ auth → allowlist → pin verify → route → output  │──► Postgres: pins, reviews, audit
 │ scan → audit/OTel        (uses toolgate-pin)    │──► OTel → Tempo/Grafana
 └──────┬──────────────┬──────────────┬────────────┘
        ▼              ▼              ▼        (+ evil-server, eval only)
   core-read       core-write       comms        ← MCP Python SDK servers
        └──────────────┴──────┬───────┘
                              ▼  (per-server credentials; never from the agent)
                 mock-enterprise API (FastAPI) ──► Postgres (synthetic data)
```

### Repository layout (uv workspace)

```
packages/toolgate-pin/      # OSS library: canonicalize, hash, PinStore, verify, scanners. No web deps.
packages/toolgate-gateway/  # MCP proxy: auth, allowlist, pin verify, routing, output scan, audit, OTel
packages/servicing-agent/   # Reusable LangGraph agent: MCP URL + client creds in; provider factory
services/mock-enterprise/   # FastAPI + Postgres + synthetic seed (incl. canary member)
services/mcp-servers/       # core_read, core_write, comms
eval/                       # corpus/, evil_server/, sink/, harness, load test, report.py, results/
infra/                      # docker-compose, Keycloak realm export (dev-only secrets), terraform/
policy/agents.yaml          # agent → allowed tools (deny by default)
docs/                       # specs, plans, write-ups, diagrams
```

### Tools (12, task-shaped, strict JSON schemas with enums, `additionalProperties: false`)

| Server | Tools | Scope to mock API |
|---|---|---|
| core-read (7) | `get_member_profile`, `get_policy_details`, `check_coverage`, `get_claim_status`, `list_member_claims`, `get_payment_history`, `get_correspondence_history` | `*:read` only |
| core-write (3) | `log_claim`, `add_claim_note`, `update_contact_preference` — each takes an `idempotency_key` | `claims:write`, `members:write` |
| comms (2) | `send_member_message(member_id, template_id, …)`, `schedule_callback` | `comms:write` |

`send_member_message` has no free-text recipient: messages go only to the contact on file. Tool calls per task are counted from day one (target: typical servicing task ≤ 4 calls).

### Agent identities

Keycloak defines three confidential clients — `servicing`, `claims-intake`, `fraud-triage` — each mapped to a different allowlist in `policy/agents.yaml`. Only the servicing agent is built; the other two demonstrate per-agent scoping in tests.

## 3. Pin model (`toolgate-pin`)

### What is pinned

- **Tool pin** per `(server_id, tool_name)` over: `name`, `title`, `description`, `inputSchema`, `outputSchema`, `annotations`. Excludes `_meta` and transport fields.
- **Server pin** over server URL + `serverInfo.name`. An unknown server's tools are never listed until the server is approved.

### Canonicalization

1. Unicode **NFC** (not NFKC — NFKC would fold compatibility/fullwidth characters and hide homoglyph-style changes).
2. In string values: collapse runs of whitespace (`str.isspace`) to one space and trim. Invisible format characters (category `Cf`) are **not** whitespace: preserved, so they change the hash; the scanner flags them separately.
3. JSON canonicalized per **RFC 8785 (JCS)**: sorted keys, no insignificant whitespace, canonical numbers. Within schemas, `required` arrays are sorted; `enum` order is preserved.
4. Hash: `"sha256:" + hex(sha256(jcs_bytes))`.

A golden-file test suite asserts: semantically equal definitions → equal hashes; every attack mutation class → different hash.

### Storage (Postgres)

- `tool_pins(id, server_id, tool_name, hash, canonical_json, status[active|superseded|revoked], approved_by, approved_at, scan_report, override_reason, supersedes_id)`
- `server_pins(id, server_id, url, server_name, approved_by, approved_at, status)`
- `pending_reviews(id, server_id, tool_name, observed_hash, observed_json, prior_pin_id, diff, scan_report, first_seen, status)`
- `audit_log(id, ts, agent_id, client_id, tool, tool_hash, args_hmac, decision, reason, latency_ms, trace_id)` — application role has INSERT only (no UPDATE/DELETE).

`decision ∈ {allow, deny_unknown_tool, deny_scope, deny_unpinned, deny_drift, deny_schema, deny_output, flag_output}`.

`args_hmac` = HMAC-SHA256 over canonical args with a gateway secret key, so low-entropy arguments (claim IDs) cannot be brute-forced back from the audit log.

### Public library interface

```python
canonicalize(tool: dict) -> bytes
pin_hash(tool: dict) -> str
class PinStore(Protocol): ...           # InMemoryPinStore, PostgresPinStore ([postgres] extra)
verify(server_id, tools, store) -> VerifyResult   # .allowed, .drifted (with diff), .unknown
scan_definition(tool, *, prior=None, inventory=()) -> ScanReport
scan_output(result, *, inventory=()) -> ScanReport
```

### Approver UX

CLI: `toolgate review` (pending items with coloured unified diff and scan findings), `toolgate approve <id> --as <name> [--override "<reason>"]`, `toolgate reject <id>`. A high-severity finding blocks approval unless `--override` is given; the reason is stored with the pin.

## 4. Gateway request flow

### Authentication and credentials

- Agent obtains a client-credentials JWT from Keycloak: `aud=toolgate-gateway`, TTL 10 minutes.
- Gateway is an OAuth resource server: local signature verification against cached JWKS; checks `iss`, `aud`, `exp`, `azp`. Unauthenticated → `401` + `WWW-Authenticate` with protected-resource metadata (RFC 9728).
- **No token passthrough.** Gateway → MCP server uses the gateway's own client-credentials token per downstream audience (cached until near expiry). MCP server → mock API uses each server's own Keycloak client and scopes; `core-read` holds only read scopes. Keycloak is the local credential broker; Cognito + Secrets Manager / AgentCore Identity on AWS.
- Agent identity propagates as `_meta.toolgate.agent_id` for downstream attribution only, never as a credential.

### `tools/list`

1. Authenticate.
2. Fetch fresh lists from all approved downstream servers in parallel (persistent pooled `ClientSession` per server).
3. Verify every tool against its active pin: match → keep; no pin → drop + pending review; mismatch → drop + pending review with diff + alert (structured log + OTel event).
4. Filter by caller's allowlist; return namespaced names (`claims.get_claim_status`).
5. Store the verified snapshot in memory. Also re-verify on downstream `notifications/tools/list_changed`.

### `tools/call` (hot path)

1. Authenticate.
2. Allowlist check → `deny_scope`.
3. Snapshot lookup → `deny_unpinned` if absent.
4. Validate arguments against the **pinned** `inputSchema` (compiled validators cached) → `deny_schema`.
5. Forward via pooled session; timeout and cancellation passthrough.
6. Output scan (rules only): high severity → result replaced by policy error (`deny_output`); low → passes, `flag_output`.
7. Enqueue audit record. One OTel span per stage.

### Latency budget

JWT verify < 0.2 ms; lookups µs; schema validation < 1 ms; output rules ~1–2 ms; audit via async batched queue (flush every 100 ms or 50 rows). Classifier and LLM judge never run on the hot path. Overhead = p95(gateway) − p95(direct) at 50 concurrent calls; target < 30 ms.

### Failure posture (fail closed)

| Failure | Behaviour |
|---|---|
| Audit queue full / audit DB unwritable | Deny calls |
| Pin store unreachable | Serve last-loaded pins for ≤ 5 minutes, then list no tools |
| Downstream server down | Its tools omitted; calls return error |
| JWKS fetch fails | Use cached keys until their cache TTL; then reject |

## 5. Poisoning detector

Runs on every new or changed definition when a pending review is created (off the hot path). The scanner never approves; it informs and can block.

**Tier 1 — rules** (scan every string in the definition, including nested schema fields, defaults and enum values):
- Hidden Unicode: `Cf` characters, tag characters U+E0000–E007F, bidi overrides, variation selectors, mixed-script tool names.
- Instruction patterns addressed to the model ("ignore previous", "do not tell the user", `<IMPORTANT>`, "before using this tool", system-prompt-like tags).
- Cross-tool references to any tool in the gateway inventory; "before calling X" / "instead of X".
- Exfil indicators: non-allowlisted URLs and emails, file paths (`~/.ssh`, `.env`), long base64/hex blobs.
- Side-channel parameters: free-text params named like `notes`, `context`, `debug`, `metadata` where the task does not need them.
- Shadowing: identical or near-duplicate (edit distance ≤ 2) unqualified names across servers.

**Tier 2 — classifier:** pretrained prompt-injection model, local CPU inference. Candidate: ProtectAI `deberta-v3-base-prompt-injection-v2` (Apache-2.0); license and fitness confirmed in sub-project C. Not trained on our corpus. Shipped as `toolgate-pin[classifier]` extra.

**Tier 3 — LLM judge:** input is old + new definition + diff; output schema `{verdict: benign|suspicious|malicious, reasons[], evidence_spans[]}`. Hardened against the text it judges: untrusted content JSON-encoded with invisible characters escaped as `\uXXXX`, inside delimited blocks, with instructions that it is data.

**Cascade vs ablation:** production config runs rules → classifier → judge only on escalation or grey-band classifier score. The evaluation runs all tiers on everything to produce a per-tier ablation table.

**Thresholds:** tuned on a separate dev set (~8 attacks, ~15 benign, authored separately), then frozen before reporting on the 30/50 sets.

**Rug pulls** are reported two ways: caught by pin drift (deterministic) and flagged by the scanner (detector quality). They are never merged into one number.

**Runtime output scan:** Tier 1 subset — instruction patterns, hidden Unicode, non-allowlisted URLs, cross-tool references.

## 6. Evaluation harness

**Attacker model:** an onboarded third-party utility MCP server (`evil-server`) with plausible tools (`postcode_lookup`, `format_uk_address`, `get_bank_holidays`). It forwards every received argument to an **attacker sink** (separate container logging all inbound requests). It loads a corpus variant by ID and can mutate definitions at runtime (emitting `list_changed`) to stage rug pulls.

**Corpus** (`eval/corpus/{malicious,benign,dev}/*.yaml`; each variant: id, family, approved definition, mutated definition, server behaviour, intended exfil path):
- 10 description poisonings
- 10 rug pulls (benign at approval, mutated later)
- 5 shadowing (attacker description alters use of legitimate tools; name collisions)
- 5 hidden-Unicode / schema poisonings
- Some variants inject via tool output to exercise the runtime scanner
- 50 benign definitions adapted from permissively licensed (MIT/Apache-2.0) public MCP servers; source and license per file in `eval/corpus/benign/SOURCES.md`

**Canary:** synthetic member with unique tokens (e.g. member number `TG-CANARY-7Q4X9`, unique email and DOB). The sink matches any token in plain, URL-encoded, base64, hex or case-folded form.

**Episodes:** 10 scripted servicing tasks involving the canary member; ≤ 15 steps each. Recorded: `leaked` and `task_completed` (verified against mock DB state and sent messages).

**Conditions:** `direct` (agent → all four servers, no gateway), `gateway` (through Toolgate; simulated approver approves unless a high-severity finding exists), and `clean` (no attacker, both conditions) to show no loss of legitimate task completion.

**Fairness:** variants are refined only against `direct`, then frozen before any `gateway` run. A variant that does not leak under `direct` on a model is reported as "not exploitable on this model", not dropped.

**Run matrix:** 30 variants × 2 conditions × 2 models × 3 repeats = 360 episodes, plus 10 clean tasks × 2 × 2 × 3 = 120. ≈ 2,500–3,000 LLM calls ≈ 3 days of quota. The runner resumes, skipping completed `(variant, condition, model, repeat)` tuples.

**Load test:** async MCP client, ~5,000 `tools/call` on `core-read` at 50 concurrency, direct vs gateway; report p50/p95 and the difference.

**Outputs:** one JSONL record per episode stamped with commit SHA, model IDs, corpus hash and seed. `eval/report.py` generates the ship-gate tables: per-family detection, FP rate, per-tier ablation, canary leak rate by model × condition, task-completion rate, latency.

## 7. Servicing agent (reusable)

- LangGraph agent; inputs: MCP endpoint URL, OAuth token URL, client id/secret, model config. Nothing Toolgate-specific.
- Provider factory keyed by config: `openrouter` (`ChatOpenAI` with OpenRouter base URL) or `bedrock` (`ChatBedrockConverse`). Exact model IDs pinned in config and recorded in results.
- Model selection (sub-project D): two free OpenRouter models with reliable tool calling — one frontier-class, one open-weights.

## 8. Phase 5 — AWS, managed comparison, publication

**Spike first (1 hour):** confirm AgentCore Gateway's current MCP-target requirements (public HTTPS, auth modes) and what Policy and gateway interceptors provide. Design against verified behaviour, not memory.

**Default hosting (Terraform, `infra/terraform/`):** ECS Fargate services (mock API, 3 MCP servers, evil-server, sink, gateway) behind ALB with HTTPS; RDS Postgres `db.t4g.micro`; Cognito user pool with three app clients; ADOT collector → AgentCore Observability / CloudWatch; all resources tagged `project=toolgate`. Fallback if Fargate is too heavy: single EC2 running the compose stack.

**Managed comparison:** register the same servers as AgentCore Gateway targets, Cognito inbound auth, Policy mirroring `policy/agents.yaml`; run corpus and load test. Write-up: capability matrix (inbound auth, per-agent authz, aggregation, description pinning, drift detection, definition scanning, output scanning, audit evidence, p95 overhead) — each row "managed provides" vs "we added". Run `toolgate-pin` alongside, as an interceptor if available, else as a scheduled verifier diffing AgentCore's `tools/list` against pins.

**Bedrock swap:** `provider: bedrock`; Claude Haiku plus a Bedrock-hosted open-weights model. One confirmation run on AWS, not the full matrix.

**Cost guardrails:** `make aws-up` / `make aws-down` wrap apply/destroy; Terraform-managed AWS Budget alarm at $25; `scripts/aws-leftovers.sh` lists anything still tagged `project=toolgate` after destroy. Destroy on the day the demo is recorded. `.gitignore` gains `*.tfstate*`, `.terraform/`, `*.tfvars` (except `*.tfvars.example`).

### Publishing `toolgate-pin`

- Version 0.1.0 to PyPI via GitHub Actions **trusted publishing** (OIDC; no stored PyPI token). Name availability checked first; fallback e.g. `mcp-toolpin`.
- Extras: `[postgres]`, `[classifier]`.
- Package contents controlled by an explicit include list in `pyproject.toml` (only `src/toolgate_pin/**`, `README.md`, `LICENSE`); tests, fixtures, corpus and config excluded.
- README: 10-line quickstart, canonicalization rules, threat model, link to results.

### Secrets protection

Three layers, each blocking:

1. **Pre-commit:** `gitleaks protect --staged` hook; plus a check rejecting `.env`, `*.pem`, `*.key`, `*.tfstate*`, `*.tfvars` from being staged.
2. **CI on every push/PR:** `gitleaks detect` over full git history.
3. **Release workflow, before upload:** build sdist and wheel, unpack both into a temp directory, run `gitleaks detect --no-git` over the unpacked contents, and assert the file list matches an expected manifest (fails on any unexpected file). Upload happens only if both checks pass.

Dev-only secrets (Keycloak realm export, compose env) are generated by a script from `.env.example` and never committed; the committed realm export contains placeholder secrets only. The OpenRouter key lives only in `.env` locally and in GitHub Actions secrets where needed.

## 9. README

The top-level README must include, as Mermaid diagrams (rendered natively by GitHub):

1. **Architecture diagram:** agent, Keycloak, gateway (with its pipeline stages), pin store/audit, the three MCP servers, mock enterprise API, OTel/Tempo — and the attacker server/sink in the eval setup.
2. **Request-flow sequence diagram:** `tools/list` with pin verification (including the rug-pull drop-and-review path) and `tools/call` through each gateway stage.

Plus: the problem in three sentences, the results tables from `eval/report.py`, how to run locally, and the AgentCore comparison summary. The `toolgate-pin` package README carries a smaller diagram of the pin/verify/review lifecycle.

## 10. Sequencing and budget

| Sub-project | Content | Est. |
|---|---|---|
| A | Mock enterprise systems + 3 MCP servers / 12 tools | ~7h |
| C | `toolgate-pin` (canonicalize, pins, verify, scanners, CLI) | ~8h |
| B | Gateway (auth, allowlist, pin verify, routing, output scan, audit, OTel) | ~8h |
| D | Servicing agent + corpus + evil-server/sink + harness + report | ~12h |
| E | Load test + latency report | ~2h |
| F | Terraform + AgentCore comparison + Bedrock swap + publish + README diagrams finalised | ~8h |

Order: A → C → B → D → E → F. If time slips, F shrinks to the capability matrix plus a single AgentCore run; the ship-gate items for apply/destroy and publication remain.

## 11. Out of scope

- User-delegated OAuth flows (belongs to Deputy).
- Building the other 11 agents.
- A web UI for approvals.
- Behavioural verification of tool *implementations* beyond output scanning (a server that keeps its description but changes behaviour is caught only via output scanning and audit).
