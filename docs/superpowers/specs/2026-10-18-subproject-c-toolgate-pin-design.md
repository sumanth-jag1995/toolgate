# Sub-project C — `toolgate-pin` Design

**Date:** 2026-10-18
**Status:** Draft for review
**Parent:** `docs/superpowers/specs/2026-10-18-toolgate-design.md` (umbrella). This document refines umbrella §3 (pin model) and §5 (detector), and moves the corpus (umbrella §6) into this sub-project. Where this document and the umbrella differ, this document wins for sub-project C.

Lines marked **(builder's call)** are left to the implementer. Lines marked **(Claude's call)** were decided while writing this design, not by Sumanth; he can overturn them while reviewing.

## 1. Intent

`toolgate-pin` is the open-source artifact of the Toolgate project. It treats MCP tool definitions as a supply chain: approve them, pin them by hash, and refuse anything that changes until a human re-approves it against a visible diff.

It is for a **platform engineer** who has never seen Toolgate. The bar is Sumanth's five-minute journey. Each step must work exactly like this:

| Minute | What the engineer does | What must happen |
|---|---|---|
| 0–1 | `uvx toolgate-pin demo` | No API keys, Docker or database. A bundled MCP server gets pinned. One tool description then changes to include a hidden instruction. The tool is quarantined, the diff shows the hidden characters made visible, and the command exits non-zero. |
| 1–2 | `toolgate-pin approve <server>` then `toolgate-pin check` | `approve` writes a lockfile with hashes, approver and timestamp. `check` fails their build pipeline whenever a tool changes. |
| 2–4 | About 10 lines of Python in their own gateway | A changed tool disappears from the agent's tool list instead of crashing anything. Every decision is emitted as a trace carrying the tool hash and the outcome. |
| 4–5 | `toolgate-pin bench` | Prints the detection and false-positive table on their own machine. It is the same table as the Toolgate README headline. |

The package also gives the Toolgate gateway (sub-project B) its pinning and scanning core, and gives the eval harness (sub-project D) its attack corpus.

## 2. Goals, non-goals, anti-goals

**Goals**
- The four journey steps above work exactly as described, from an installed wheel, on Windows, macOS and Linux.
- Canonical hashing that never false-alarms on semantically equal definitions.
- A lockfile that is readable, diff-friendly and committed to git: it is the audit evidence.
- A three-tier definition scanner (rules, then a pretrained classifier, then an LLM judge) and a rules-only output scanner.
- A corpus of 30 malicious and 50 benign definitions, plus a separate dev set, shipped as package data.
- `bench` reproduces the headline table.

**Non-goals**
- A Postgres pin store (Claude's call: deferred to sub-project B, which is its only user. C defines the `PinStore` protocol B will implement).
- A web UI, a long-running service, or gateway routing.
- Behavioural verification of tool implementations.
- Publishing to PyPI (that is sub-project F; C only has to produce a wheel that works through `uvx`).

**Anti-goals: things that count as failure even if the code technically works**
- Pins that false-alarm on key order, whitespace or Unicode normalization. Engineers switch those off.
- A demo that needs any setup, download, key or network access.
- Drift in the library path raising an exception that takes the gateway down. Drift must quarantine, never crash.
- The scanner approving anything on its own.
- Thresholds tuned on the reported test set.
- Merging "caught by pin drift" with "flagged by scanner" into one number.
- `bench` silently skipping a tier. It must print which tiers ran.
- Corpus files that trip gitleaks: no realistic-looking secrets, keys or tokens, even fake ones.

## 3. Constraints

- Lives at `packages/toolgate-pin/` in the existing uv workspace. Distribution name `toolgate-pin`, import `toolgate_pin`, console script `toolgate-pin`. MIT license (the repo's license).
- `requires-python >=3.11` (Claude's call: broader than the workspace's 3.12 so `uvx` works for more people; code must not use 3.12-only features).
- **Core dependencies:**
  - `mcp>=1.12,<2`, matching the workspace pin from sub-project A. It provides the client for `approve`/`check` and the bundled demo server.
  - `rfc8785` for JCS canonical JSON (Claude's call; the builder may hand-roll JCS instead if it passes the golden tests).
  - Nothing heavier.
- **Extras:**
  - `[classifier]`: `onnxruntime`, `tokenizers` and `huggingface-hub`, running the ONNX export of the classifier, with no torch (Claude's call: an extra cannot point at the PyTorch CPU index, and plain `torch` pulls multi-GB CUDA builds on Linux). The builder confirms the model repo ships ONNX weights at the pinned revision. If it doesn't, the fallback is `transformers` plus `torch`, with the CPU index URL documented in the README.
  - `[otel]`: `opentelemetry-api`.
  - The judge needs no extra: it talks to OpenRouter's OpenAI-compatible endpoint with `httpx`, which `mcp` already brings in.
- **CLI:** standard-library `argparse`, colour only when stdout is a TTY (Claude's call: no click/typer/rich, to keep `uvx` cold-start fast).
- Everything runs in the repo's uv `.venv`. Tests run via `uv run pytest` and are included in the root test paths.
- **Git hooks:** existing pre-commit hooks (gitleaks, ruff, forbidden-files) must pass on all corpus files.

## 4. What Sumanth decided

- The five-minute journey in §1, step for step, including that `demo` exits with an error code.
- The pin store is a **lockfile** first.
- `bench` prints the exact headline table. That means the 30 malicious and 50 benign definitions are built in this sub-project, not in D.
- C grows to about 13 hours and D shrinks by about the same; the 45-hour total is unchanged.
- If C runs over budget, the classifier tier is cut first. The headline table then shows rules + LLM judge, and the full corpus and the five-minute journey stay intact. The plan orders work so the classifier comes last.
- The tiers, canonicalization rules, honest-threshold rule and two-way rug-pull reporting from umbrella §3 and §5 still apply.

## 5. Design

### 5.1 Canonicalization and hashing (unchanged from umbrella §3)

- **Hashed fields:** `name`, `title`, `description`, `inputSchema`, `outputSchema` and `annotations`. Missing fields are omitted, not null. `_meta` is excluded.
- **Normalization:**
  - Unicode NFC (not NFKC).
  - Runs of `str.isspace` characters in string values collapse to one space, and leading/trailing whitespace is trimmed.
  - `Cf` characters are preserved.
  - Inside schemas, `required` arrays are sorted and `enum` order is preserved.
- **Serialization:** RFC 8785 JCS. The hash is `"sha256:" + hex`.
- **Golden tests:**
  - Key order, whitespace variants, NFC/NFD and `required` order must give equal hashes.
  - Every mutation class in the corpus must give a different hash.
- **Server identity:** `server_id` (user-chosen, default `serverInfo.name`) plus `serverInfo.name`. If `serverInfo.name` changes, the whole server is quarantined as `server_drift`. The transport target is stored only so the server can be reached again; it is **not** part of identity. A URL or stdio command that differs between a laptop and CI quarantines nothing (Claude's call).

### 5.2 Lockfile

- **Location:** default `toolgate.lock.json` in the current directory; `--lockfile` overrides it.
- **Formatting:** JSON, 2-space indent, sorted keys, trailing newline, so git diffs are clean.
- **Structure:**
  - `"version": 1` at the top.
  - Per server: transport target (URL, or stdio command as an argv list), header **templates** exactly as typed (for example `Authorization: Bearer ${TOOLGATE_TOKEN}`, stored unexpanded so `check` can authenticate in CI from its own environment), `serverInfo.name`, and a `tools` map (Claude's call).
  - Per tool: `hash`, the full canonical definition (so `check` can show a diff without the old server), `approved_by`, `approved_at` (UTC ISO-8601), a summary of the scan findings, and `override_reason` when an approval overrode a high-severity finding.
- **What the lockfile does not store:** expanded header values. They are never written to the lockfile, logs or traces. A header containing a literal value instead of `${ENV}` is refused at `approve` with a message to use an environment variable (Claude's call).
- **Approver identity:** `--as <name>`, defaulting to `git config user.name`. If neither is available, the command fails asking for `--as` (Claude's call).

### 5.3 CLI

| Command | Behaviour | Exit codes |
|---|---|---|
| `demo` | Runs the bundled server in-process (MCP in-memory transport, no ports). Pins it into a temporary lockfile. Mutates one tool's description by appending an instruction encoded in Unicode tag characters. Runs `check` logic and prints the quarantine with a diff. Invisible characters are rendered visibly, for example `⟦U+E0049 TAG LATIN CAPITAL LETTER I⟧`, and the decoded hidden text is shown too. Also prints the scanner findings and one line on what to do next. Fully offline. | 1, intentionally, mirroring what CI sees. `--no-fail` exits 0 for people scripting it. |
| `approve <target>` | Connects, lists tools, and compares against the lockfile. Shows a diff plus scan findings for new or changed tools. Asks for confirmation, or `--yes` skips it. Writes the lockfile. A `malicious` verdict from any tier that ran blocks approval unless `--override "<reason>"` is given, so `--classifier` and `--judge` can block too. `override_reason` records the reason and which tiers produced the verdict (Claude's call). Only rules run by default; `--classifier` and `--judge` opt into the other tiers. | 0 ok; 2 connection or usage error; 3 blocked by a finding |
| `check [<target>]` | With no target, checks every server in the lockfile using its stored target and header templates, and aggregates the results; this is the CI form. With a target, checks only that server. Connects and compares against the lockfile. Prints every quarantined tool (`drift`, `unpinned`, `removed`, `server_drift`) with its diff. Never writes. `--format text\|json`. | 0 clean; 1 any quarantine; 2 connection or usage error |
| `demo-server [--mutated]` | Runs the bundled demo server over stdio, so an engineer can try `approve --stdio -- toolgate-pin demo-server` and then watch `check --stdio -- toolgate-pin demo-server --mutated` fail (Claude's call). | — |
| `bench` | Runs the corpus through the scanner tiers available. Prints the headline table. `--format text\|md\|json` and `--tiers rules,classifier,judge`. | 0 |

**Targets**
- An `http(s)://` URL means streamable HTTP.
- `--stdio -- <command...>` means a stdio server.
- `--header "K: V"` is repeatable, and `${ENV}` in a value is expanded so tokens stay out of shell history.
- `--name` sets the `server_id`.
- `removed` means a pinned tool is gone. It is reported, and it fails `check`.

### 5.4 Library API: the ten-line integration

```python
from toolgate_pin import Pinner, LockfileStore

pinner = Pinner(LockfileStore("toolgate.lock.json"))


async def list_tools_for_agent(server_id, session):
    tools = (await session.list_tools()).tools
    result = pinner.verify(server_id, tools)  # never raises on drift
    for q in result.quarantined:
        alert(q.tool_name, q.reason, q.diff)  # caller's choice
    return result.allowed
```

- `Pinner.verify(server_id, tools, *, server_info=None)` accepts MCP `Tool` objects or dicts. When `server_info` (the `serverInfo` from the session's initialize result) is passed and its name differs from the pinned one, every tool is quarantined as `server_drift`. Without it, server drift is not checked (Claude's call). It returns a `VerifyResult` with:
  - `allowed`: the original objects, untouched.
  - `quarantined`: a list of `Quarantine(tool_name, reason, observed_hash, pinned_hash, diff, findings)`.
- `verify` is synchronous and in-memory against a loaded `PinSet`. The store is read once and reloaded via `pinner.reload()`.
  - Target: under 1 ms for 12 tools.
  - It raises only on programmer error (wrong types), never on drift or an unknown server. An unknown server means every tool is quarantined as `unpinned`.
- `PinStore` protocol: `load() -> PinSet`, `save(PinSet)`. Implementations are `LockfileStore` and `InMemoryStore`. Sub-project B adds a Postgres implementation.
- **Tracing:**
  - If `opentelemetry` is importable, `verify` emits one span, `toolgate.pin.verify` (attributes `toolgate.server_id` and counts), with one event per tool: `toolgate.tool.name`, `toolgate.tool.hash`, `toolgate.decision` ∈ {`allow`, `quarantine_drift`, `quarantine_unpinned`, `quarantine_removed`, `quarantine_server`}.
  - Scans get spans too. Without OTel installed, tracing is a no-op.
  - Tool definitions and argument values never go into attributes, only names, hashes and decisions.
- Other public functions: `canonicalize(tool) -> bytes`, `pin_hash(tool) -> str`, `diff(pinned, observed) -> str`, `scan_definition(tool, *, server_id, prior=None, inventory=(), tiers=("rules",)) -> ScanReport`, `scan_output(result, *, server_id, inventory=()) -> ScanReport`, where `inventory` is an iterable of `InventoryTool(server_id, name)` (Claude's call).

### 5.5 Scanner

**Finding:** `rule_id`, `severity` (`low`/`medium`/`high`), `field_path` (JSON Pointer into the definition), `evidence` (an excerpt with invisible characters escaped), `message`.

**ScanReport:** `findings`, `tiers_run`, `classifier_score` (optional), `judge` (optional `{verdict, reasons}`), and `verdict` ∈ {`benign`, `suspicious`, `malicious`}.

**Verdict rule** (Claude's call; thresholds frozen after dev-set tuning):
- `malicious` if any high finding, or a classifier score at or above the high threshold, or the judge says `malicious`.
- `suspicious` on any medium finding, a grey-band classifier score, or a judge `suspicious`.
- Otherwise `benign`.
- `bench` counts a definition as **detected** or **false positive** when its verdict is not `benign`. Approval is **blocked** only on `malicious`.

**Tier 1, rules:** scans every string in the definition, including nested schema descriptions, titles, defaults and enum values. Families, from umbrella §5:
- hidden Unicode: `Cf`, tag characters, bidi overrides, variation selectors, mixed-script names
- instruction patterns aimed at the model
- references to tools on **other servers** in the inventory (high), and ordering or redirect phrasing such as "before calling X" or "instead of X" (high). A plain mention of another tool on the **same** server is at most `low` and does not make a definition suspicious (Claude's call; this matches the benign hard negatives)
- exfiltration indicators: URLs or emails not on an allowlist, sensitive file paths, long base64/hex
- side-channel free-text parameters
- shadowing: an identical or near-identical name across servers in the inventory

Each rule has its own unit tests, with a positive and a negative case. When `prior` is given, findings that already existed in the prior definition are marked as such, so the diff highlights what is new.

**Tier 2, classifier:**
- ProtectAI `deberta-v3-base-prompt-injection-v2`, ONNX export, run with onnxruntime on CPU. The builder confirms the Apache-2.0 license and pins the model revision.
- Scores the description and each parameter description (truncated to the model limit) and takes the maximum.
- The model downloads on first use to the Hugging Face cache. `bench` warns once about the download.
- Not trained on the corpus.

**Tier 3, LLM judge:**
- Calls OpenRouter's chat completions with the key in `OPENROUTER_API_KEY` and the model in `TOOLGATE_JUDGE_MODEL`. The default is a free model that reliably returns JSON. The builder picks it and pins its exact ID.
- Input: old and new definition plus the diff, JSON-encoded, with invisible characters escaped as `\uXXXX`, inside delimited blocks that are declared to be data.
- Output: JSON `{verdict, reasons[], evidence_spans[]}`, validated. Invalid output gets one retry, then the judge is reported as unavailable for that item.
- Results are cached by `(definition hash, prompt version, model)` in a local cache directory (Claude's call: protects the ~1,000 requests/day quota across `bench` reruns). `--no-cache` bypasses it.
- An API failure marks the tier unavailable and `bench` prints that. It never counts as a pass.

**Output scanner:** rules only. It covers instruction patterns, hidden Unicode, URLs not on the allowlist and cross-tool references. Target: under 2 ms for a 4 KB output.

### 5.6 Corpus (package data)

- **Format:** JSON files under `toolgate_pin/corpus/{malicious,benign,dev}/` (Claude's call: JSON, so the core install needs no YAML dependency).
- **Malicious variants** carry: `id`, `family`, a short `technique` note, `server_id` (the variant's own server), `approved` (definition at approval), `mutated` (rug pulls only), `inventory` (a list of `{server_id, name, definition}` for the other tools present, used by the shadowing and cross-reference rules), optional `output_sample` (for output-injection cases) and `exfil` metadata (which canary fields the attack targets and which parameter carries them).
  - The `exfil` metadata exists so sub-project D's attacker server can load the same files.
- **Families and counts:** 10 description poisonings, 10 rug pulls, 5 shadowing, 5 hidden-Unicode/schema poisonings. At least 3 variants include an `output_sample` with injected instructions.
- **Realism:** attacks follow publicly documented techniques (tool poisoning and rug pulls as published in April 2025, the MCP Top 10, Unicode tag smuggling). Variety matters more than volume: no two variants in a family should differ only in wording.
- **Fake endpoints and data:** attacker endpoints use reserved domains (`*.example`, `*.invalid`). There are no realistic secrets anywhere.
- **Benign set (50):** adapted from public MCP servers whose licenses allow reuse. The builder verifies each license; MIT and Apache-2.0 only. `benign/SOURCES.md` records the source repo, file, license and what was changed.
  - It deliberately includes hard negatives: descriptions with imperative phrasing ("You must provide…"), URLs in documentation, mentions of other tools in the same server, and non-English text.
- **Dev set (~8 malicious, ~15 benign):** written separately, and the only set used for tuning thresholds and the judge prompt. Its files are marked `"split": "dev"`. `bench` never reports it unless given `--split dev`.

### 5.7 `bench` output: the headline table

```
toolgate-pin bench — tiers: rules, classifier, judge (model: <id>)   corpus v1
family                 n   rules  +classifier  +judge   caught by pin
description_poisoning  10  ..     ..           ..       n/a
rug_pull               10  ..     ..           ..       10/10
shadowing               5  ..     ..           ..       n/a
unicode_schema          5  ..     ..           ..       n/a
output_injection        k  ..     (rules only — runtime scanner)
benign (false pos.)    50  ..     ..           ..
```

- The columns are cumulative tiers.
- Tiers that didn't run show `—` and are listed at the top.
- For rug pulls, the scanner columns score the mutated definition against the approved one as `prior`.
- `--format md` produces the same table for the README.

## 6. Testing

- Golden canonicalization tests (§5.1).
- Unit tests per rule.
- `verify` behaviour for each quarantine reason, including the guarantee that it never raises.
- Lockfile round-trip and formatting stability: saving twice produces identical bytes.
- **CLI tests:**
  - `demo` exits 1 and its output contains a visible tag-character escape and the decoded hidden text.
  - `approve` then `check` against the bundled server over in-memory transport and over stdio.
  - Header values never appear in the lockfile or output.
- Corpus schema validation test over every file.
- `bench` rules-tier test asserting the table shape. Once thresholds are frozen it also asserts the exact rules-tier numbers, which catches silent regressions.
- Classifier and judge tests are marked and skipped when the extra or the key is missing.
- Performance tests: `verify` on 12 tools under 1 ms; `scan_output` on 4 KB under 2 ms (median over repeated runs).
- **Packaging check:** `uv build`, then run `uvx --from <built wheel> toolgate-pin demo` with networking unavailable to the command. It must exit 1 with the expected output. The builder chooses how to enforce "offline", for example by checking that no socket opens.

## 7. Left to the builder

- Module layout inside `toolgate_pin`.
- The exact regexes and the near-duplicate-name algorithm.
- The diff rendering style, as long as invisible characters are always visible.
- How `demo`'s bundled server is organized. Its tools should look like plausible insurer tools, consistent with sub-project A.
- The classifier grey band and thresholds, settled on the dev set only.
- The judge's default model and prompt wording.
- The cache directory location, which should follow platform conventions.

## 8. Effects on other sub-projects

- **B (gateway):** uses `Pinner` and `scan_output`, and implements the Postgres `PinStore`.
- **D (eval):** loads the corpus from the package instead of writing its own. Its estimate drops by about 5 hours.
- **F (publish):** publishes this package. Secret scanning of the built wheel (umbrella §8) applies to the corpus files too.
- **The umbrella spec** is not edited. This document records the deltas.
