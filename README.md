# toolgate
MCP tool plane for accessing various tool calls

## Run sub-project A locally

Sub-project A is a mock enterprise API plus three authenticated MCP servers
(`core-read` :8101, `core-write` :8102, `comms` :8103; 12 tools) behind Keycloak.
Requires Docker and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --all-packages
uv run python scripts/gen_dev_env.py          # writes .env and the Keycloak realm (local only, gitignored)
docker compose --env-file .env -f infra/docker-compose.yml up -d --build
uv run python scripts/smoke_a.py              # end-to-end check; exits non-zero on failure
```

The `--env-file .env` flag is required: compose interpolates each container's own secrets from it
(no container receives the whole file).

MCP endpoints are `http://localhost:810{1,2,3}/mcp` (bound to 127.0.0.1) and need a
Keycloak bearer token with the matching audience (the `dev-tester` client has all three).

## Run sub-project B (the Toolgate gateway)

Sub-project B adds the gateway (`http://localhost:8200/mcp`): one authenticated MCP endpoint
in front of the three servers. Agents (Keycloak clients `servicing`, `claims-intake`,
`fraud-triage`, tokens with `aud=toolgate-gateway`) see only the namespaced tools
(`core-read.get_member_profile`, ...) that `policy/agents.yaml` allows them and that match the
pins in `policy/toolgate.lock.json`. Every `tools/call` is audited to `gateway.audit_log` in
Postgres (an arguments HMAC, never raw arguments) and traced to Grafana Tempo.

```bash
uv sync --all-packages --all-extras
uv run python scripts/gen_dev_env.py               # first time: writes .env and the Keycloak realm
uv run python scripts/gen_dev_env.py --add-missing # existing .env: appends only new keys, keeps the rest
docker compose --env-file .env -f infra/docker-compose.yml up -d --build
uv run python scripts/smoke_b.py                   # end-to-end check; exits non-zero on failure
```

If your `.env` predates sub-project B, run the `--add-missing` form and recreate Keycloak so it
re-imports the realm with the new clients:
`docker compose --env-file .env -f infra/docker-compose.yml up -d --force-recreate keycloak`.

**Pins and approvals.** The lockfile is committed. Run
`uv run python scripts/pin_servers.py` only when the MCP servers' tools change: it runs
`toolgate-pin approve` for each server with a `dev-tester` token held only in the child process
(the lockfile stores the header template `${TOOLGATE_DEV_TOKEN}`, never the token). Approving a
tool change means `toolgate-pin approve` plus a reviewed commit of `policy/toolgate.lock.json`;
the gateway hot-reloads the lockfile. Open drift reviews:
`docker compose --env-file .env -f infra/docker-compose.yml exec gateway toolgate-gateway reviews`.

**Traces.** Grafana is at http://localhost:3000 (anonymous, read-only). Open **Explore**, pick
the **Tempo** data source, and search for service name `toolgate-gateway`. Tempo's own API is at
http://localhost:3200.
