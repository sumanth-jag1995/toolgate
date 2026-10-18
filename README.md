# toolgate
MCP tool plane for accessing various tool calls

## Run sub-project A locally

Sub-project A is a mock enterprise API plus three authenticated MCP servers
(`core-read` :8101, `core-write` :8102, `comms` :8103; 12 tools) behind Keycloak.
Requires Docker and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --all-packages
uv run python scripts/gen_dev_env.py          # writes .env and the Keycloak realm (local only, gitignored)
docker compose -f infra/docker-compose.yml up -d --build
uv run python scripts/smoke_a.py              # end-to-end check; exits non-zero on failure
```

MCP endpoints are `http://localhost:810{1,2,3}/mcp` (bound to 127.0.0.1) and need a
Keycloak bearer token with the matching audience (the `dev-tester` client has all three).
