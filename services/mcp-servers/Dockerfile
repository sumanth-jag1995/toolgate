# Build context: repo root (see infra/docker-compose.yml)
FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.13 /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=1 PATH="/app/.venv/bin:$PATH"
COPY pyproject.toml uv.lock ./
COPY services/mcp-servers ./services/mcp-servers
RUN uv sync --package toolgate-mcp-servers --frozen --no-dev
EXPOSE 8101 8102 8103
CMD ["python", "-m", "toolgate_mcp_servers.core_read"]
