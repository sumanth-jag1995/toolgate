# Build context: repo root (see infra/docker-compose.yml)
FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.13 /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=1 PATH="/app/.venv/bin:$PATH"
COPY pyproject.toml uv.lock ./
COPY packages/toolgate-pin ./packages/toolgate-pin
COPY packages/toolgate-gateway ./packages/toolgate-gateway
RUN uv sync --package toolgate-gateway --frozen --no-dev
RUN useradd --system --no-create-home --uid 10001 toolgate
USER toolgate
EXPOSE 8200
CMD ["toolgate-gateway", "serve"]
