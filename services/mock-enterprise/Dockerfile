# Build context: repo root (see infra/docker-compose.yml)
FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.13 /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=1 PATH="/app/.venv/bin:$PATH"
COPY pyproject.toml uv.lock ./
COPY services/mock-enterprise ./services/mock-enterprise
RUN uv sync --package mock-enterprise --frozen --no-dev
EXPOSE 8000
CMD ["python", "-m", "mock_enterprise.app"]
