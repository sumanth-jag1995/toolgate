import jwt
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import async_sessionmaker

from mock_enterprise.db import make_engine, make_sessionmaker
from mock_enterprise.routes_read import router as read_router
from mock_enterprise.routes_write import router as write_router
from mock_enterprise.settings import Settings


def create_app(
    settings: Settings,
    *,
    jwk_client: jwt.PyJWKClient | None = None,
    sessionmaker: async_sessionmaker | None = None,
) -> FastAPI:
    app = FastAPI(title="Toolgate mock enterprise API")
    app.state.settings = settings
    app.state.jwk_client = jwk_client or jwt.PyJWKClient(
        settings.jwks_url, cache_keys=True
    )
    app.state.sessionmaker = sessionmaker or make_sessionmaker(
        make_engine(settings.database_url)
    )
    app.include_router(read_router)
    app.include_router(write_router)
    return app


def main() -> None:
    import uvicorn

    uvicorn.run(
        create_app(Settings()),  # type: ignore[call-arg]  # values come from env
        host="0.0.0.0",
        port=8000,
    )


if __name__ == "__main__":
    main()
