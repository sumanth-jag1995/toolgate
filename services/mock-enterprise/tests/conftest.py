import os

os.environ.setdefault("TESTCONTAINERS_RYUK_DISABLED", "true")

import pytest
import pytest_asyncio
from mock_enterprise.db import create_schema, make_sessionmaker
from mock_enterprise.models import Base
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool
from testcontainers.community.postgres import PostgresContainer


@pytest.fixture(scope="session")
def pg_url():
    with PostgresContainer("postgres:16-alpine", driver="asyncpg") as pg:
        yield pg.get_connection_url()


@pytest_asyncio.fixture
async def session(pg_url):
    """Fresh schema per test (order-independent); NullPool avoids cross-loop reuse."""
    engine = create_async_engine(pg_url, poolclass=NullPool)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await create_schema(engine)
    async with make_sessionmaker(engine)() as s:
        yield s
    await engine.dispose()
