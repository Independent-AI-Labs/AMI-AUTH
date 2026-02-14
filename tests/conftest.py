"""Shared test fixtures for AMI-AUTH."""

from collections.abc import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ami.core.app import create_app
from ami.db.base import BaseEntity
from ami.db.engine import get_session


@pytest.fixture(autouse=True)
def _set_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set environment variables for test settings."""
    monkeypatch.setenv("AUTH_ISSUER_URL", "http://localhost:8000")


@pytest.fixture
async def db_session() -> AsyncIterator[AsyncSession]:
    """Create an in-memory SQLite async session for tests."""
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)

    # SQLite does not support ARRAY -- render as VARCHAR
    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, _rec) -> None:
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(BaseEntity.metadata.create_all)

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session

    await engine.dispose()


@pytest.fixture
async def client(db_session: AsyncSession) -> AsyncIterator[AsyncClient]:
    """Create an httpx test client with DB session override."""
    app = create_app()

    async def _override_session() -> AsyncIterator[AsyncSession]:
        try:
            yield db_session
            await db_session.commit()
        except Exception:
            await db_session.rollback()
            raise

    app.dependency_overrides[get_session] = _override_session

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
