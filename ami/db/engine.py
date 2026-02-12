"""Async SQLAlchemy engine and session management."""

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ami.core.settings import DatabaseSettings


class _EngineHolder:
    """Lazy singleton for the async session factory."""

    factory: async_sessionmaker[AsyncSession] | None = None


_holder = _EngineHolder()


def _get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Lazily create the async session factory."""
    if _holder.factory is None:
        db = DatabaseSettings()
        engine = create_async_engine(
            db.async_url,
            pool_size=db.pool_size,
            max_overflow=db.max_overflow,
        )
        _holder.factory = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _holder.factory


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency that yields an async database session."""
    factory = _get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
