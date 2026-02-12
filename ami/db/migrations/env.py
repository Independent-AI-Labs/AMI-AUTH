"""Alembic environment configuration for async migrations."""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from ami.core.settings import DatabaseSettings
from ami.db.base import BaseEntity
from ami.db.models_keys import SigningKeyEntity
from ami.db.models_oauth import (
    AuthorizationCodeEntity,
    OAuthClientEntity,
    OAuthTokenEntity,
)
from ami.db.models_user import UserEntity

_registered = (
    SigningKeyEntity,
    OAuthClientEntity,
    AuthorizationCodeEntity,
    OAuthTokenEntity,
    UserEntity,
)

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = BaseEntity.metadata


def run_migrations_offline() -> None:
    """Run migrations in offline mode (SQL script generation)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Execute migrations with the given connection."""
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations in online mode with async engine."""
    db_settings = DatabaseSettings()
    engine = create_async_engine(db_settings.async_url)

    async with engine.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
