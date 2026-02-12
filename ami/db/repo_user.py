"""User repository for database CRUD operations."""

from datetime import UTC, datetime

import uuid_utils
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ami.crypto.password import verify_password
from ami.db.models_user import UserEntity


class UserUpsertData(BaseModel):
    """Parameters for creating or updating a user."""

    email: str
    user_id: str | None = None
    name: str | None = None
    image: str | None = None
    roles: list[str] | None = None
    groups: list[str] | None = None
    tenant_id: str | None = None


async def get_user_by_email(session: AsyncSession, email: str) -> UserEntity | None:
    """Look up a user by email address (case-insensitive)."""
    stmt = select(UserEntity).where(UserEntity.email == email.lower())
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def get_user_by_id(session: AsyncSession, user_id: str) -> UserEntity | None:
    """Look up a user by primary key."""
    stmt = select(UserEntity).where(UserEntity.id == user_id)
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def upsert_user(session: AsyncSession, data: UserUpsertData) -> UserEntity:
    """Create a user if none exists for this email, otherwise update."""
    existing = await get_user_by_email(session, data.email)
    if existing is not None:
        if data.name is not None:
            existing.name = data.name
        if data.image is not None:
            existing.image = data.image
        if data.roles is not None:
            existing.roles = data.roles
        if data.groups is not None:
            existing.groups = data.groups
        if data.tenant_id is not None:
            existing.tenant_id = data.tenant_id
        await session.flush()
        return existing

    user = UserEntity(
        id=data.user_id or str(uuid_utils.uuid7()),
        email=data.email.lower(),
        name=data.name,
        image=data.image,
        roles=data.roles or ["user"],
        groups=data.groups or [],
        tenant_id=data.tenant_id,
        login_count=0,
        is_active=True,
    )
    session.add(user)
    await session.flush()
    return user


async def verify_credentials(
    session: AsyncSession, email: str, password: str
) -> UserEntity | None:
    """Authenticate a user by email and password."""
    user = await get_user_by_email(session, email)
    if user is None:
        return None
    if not user.password_hash:
        return None
    if not verify_password(password, user.password_hash):
        return None
    user.login_count = (user.login_count or 0) + 1
    user.last_login = datetime.now(UTC)
    await session.flush()
    return user
