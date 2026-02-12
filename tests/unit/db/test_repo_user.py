"""Tests for user repository operations."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from ami.crypto.password import hash_password
from ami.db.models_user import UserEntity
from ami.db.repo_user import (
    UserUpsertData,
    get_user_by_email,
    get_user_by_id,
    upsert_user,
    verify_credentials,
)


async def _seed_user(
    session: AsyncSession,
    *,
    user_id: str = "test-id-001",
    email: str = "alice@example.com",
    password: str | None = "secret123",
) -> UserEntity:
    """Insert a test user directly into the session."""
    user = UserEntity(
        id=user_id,
        email=email,
        name="Alice",
        password_hash=hash_password(password) if password else None,
        roles=["user"],
        groups=[],
        login_count=0,
        is_active=True,
    )
    session.add(user)
    await session.flush()
    return user


class TestGetUserByEmail:
    """Tests for get_user_by_email."""

    @pytest.mark.asyncio
    async def test_returns_user_when_found(self, db_session: AsyncSession) -> None:
        await _seed_user(db_session)
        result = await get_user_by_email(db_session, "alice@example.com")
        assert result is not None
        assert result.email == "alice@example.com"

    @pytest.mark.asyncio
    async def test_case_insensitive_lookup(self, db_session: AsyncSession) -> None:
        await _seed_user(db_session)
        result = await get_user_by_email(db_session, "ALICE@EXAMPLE.COM")
        assert result is not None

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self, db_session: AsyncSession) -> None:
        result = await get_user_by_email(db_session, "nobody@example.com")
        assert result is None


class TestGetUserById:
    """Tests for get_user_by_id."""

    @pytest.mark.asyncio
    async def test_returns_user_when_found(self, db_session: AsyncSession) -> None:
        await _seed_user(db_session, user_id="uid-42")
        result = await get_user_by_id(db_session, "uid-42")
        assert result is not None
        assert result.id == "uid-42"

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self, db_session: AsyncSession) -> None:
        result = await get_user_by_id(db_session, "nonexistent")
        assert result is None


class TestUpsertUser:
    """Tests for upsert_user."""

    @pytest.mark.asyncio
    async def test_creates_new_user(self, db_session: AsyncSession) -> None:
        user = await upsert_user(
            db_session,
            UserUpsertData(
                email="bob@example.com",
                name="Bob",
                roles=["admin"],
            ),
        )
        assert user.email == "bob@example.com"
        assert user.name == "Bob"
        assert user.roles == ["admin"]
        assert user.id  # auto-generated uuid7

    @pytest.mark.asyncio
    async def test_updates_existing_user(self, db_session: AsyncSession) -> None:
        await _seed_user(db_session, email="bob@example.com")
        updated = await upsert_user(
            db_session,
            UserUpsertData(
                email="bob@example.com",
                name="Bobby",
                roles=["admin", "user"],
            ),
        )
        assert updated.name == "Bobby"
        assert updated.roles == ["admin", "user"]

    @pytest.mark.asyncio
    async def test_preserves_fields_not_provided(
        self, db_session: AsyncSession
    ) -> None:
        await _seed_user(db_session, email="carol@example.com")
        updated = await upsert_user(
            db_session,
            UserUpsertData(email="carol@example.com", name="Carol Updated"),
        )
        assert updated.name == "Carol Updated"
        # roles should remain unchanged
        assert updated.roles == ["user"]


class TestVerifyCredentials:
    """Tests for verify_credentials."""

    @pytest.mark.asyncio
    async def test_valid_credentials(self, db_session: AsyncSession) -> None:
        await _seed_user(db_session, password="correct-password")
        result = await verify_credentials(
            db_session, "alice@example.com", "correct-password"
        )
        assert result is not None
        assert result.login_count == 1

    @pytest.mark.asyncio
    async def test_wrong_password(self, db_session: AsyncSession) -> None:
        await _seed_user(db_session, password="correct-password")
        result = await verify_credentials(
            db_session, "alice@example.com", "wrong-password"
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_nonexistent_user(self, db_session: AsyncSession) -> None:
        result = await verify_credentials(db_session, "nobody@example.com", "any")
        assert result is None

    @pytest.mark.asyncio
    async def test_user_without_password(self, db_session: AsyncSession) -> None:
        await _seed_user(db_session, password=None)
        result = await verify_credentials(db_session, "alice@example.com", "any")
        assert result is None
