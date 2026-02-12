"""Tests for DataOps API endpoints."""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from ami.crypto.password import hash_password
from ami.db.models_user import UserEntity

TEST_TOKEN = "test-internal-token"
AUTH_HEADER = {"Authorization": f"Bearer {TEST_TOKEN}"}
BAD_HEADER = {"Authorization": "Bearer wrong-token"}


async def _seed_user(
    session: AsyncSession,
    *,
    user_id: str = "u-001",
    email: str = "alice@example.com",
    password: str = "secret123",
) -> UserEntity:
    """Insert a test user."""
    user = UserEntity(
        id=user_id,
        email=email,
        name="Alice",
        password_hash=hash_password(password),
        roles=["user"],
        groups=["team-a"],
        login_count=0,
        is_active=True,
    )
    session.add(user)
    await session.flush()
    return user


class TestInternalTokenAuth:
    """All DataOps endpoints require valid internal token."""

    @pytest.mark.asyncio
    async def test_missing_token_returns_401(self, client: AsyncClient) -> None:
        resp = await client.get("/auth/providers/catalog")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_wrong_token_returns_401(self, client: AsyncClient) -> None:
        resp = await client.get("/auth/providers/catalog", headers=BAD_HEADER)
        assert resp.status_code == 401


class TestVerifyEndpoint:
    """POST /auth/verify."""

    @pytest.mark.asyncio
    async def test_valid_credentials(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        await _seed_user(db_session, password="correct")
        resp = await client.post(
            "/auth/verify",
            json={"email": "alice@example.com", "password": "correct"},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["user"] is not None
        assert body["user"]["email"] == "alice@example.com"
        assert body["user"]["id"] == "u-001"

    @pytest.mark.asyncio
    async def test_wrong_password(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        await _seed_user(db_session, password="correct")
        resp = await client.post(
            "/auth/verify",
            json={"email": "alice@example.com", "password": "wrong"},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["user"] is None
        assert body["reason"] == "invalid_credentials"

    @pytest.mark.asyncio
    async def test_nonexistent_user(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/auth/verify",
            json={"email": "nobody@x.com", "password": "any"},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200
        assert resp.json()["user"] is None


class TestGetUserByEmail:
    """GET /auth/users/by-email."""

    @pytest.mark.asyncio
    async def test_found(self, client: AsyncClient, db_session: AsyncSession) -> None:
        await _seed_user(db_session)
        resp = await client.get(
            "/auth/users/by-email",
            params={"email": "alice@example.com"},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200
        assert resp.json()["user"]["email"] == "alice@example.com"

    @pytest.mark.asyncio
    async def test_not_found(self, client: AsyncClient) -> None:
        resp = await client.get(
            "/auth/users/by-email",
            params={"email": "nobody@x.com"},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200
        assert resp.json()["user"] is None


class TestGetUserById:
    """GET /auth/users/{id}."""

    @pytest.mark.asyncio
    async def test_found(self, client: AsyncClient, db_session: AsyncSession) -> None:
        await _seed_user(db_session, user_id="uid-99")
        resp = await client.get("/auth/users/uid-99", headers=AUTH_HEADER)
        assert resp.status_code == 200
        assert resp.json()["user"]["id"] == "uid-99"

    @pytest.mark.asyncio
    async def test_not_found(self, client: AsyncClient) -> None:
        resp = await client.get("/auth/users/nonexistent", headers=AUTH_HEADER)
        assert resp.status_code == 200
        assert resp.json()["user"] is None


class TestCreateOrUpdateUser:
    """POST /auth/users."""

    @pytest.mark.asyncio
    async def test_creates_new_user(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/auth/users",
            json={
                "email": "new@example.com",
                "name": "New User",
                "roles": ["admin"],
                "groups": [],
            },
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200
        user = resp.json()["user"]
        assert user["email"] == "new@example.com"
        assert user["name"] == "New User"
        assert user["roles"] == ["admin"]
        assert user["id"]  # auto-generated

    @pytest.mark.asyncio
    async def test_updates_existing_user(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        await _seed_user(db_session)
        resp = await client.post(
            "/auth/users",
            json={
                "email": "alice@example.com",
                "name": "Alice Updated",
                "roles": ["admin", "user"],
                "groups": ["team-b"],
            },
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200
        user = resp.json()["user"]
        assert user["name"] == "Alice Updated"
        assert user["roles"] == ["admin", "user"]


class TestProviderCatalog:
    """GET /auth/providers/catalog."""

    @pytest.mark.asyncio
    async def test_returns_empty_catalog(self, client: AsyncClient) -> None:
        resp = await client.get("/auth/providers/catalog", headers=AUTH_HEADER)
        assert resp.status_code == 200
        assert resp.json()["providers"] == []
