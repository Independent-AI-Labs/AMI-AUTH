"""Tests for the OIDC userinfo endpoint."""

import pytest
from cryptography.fernet import Fernet
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from ami.crypto.jwt_manager import JWTManager
from ami.crypto.keys import encrypt_private_key, generate_rsa_keypair
from ami.crypto.types import TokenClaims
from ami.db.models_keys import SigningKeyEntity
from ami.db.models_user import UserEntity

FERNET_KEY = Fernet.generate_key().decode()
ISSUER = "http://localhost:8000"
USER_ID = "userinfo-user-1"


@pytest.fixture(autouse=True)
def _ui_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTH_SIGNING_KEY_ENCRYPTION_KEY", FERNET_KEY)


@pytest.fixture
async def signing_key(db_session: AsyncSession) -> SigningKeyEntity:
    kp = generate_rsa_keypair()
    entity = SigningKeyEntity(
        kid=kp.kid,
        algorithm="RS256",
        private_key_pem=encrypt_private_key(kp.private_key_pem, FERNET_KEY),
        public_key_pem=kp.public_key_pem,
        is_active=True,
    )
    db_session.add(entity)
    await db_session.flush()
    return entity


@pytest.fixture
async def user(db_session: AsyncSession) -> UserEntity:
    entity = UserEntity(
        id=USER_ID,
        email="ui@example.com",
        name="UI User",
        roles=["viewer"],
        groups=["team-a"],
        tenant_id="tenant-1",
    )
    db_session.add(entity)
    await db_session.flush()
    return entity


@pytest.fixture
def jwt_mgr(signing_key: SigningKeyEntity) -> JWTManager:
    private_pem = (
        Fernet(FERNET_KEY.encode())
        .decrypt(signing_key.private_key_pem.encode())
        .decode()
    )
    return JWTManager(
        private_key_pem=private_pem,
        public_key_pem=signing_key.public_key_pem,
        kid=signing_key.kid,
        issuer=ISSUER,
    )


class TestUserInfo:
    """Tests for GET /oauth/userinfo."""

    async def test_returns_user_claims(
        self,
        client: AsyncClient,
        jwt_mgr: JWTManager,
        user: UserEntity,
    ) -> None:
        token = jwt_mgr.create_access_token(
            TokenClaims(
                sub=USER_ID,
                aud="test-client",
                scope="openid",
                email="ui@example.com",
                name="UI User",
            )
        )
        resp = await client.get(
            "/oauth/userinfo",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["sub"] == USER_ID
        assert body["email"] == "ui@example.com"
        assert body["name"] == "UI User"
        assert body["roles"] == ["viewer"]
        assert body["groups"] == ["team-a"]
        assert body["tenant_id"] == "tenant-1"

    async def test_missing_bearer_returns_401(
        self,
        client: AsyncClient,
        signing_key: SigningKeyEntity,
    ) -> None:
        resp = await client.get("/oauth/userinfo")
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_token"

    async def test_invalid_token_returns_401(
        self,
        client: AsyncClient,
        signing_key: SigningKeyEntity,
    ) -> None:
        resp = await client.get(
            "/oauth/userinfo",
            headers={"Authorization": "Bearer bad-jwt-token"},
        )
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_token"

    async def test_no_signing_key_returns_500(
        self,
        client: AsyncClient,
    ) -> None:
        resp = await client.get(
            "/oauth/userinfo",
            headers={"Authorization": "Bearer some-token"},
        )
        assert resp.status_code == 500
        assert resp.json()["error"] == "server_error"

    async def test_user_not_in_db_still_returns_claims(
        self,
        client: AsyncClient,
        jwt_mgr: JWTManager,
        signing_key: SigningKeyEntity,
    ) -> None:
        token = jwt_mgr.create_access_token(
            TokenClaims(
                sub="nonexistent-user",
                aud="c",
                scope="openid",
                email="gone@example.com",
            )
        )
        resp = await client.get(
            "/oauth/userinfo",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["sub"] == "nonexistent-user"
        assert body["email"] == "gone@example.com"
        assert "roles" not in body
