"""Tests for token service DB operations (issue, refresh, revoke)."""

import pytest
from cryptography.fernet import Fernet
from sqlalchemy.ext.asyncio import AsyncSession

from ami.crypto.jwt_manager import JWTManager
from ami.crypto.keys import generate_rsa_keypair
from ami.db.models_oauth import OAuthClientEntity, OAuthTokenEntity
from ami.db.models_user import UserEntity
from ami.oidc.token_service import (
    hash_token,
    issue_tokens,
    refresh_tokens,
    revoke_token,
)
from ami.oidc.types import TokenIssuanceParams

FERNET_KEY = Fernet.generate_key().decode()
ISSUER = "http://localhost:8000"
CLIENT_ID = "ts-client-1"
USER_ID = "ts-user-1"
ACCESS_TTL = 3600
REFRESH_TTL = 86400


@pytest.fixture
async def seed(db_session: AsyncSession) -> None:
    """Insert client + user for FK constraints."""
    db_session.add(
        OAuthClientEntity(
            id=CLIENT_ID,
            client_name="TS App",
            redirect_uris=["http://localhost:3000/cb"],
        )
    )
    db_session.add(UserEntity(id=USER_ID, email="ts@example.com", name="TS User"))
    await db_session.flush()


@pytest.fixture
def jwt_mgr() -> JWTManager:
    kp = generate_rsa_keypair()
    return JWTManager(
        private_key_pem=kp.private_key_pem,
        public_key_pem=kp.public_key_pem,
        kid=kp.kid,
        issuer=ISSUER,
    )


class TestIssueTokens:
    """Tests for issue_tokens."""

    async def test_returns_token_response(
        self, db_session: AsyncSession, seed: None, jwt_mgr: JWTManager
    ) -> None:
        resp = await issue_tokens(
            db_session,
            TokenIssuanceParams(
                client_id=CLIENT_ID,
                user_id=USER_ID,
                scope="openid",
                email="ts@example.com",
                name="TS User",
                nonce="n1",
                jwt_mgr=jwt_mgr,
                access_ttl=ACCESS_TTL,
                refresh_ttl=REFRESH_TTL,
            ),
        )
        assert resp.access_token
        assert resp.refresh_token
        assert resp.id_token
        assert resp.token_type == "Bearer"
        assert resp.scope == "openid"
        assert resp.expires_in == ACCESS_TTL

    async def test_stores_hashes_in_db(
        self, db_session: AsyncSession, seed: None, jwt_mgr: JWTManager
    ) -> None:
        resp = await issue_tokens(
            db_session,
            TokenIssuanceParams(
                client_id=CLIENT_ID,
                user_id=USER_ID,
                scope="openid",
                email="ts@example.com",
                name=None,
                nonce=None,
                jwt_mgr=jwt_mgr,
                access_ttl=ACCESS_TTL,
                refresh_ttl=REFRESH_TTL,
            ),
        )
        from sqlalchemy import select

        stmt = select(OAuthTokenEntity).where(
            OAuthTokenEntity.access_token_hash == hash_token(resp.access_token)
        )
        result = await db_session.execute(stmt)
        entity = result.scalar_one_or_none()
        assert entity is not None
        assert entity.client_id == CLIENT_ID
        assert entity.revoked is False


class TestRefreshTokens:
    """Tests for refresh_tokens."""

    async def test_rotates_tokens(
        self, db_session: AsyncSession, seed: None, jwt_mgr: JWTManager
    ) -> None:
        original = await issue_tokens(
            db_session,
            TokenIssuanceParams(
                client_id=CLIENT_ID,
                user_id=USER_ID,
                scope="openid",
                email="ts@example.com",
                name=None,
                nonce=None,
                jwt_mgr=jwt_mgr,
                access_ttl=ACCESS_TTL,
                refresh_ttl=REFRESH_TTL,
            ),
        )
        new_resp = await refresh_tokens(
            db_session,
            TokenIssuanceParams(
                client_id=CLIENT_ID,
                user_id="",
                scope="",
                email="ts@example.com",
                name=None,
                jwt_mgr=jwt_mgr,
                access_ttl=ACCESS_TTL,
                refresh_ttl=REFRESH_TTL,
            ),
            original.refresh_token,
        )
        assert new_resp is not None
        assert new_resp.access_token
        assert new_resp.refresh_token != original.refresh_token

    async def test_old_refresh_token_revoked(
        self, db_session: AsyncSession, seed: None, jwt_mgr: JWTManager
    ) -> None:
        original = await issue_tokens(
            db_session,
            TokenIssuanceParams(
                client_id=CLIENT_ID,
                user_id=USER_ID,
                scope="openid",
                email="ts@example.com",
                name=None,
                nonce=None,
                jwt_mgr=jwt_mgr,
                access_ttl=ACCESS_TTL,
                refresh_ttl=REFRESH_TTL,
            ),
        )
        refresh_params = TokenIssuanceParams(
            client_id=CLIENT_ID,
            user_id="",
            scope="",
            email="ts@example.com",
            name=None,
            jwt_mgr=jwt_mgr,
            access_ttl=ACCESS_TTL,
            refresh_ttl=REFRESH_TTL,
        )
        await refresh_tokens(
            db_session,
            refresh_params,
            original.refresh_token,
        )
        # Try reusing old refresh token
        reuse = await refresh_tokens(
            db_session,
            refresh_params,
            original.refresh_token,
        )
        assert reuse is None

    async def test_invalid_refresh_returns_none(
        self, db_session: AsyncSession, seed: None, jwt_mgr: JWTManager
    ) -> None:
        result = await refresh_tokens(
            db_session,
            TokenIssuanceParams(
                client_id=CLIENT_ID,
                user_id="",
                scope="",
                email="ts@example.com",
                name=None,
                jwt_mgr=jwt_mgr,
                access_ttl=ACCESS_TTL,
                refresh_ttl=REFRESH_TTL,
            ),
            "nonexistent-token",
        )
        assert result is None


class TestRevokeToken:
    """Tests for revoke_token."""

    async def test_revoke_access_token(
        self, db_session: AsyncSession, seed: None, jwt_mgr: JWTManager
    ) -> None:
        resp = await issue_tokens(
            db_session,
            TokenIssuanceParams(
                client_id=CLIENT_ID,
                user_id=USER_ID,
                scope="openid",
                email="ts@example.com",
                name=None,
                nonce=None,
                jwt_mgr=jwt_mgr,
                access_ttl=ACCESS_TTL,
                refresh_ttl=REFRESH_TTL,
            ),
        )
        result = await revoke_token(db_session, token=resp.access_token)
        assert result is True

    async def test_revoke_refresh_token(
        self, db_session: AsyncSession, seed: None, jwt_mgr: JWTManager
    ) -> None:
        resp = await issue_tokens(
            db_session,
            TokenIssuanceParams(
                client_id=CLIENT_ID,
                user_id=USER_ID,
                scope="openid",
                email="ts@example.com",
                name=None,
                nonce=None,
                jwt_mgr=jwt_mgr,
                access_ttl=ACCESS_TTL,
                refresh_ttl=REFRESH_TTL,
            ),
        )
        result = await revoke_token(db_session, token=resp.refresh_token)
        assert result is True

    async def test_revoke_unknown_token_is_idempotent(
        self, db_session: AsyncSession
    ) -> None:
        result = await revoke_token(db_session, token="unknown-token")
        assert result is True
