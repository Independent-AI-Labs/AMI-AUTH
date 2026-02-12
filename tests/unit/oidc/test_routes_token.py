"""Tests for the OIDC token endpoint."""

import hashlib
from base64 import urlsafe_b64encode
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from ami.crypto.keys import encrypt_private_key, generate_rsa_keypair
from ami.db.models_keys import SigningKeyEntity
from ami.db.models_oauth import (
    AuthorizationCodeEntity,
    OAuthClientEntity,
)
from ami.db.models_user import UserEntity

CLIENT_ID = "tok-client-1"
USER_ID = "tok-user-1"
REDIRECT_URI = "http://localhost:3000/callback"
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
FERNET_KEY = Fernet.generate_key().decode()


def _make_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@pytest.fixture(autouse=True)
def _token_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set signing key encryption key for token tests."""
    monkeypatch.setenv("AUTH_SIGNING_KEY_ENCRYPTION_KEY", FERNET_KEY)


@pytest.fixture
async def oauth_client(db_session: AsyncSession) -> OAuthClientEntity:
    """Insert a test OAuth client."""
    entity = OAuthClientEntity(
        id=CLIENT_ID,
        client_name="Token Test App",
        redirect_uris=[REDIRECT_URI],
    )
    db_session.add(entity)
    await db_session.flush()
    return entity


@pytest.fixture
async def user(db_session: AsyncSession) -> UserEntity:
    """Insert a test user."""
    entity = UserEntity(
        id=USER_ID,
        email="token-user@example.com",
        name="Token User",
    )
    db_session.add(entity)
    await db_session.flush()
    return entity


@pytest.fixture
async def signing_key(db_session: AsyncSession) -> SigningKeyEntity:
    """Insert a signing key for JWT creation."""
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
async def auth_code(
    db_session: AsyncSession,
    oauth_client: OAuthClientEntity,
    user: UserEntity,
) -> AuthorizationCodeEntity:
    """Insert a valid authorization code."""
    entity = AuthorizationCodeEntity(
        code="test-auth-code-123",
        client_id=CLIENT_ID,
        user_id=USER_ID,
        redirect_uri=REDIRECT_URI,
        scope="openid",
        nonce="test-nonce",
        code_challenge=_make_challenge(VERIFIER),
        code_challenge_method="S256",
        expires_at=datetime.now(UTC) + timedelta(seconds=60),
        used=False,
    )
    db_session.add(entity)
    await db_session.flush()
    return entity


class TestAuthCodeGrant:
    """Tests for grant_type=authorization_code."""

    async def test_valid_exchange(
        self,
        client: AsyncClient,
        auth_code: AuthorizationCodeEntity,
        signing_key: SigningKeyEntity,
    ) -> None:
        resp = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": "test-auth-code-123",
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "code_verifier": VERIFIER,
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert "refresh_token" in body
        assert "id_token" in body
        assert body["token_type"] == "Bearer"
        assert body["scope"] == "openid"

    async def test_missing_code_rejected(
        self,
        client: AsyncClient,
        signing_key: SigningKeyEntity,
    ) -> None:
        resp = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "code_verifier": VERIFIER,
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"

    async def test_missing_verifier_rejected(
        self,
        client: AsyncClient,
        auth_code: AuthorizationCodeEntity,
        signing_key: SigningKeyEntity,
    ) -> None:
        resp = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": "test-auth-code-123",
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"

    async def test_wrong_verifier_rejected(
        self,
        client: AsyncClient,
        auth_code: AuthorizationCodeEntity,
        signing_key: SigningKeyEntity,
    ) -> None:
        resp = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": "test-auth-code-123",
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "code_verifier": "wrong-verifier-value",
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"

    async def test_invalid_code_rejected(
        self,
        client: AsyncClient,
        signing_key: SigningKeyEntity,
        oauth_client: OAuthClientEntity,
    ) -> None:
        resp = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": "nonexistent-code",
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "code_verifier": VERIFIER,
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"

    async def test_code_cannot_be_reused(
        self,
        client: AsyncClient,
        auth_code: AuthorizationCodeEntity,
        signing_key: SigningKeyEntity,
    ) -> None:
        data = {
            "grant_type": "authorization_code",
            "code": "test-auth-code-123",
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "code_verifier": VERIFIER,
        }
        resp1 = await client.post("/oauth/token", data=data)
        assert resp1.status_code == 200
        resp2 = await client.post("/oauth/token", data=data)
        assert resp2.status_code == 400
        assert resp2.json()["error"] == "invalid_grant"


class TestRefreshTokenGrant:
    """Tests for grant_type=refresh_token."""

    async def test_valid_refresh(
        self,
        client: AsyncClient,
        auth_code: AuthorizationCodeEntity,
        signing_key: SigningKeyEntity,
    ) -> None:
        # First, exchange auth code to get tokens
        resp1 = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": "test-auth-code-123",
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "code_verifier": VERIFIER,
            },
        )
        assert resp1.status_code == 200
        refresh = resp1.json()["refresh_token"]

        # Now refresh
        resp2 = await client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh,
                "client_id": CLIENT_ID,
            },
        )
        assert resp2.status_code == 200
        body2 = resp2.json()
        assert "access_token" in body2
        assert "refresh_token" in body2
        assert body2["refresh_token"] != refresh  # rotated

    async def test_invalid_refresh_token(
        self,
        client: AsyncClient,
        signing_key: SigningKeyEntity,
        oauth_client: OAuthClientEntity,
    ) -> None:
        resp = await client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "invalid-refresh-token",
                "client_id": CLIENT_ID,
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"

    async def test_missing_refresh_token(
        self,
        client: AsyncClient,
        signing_key: SigningKeyEntity,
    ) -> None:
        resp = await client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": CLIENT_ID,
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"


class TestUnsupportedGrant:
    """Tests for unsupported grant types."""

    async def test_unsupported_grant_type(
        self,
        client: AsyncClient,
        signing_key: SigningKeyEntity,
    ) -> None:
        resp = await client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": CLIENT_ID,
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "unsupported_grant_type"


class TestNoSigningKey:
    """Tests when no signing key is configured."""

    async def test_returns_server_error(
        self,
        client: AsyncClient,
    ) -> None:
        resp = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": "any-code",
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "code_verifier": VERIFIER,
            },
        )
        assert resp.status_code == 500
        assert resp.json()["error"] == "server_error"
