"""Tests for the OIDC authorization endpoint."""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from ami.db.models_oauth import OAuthClientEntity
from ami.db.models_user import UserEntity

CLIENT_ID = "test-client-1"
USER_ID = "user-auth-1"
REDIRECT_URI = "http://localhost:3000/callback"
CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


@pytest.fixture
async def oauth_client(db_session: AsyncSession) -> OAuthClientEntity:
    """Insert a test OAuth client."""
    entity = OAuthClientEntity(
        id=CLIENT_ID,
        client_name="Test App",
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
        email="auth-user@example.com",
        name="Auth User",
    )
    db_session.add(entity)
    await db_session.flush()
    return entity


class TestAuthorize:
    """Tests for GET /oauth/authorize."""

    async def test_valid_request_redirects_with_code(
        self,
        client: AsyncClient,
        oauth_client: OAuthClientEntity,
        user: UserEntity,
    ) -> None:
        resp = await client.get(
            "/oauth/authorize",
            params={
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "scope": "openid",
                "code_challenge": CODE_CHALLENGE,
                "code_challenge_method": "S256",
                "user_id": USER_ID,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert location.startswith(REDIRECT_URI)
        assert "code=" in location

    async def test_state_is_echoed(
        self,
        client: AsyncClient,
        oauth_client: OAuthClientEntity,
        user: UserEntity,
    ) -> None:
        resp = await client.get(
            "/oauth/authorize",
            params={
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "code_challenge": CODE_CHALLENGE,
                "code_challenge_method": "S256",
                "state": "random-state-value",
                "user_id": USER_ID,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "state=random-state-value" in resp.headers["location"]

    async def test_missing_code_challenge_rejected(
        self,
        client: AsyncClient,
        oauth_client: OAuthClientEntity,
    ) -> None:
        resp = await client.get(
            "/oauth/authorize",
            params={
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "user_id": USER_ID,
            },
        )
        assert resp.status_code == 400
        body = resp.json()
        assert body["error"] == "invalid_request"

    async def test_unsupported_response_type(
        self,
        client: AsyncClient,
        oauth_client: OAuthClientEntity,
    ) -> None:
        resp = await client.get(
            "/oauth/authorize",
            params={
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "response_type": "token",
                "code_challenge": CODE_CHALLENGE,
                "user_id": USER_ID,
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "unsupported_response_type"

    async def test_invalid_client_id(
        self,
        client: AsyncClient,
    ) -> None:
        resp = await client.get(
            "/oauth/authorize",
            params={
                "client_id": "nonexistent-client",
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "code_challenge": CODE_CHALLENGE,
                "user_id": USER_ID,
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_client"

    async def test_unregistered_redirect_uri(
        self,
        client: AsyncClient,
        oauth_client: OAuthClientEntity,
    ) -> None:
        resp = await client.get(
            "/oauth/authorize",
            params={
                "client_id": CLIENT_ID,
                "redirect_uri": "http://evil.com/callback",
                "response_type": "code",
                "code_challenge": CODE_CHALLENGE,
                "user_id": USER_ID,
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_redirect_uri"

    async def test_missing_user_id_returns_login_required(
        self,
        client: AsyncClient,
        oauth_client: OAuthClientEntity,
    ) -> None:
        resp = await client.get(
            "/oauth/authorize",
            params={
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "code_challenge": CODE_CHALLENGE,
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "login_required"

    async def test_non_s256_method_rejected(
        self,
        client: AsyncClient,
        oauth_client: OAuthClientEntity,
    ) -> None:
        resp = await client.get(
            "/oauth/authorize",
            params={
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "code_challenge": CODE_CHALLENGE,
                "code_challenge_method": "plain",
                "user_id": USER_ID,
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"
