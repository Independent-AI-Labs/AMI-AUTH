"""Integration test: full OIDC authorization code flow."""

import hashlib
from base64 import urlsafe_b64encode
from collections.abc import AsyncIterator
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ami.core.app import create_app
from ami.crypto.keys import encrypt_private_key, generate_rsa_keypair
from ami.crypto.password import hash_password
from ami.db.base import BaseEntity
from ami.db.engine import get_session
from ami.db.models_keys import SigningKeyEntity
from ami.db.models_oauth import OAuthClientEntity
from ami.db.models_user import UserEntity

HTTP_OK = 200
HTTP_REDIRECT = 302

FERNET_KEY = Fernet.generate_key().decode()
CLIENT_ID = "integration-client"
REDIRECT_URI = "http://localhost:3000/callback"
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
USER_EMAIL = "flow@example.com"


def _make_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@pytest.fixture(autouse=True)
def _flow_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTH_ISSUER_URL", "http://localhost:8000")
    monkeypatch.setenv("AUTH_SIGNING_KEY_ENCRYPTION_KEY", FERNET_KEY)


@pytest.fixture
async def flow_client() -> AsyncIterator[AsyncClient]:
    """Set up a full OIDC environment and return an httpx client."""
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)

    @event.listens_for(engine.sync_engine, "connect")
    def _pragma(dbapi_conn, _rec) -> None:
        c = dbapi_conn.cursor()
        c.execute("PRAGMA journal_mode=WAL")
        c.close()

    async with engine.begin() as conn:
        await conn.run_sync(BaseEntity.metadata.create_all)

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Seed data
    async with factory() as session:
        session.add(
            OAuthClientEntity(
                id=CLIENT_ID,
                client_name="Flow App",
                redirect_uris=[REDIRECT_URI],
            )
        )
        session.add(
            UserEntity(
                id="flow-user-1",
                email=USER_EMAIL,
                name="Flow User",
                password_hash=hash_password("secret123"),
                roles=["admin"],
                groups=["staff"],
            )
        )
        kp = generate_rsa_keypair()
        session.add(
            SigningKeyEntity(
                kid=kp.kid,
                algorithm="RS256",
                private_key_pem=encrypt_private_key(kp.private_key_pem, FERNET_KEY),
                public_key_pem=kp.public_key_pem,
                is_active=True,
            )
        )
        await session.commit()

    app = create_app()

    async def _override() -> AsyncIterator[AsyncSession]:
        async with factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    app.dependency_overrides[get_session] = _override
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    await engine.dispose()


@pytest.mark.integration
class TestFullOIDCFlow:
    """End-to-end OIDC authorization code flow."""

    async def test_discovery(self, flow_client: AsyncClient) -> None:
        resp = await flow_client.get("/.well-known/openid-configuration")
        assert resp.status_code == HTTP_OK
        doc = resp.json()
        assert doc["issuer"] == "http://localhost:8000"
        assert "/oauth/token" in doc["token_endpoint"]
        assert "S256" in doc["code_challenge_methods_supported"]

    async def test_jwks(self, flow_client: AsyncClient) -> None:
        resp = await flow_client.get("/oauth/jwks")
        assert resp.status_code == HTTP_OK
        body = resp.json()
        assert len(body["keys"]) >= 1
        assert body["keys"][0]["kty"] == "RSA"

    async def test_full_flow(self, flow_client: AsyncClient) -> None:
        """authorize -> token -> userinfo -> revoke."""
        ac = flow_client
        challenge = _make_challenge(VERIFIER)

        # Step 1: Authorize
        resp = await ac.get(
            "/oauth/authorize",
            params={
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "scope": "openid",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "user_id": "flow-user-1",
                "state": "xstate",
            },
            follow_redirects=False,
        )
        assert resp.status_code == HTTP_REDIRECT
        loc = resp.headers["location"]
        parsed = urlparse(loc)
        qs = parse_qs(parsed.query)
        assert "code" in qs
        assert qs["state"] == ["xstate"]
        code = qs["code"][0]

        # Step 2: Token exchange
        resp = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "code_verifier": VERIFIER,
            },
        )
        assert resp.status_code == HTTP_OK
        tokens = resp.json()
        assert tokens["token_type"] == "Bearer"
        access_token = tokens["access_token"]
        refresh_token = tokens["refresh_token"]

        # Step 3: UserInfo
        resp = await ac.get(
            "/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert resp.status_code == HTTP_OK
        info = resp.json()
        assert info["sub"] == "flow-user-1"
        assert info["email"] == USER_EMAIL

        # Step 4: Refresh
        resp = await ac.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": CLIENT_ID,
            },
        )
        assert resp.status_code == HTTP_OK
        new_tokens = resp.json()
        assert new_tokens["access_token"] != access_token
        assert new_tokens["refresh_token"] != refresh_token

        # Step 5: Revoke the new access token
        resp = await ac.post(
            "/oauth/revoke",
            data={"token": new_tokens["access_token"]},
        )
        assert resp.status_code == HTTP_OK
