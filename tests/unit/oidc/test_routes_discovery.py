"""Tests for OIDC discovery and JWKS endpoints."""

from cryptography.fernet import Fernet
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from ami.crypto.keys import encrypt_private_key, generate_rsa_keypair
from ami.db.models_keys import SigningKeyEntity

FERNET_KEY = Fernet.generate_key().decode()


class TestOpenIDConfiguration:
    """Tests for GET /.well-known/openid-configuration."""

    async def test_returns_discovery_document(self, client: AsyncClient) -> None:
        resp = await client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200
        body = resp.json()
        assert body["issuer"] == "http://localhost:8000"
        assert "authorization_code" in body["grant_types_supported"]
        assert "S256" in body["code_challenge_methods_supported"]
        assert "RS256" in body["id_token_signing_alg_values_supported"]


class TestJWKS:
    """Tests for GET /oauth/jwks."""

    async def test_returns_empty_keys(self, client: AsyncClient) -> None:
        resp = await client.get("/oauth/jwks")
        assert resp.status_code == 200
        assert resp.json()["keys"] == []

    async def test_returns_keys_with_cache_header(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
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

        resp = await client.get("/oauth/jwks")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["keys"]) == 1
        assert body["keys"][0]["kty"] == "RSA"
        assert body["keys"][0]["kid"] == kp.kid
        assert "public" in resp.headers.get("cache-control", "")
