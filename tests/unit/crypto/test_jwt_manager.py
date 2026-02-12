"""Tests for JWT creation and verification."""

import time

import jwt
import pytest

from ami.crypto.jwt_manager import JWTManager
from ami.crypto.keys import generate_rsa_keypair
from ami.crypto.types import TokenClaims

ISSUER = "http://localhost:8000"


@pytest.fixture
def jwt_mgr() -> JWTManager:
    """Create a JWTManager with a fresh keypair."""
    kp = generate_rsa_keypair()
    return JWTManager(
        private_key_pem=kp.private_key_pem,
        public_key_pem=kp.public_key_pem,
        kid=kp.kid,
        issuer=ISSUER,
    )


class TestCreateAccessToken:
    """Tests for access token creation."""

    def test_creates_valid_jwt(self, jwt_mgr: JWTManager) -> None:
        token = jwt_mgr.create_access_token(
            TokenClaims(
                sub="user-1",
                aud="client-1",
                scope="openid",
                email="a@b.com",
            )
        )
        assert isinstance(token, str)
        assert len(token) > 50

    def test_token_has_kid_header(self, jwt_mgr: JWTManager) -> None:
        token = jwt_mgr.create_access_token(
            TokenClaims(
                sub="user-1",
                aud="client-1",
                scope="openid",
                email="a@b.com",
            )
        )
        header = jwt.get_unverified_header(token)
        assert "kid" in header

    def test_token_contains_claims(self, jwt_mgr: JWTManager) -> None:
        token = jwt_mgr.create_access_token(
            TokenClaims(
                sub="user-1",
                aud="client-1",
                scope="openid profile",
                email="alice@example.com",
                name="Alice",
            )
        )
        claims = jwt_mgr.verify_token(token, audience="client-1")
        assert claims.sub == "user-1"
        assert claims.aud == "client-1"
        assert claims.iss == ISSUER
        assert claims.email == "alice@example.com"
        assert claims.name == "Alice"
        assert claims.scope == "openid profile"


class TestCreateIdToken:
    """Tests for id_token creation."""

    def test_includes_nonce(self, jwt_mgr: JWTManager) -> None:
        token = jwt_mgr.create_id_token(
            TokenClaims(
                sub="user-1",
                aud="client-1",
                email="a@b.com",
                nonce="abc123",
            )
        )
        claims = jwt_mgr.verify_token(token, audience="client-1")
        assert claims.nonce == "abc123"

    def test_nonce_omitted_when_none(self, jwt_mgr: JWTManager) -> None:
        token = jwt_mgr.create_id_token(
            TokenClaims(sub="user-1", aud="client-1", email="a@b.com")
        )
        claims = jwt_mgr.verify_token(token, audience="client-1")
        assert claims.nonce is None


class TestVerifyToken:
    """Tests for token verification."""

    def test_expired_token_rejected(self, jwt_mgr: JWTManager) -> None:
        token = jwt_mgr.create_access_token(
            TokenClaims(
                sub="user-1",
                aud="client-1",
                scope="openid",
                email="a@b.com",
                ttl_seconds=-1,
            )
        )
        time.sleep(0.1)
        with pytest.raises(jwt.ExpiredSignatureError):
            jwt_mgr.verify_token(token, audience="client-1")

    def test_wrong_key_rejected(self, jwt_mgr: JWTManager) -> None:
        token = jwt_mgr.create_access_token(
            TokenClaims(
                sub="user-1",
                aud="client-1",
                scope="openid",
                email="a@b.com",
            )
        )
        other_kp = generate_rsa_keypair()
        other_mgr = JWTManager(
            private_key_pem=other_kp.private_key_pem,
            public_key_pem=other_kp.public_key_pem,
            kid=other_kp.kid,
            issuer=ISSUER,
        )
        with pytest.raises(jwt.InvalidSignatureError):
            other_mgr.verify_token(token, audience="client-1")
