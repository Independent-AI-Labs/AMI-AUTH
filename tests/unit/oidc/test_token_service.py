"""Tests for token service operations."""

from ami.oidc.token_service import generate_refresh_token, hash_token

TOKEN_MIN_LENGTH = 30


class TestGenerateRefreshToken:
    """Tests for opaque refresh token generation."""

    def test_sufficient_length(self) -> None:
        token = generate_refresh_token()
        assert len(token) >= TOKEN_MIN_LENGTH

    def test_unique_tokens(self) -> None:
        tokens = {generate_refresh_token() for _ in range(100)}
        assert len(tokens) == 100


class TestHashToken:
    """Tests for SHA-256 token hashing."""

    def test_consistent_hash(self) -> None:
        token = "my-test-token"
        h1 = hash_token(token)
        h2 = hash_token(token)
        assert h1 == h2

    def test_hex_output(self) -> None:
        h = hash_token("anything")
        assert len(h) == 64  # SHA-256 hex = 64 chars
        assert all(c in "0123456789abcdef" for c in h)

    def test_different_tokens_different_hashes(self) -> None:
        assert hash_token("token-a") != hash_token("token-b")
