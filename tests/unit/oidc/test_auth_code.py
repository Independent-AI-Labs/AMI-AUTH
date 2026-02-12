"""Tests for authorization code and PKCE operations."""

import hashlib
from base64 import urlsafe_b64encode

from ami.oidc.auth_code import generate_code, verify_pkce

CODE_LENGTH_MIN = 20


class TestGenerateCode:
    """Tests for auth code generation."""

    def test_sufficient_length(self) -> None:
        code = generate_code()
        assert len(code) >= CODE_LENGTH_MIN

    def test_unique_codes(self) -> None:
        codes = {generate_code() for _ in range(100)}
        assert len(codes) == 100


class TestVerifyPKCE:
    """Tests for S256 PKCE verification."""

    def test_valid_verifier(self) -> None:
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        assert verify_pkce(verifier, challenge) is True

    def test_invalid_verifier(self) -> None:
        verifier = "correct-verifier"
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        assert verify_pkce("wrong-verifier", challenge) is False

    def test_empty_verifier_fails(self) -> None:
        assert verify_pkce("", "some-challenge") is False
