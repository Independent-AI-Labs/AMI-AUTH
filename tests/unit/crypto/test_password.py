"""Tests for password hashing and verification."""

import pytest

from ami.crypto.password import hash_password, verify_password


class TestHashPassword:
    """Tests for hash_password."""

    def test_produces_argon2_hash(self) -> None:
        result = hash_password("my-secret")
        assert result.startswith("$argon2")

    def test_different_passwords_produce_different_hashes(self) -> None:
        h1 = hash_password("password-one")
        h2 = hash_password("password-two")
        assert h1 != h2

    def test_same_password_produces_different_hashes(self) -> None:
        h1 = hash_password("same")
        h2 = hash_password("same")
        assert h1 != h2  # salted


class TestVerifyPassword:
    """Tests for verify_password."""

    def test_correct_password_returns_true(self) -> None:
        hashed = hash_password("correct-horse")
        assert verify_password("correct-horse", hashed) is True

    def test_wrong_password_returns_false(self) -> None:
        hashed = hash_password("correct-horse")
        assert verify_password("wrong-horse", hashed) is False

    def test_invalid_hash_returns_false(self) -> None:
        assert verify_password("anything", "not-a-valid-hash") is False

    def test_empty_password_can_be_hashed(self) -> None:
        hashed = hash_password("")
        assert verify_password("", hashed) is True

    @pytest.mark.parametrize("pwd", ["short", "a" * 128, "special!@#$%"])
    def test_various_passwords(self, pwd: str) -> None:
        hashed = hash_password(pwd)
        assert verify_password(pwd, hashed) is True
