"""Tests for RSA key generation and Fernet encryption."""

from cryptography.fernet import Fernet

from ami.crypto.keys import (
    decrypt_private_key,
    encrypt_private_key,
    generate_rsa_keypair,
    pem_to_jwk_entry,
)


class TestGenerateRSAKeypair:
    """Tests for RSA keypair generation."""

    def test_produces_valid_pem(self) -> None:
        kp = generate_rsa_keypair()
        assert kp.private_key_pem.startswith("-----BEGIN PRIVATE KEY-----")
        assert kp.public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")

    def test_kid_is_nonempty(self) -> None:
        kp = generate_rsa_keypair()
        assert len(kp.kid) > 10

    def test_different_calls_produce_different_keys(self) -> None:
        kp1 = generate_rsa_keypair()
        kp2 = generate_rsa_keypair()
        assert kp1.kid != kp2.kid
        assert kp1.private_key_pem != kp2.private_key_pem


class TestFernetEncryption:
    """Tests for Fernet encrypt/decrypt of private keys."""

    def test_roundtrip(self) -> None:
        kp = generate_rsa_keypair()
        fernet_key = Fernet.generate_key().decode()
        encrypted = encrypt_private_key(kp.private_key_pem, fernet_key)
        assert encrypted != kp.private_key_pem
        decrypted = decrypt_private_key(encrypted, fernet_key)
        assert decrypted == kp.private_key_pem


class TestPemToJWK:
    """Tests for PEM to JWK conversion."""

    def test_produces_valid_jwk(self) -> None:
        kp = generate_rsa_keypair()
        jwk = pem_to_jwk_entry(kp.public_key_pem, kp.kid)
        assert jwk.kty == "RSA"
        assert jwk.use == "sig"
        assert jwk.alg == "RS256"
        assert jwk.kid == kp.kid
        assert len(jwk.n) > 100  # RSA-2048 modulus is large
        assert jwk.e  # exponent is set
