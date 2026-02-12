"""RSA signing key generation, encryption, and JWK conversion."""

import base64

import uuid_utils
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from ami.crypto.types import JWKEntry, SigningKeyData

RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537


def generate_rsa_keypair() -> SigningKeyData:
    """Generate a new RSA-2048 keypair for JWT signing."""
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    kid = str(uuid_utils.uuid7())
    return SigningKeyData(
        kid=kid, private_key_pem=private_pem, public_key_pem=public_pem
    )


def encrypt_private_key(private_pem: str, fernet_key: str) -> str:
    """Encrypt a PEM private key with Fernet for database storage."""
    cipher = Fernet(fernet_key.encode())
    return cipher.encrypt(private_pem.encode()).decode()


def decrypt_private_key(encrypted: str, fernet_key: str) -> str:
    """Decrypt a Fernet-encrypted PEM private key."""
    cipher = Fernet(fernet_key.encode())
    return cipher.decrypt(encrypted.encode()).decode()


def _int_to_base64url(value: int) -> str:
    """Encode an integer as base64url without padding."""
    byte_length = (value.bit_length() + 7) // 8
    raw = value.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def pem_to_jwk_entry(public_key_pem: str, kid: str) -> JWKEntry:
    """Convert a PEM public key to JWK format."""
    loaded = serialization.load_pem_public_key(public_key_pem.encode())
    assert isinstance(loaded, RSAPublicKey)
    numbers = loaded.public_numbers()
    return JWKEntry(
        kid=kid,
        n=_int_to_base64url(numbers.n),
        e=_int_to_base64url(numbers.e),
    )
