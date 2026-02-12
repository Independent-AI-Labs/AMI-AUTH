"""Password hashing and verification using Argon2id."""

import argon2

_hasher = argon2.PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=1,
)


def hash_password(password: str) -> str:
    """Hash a password using Argon2id."""
    return _hasher.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against its Argon2 hash."""
    try:
        return _hasher.verify(hashed, plain)
    except argon2.exceptions.VerifyMismatchError:
        return False
    except argon2.exceptions.InvalidHashError:
        return False
