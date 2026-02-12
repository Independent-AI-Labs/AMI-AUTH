"""Database operations for signing key management."""

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ami.crypto.keys import encrypt_private_key, generate_rsa_keypair
from ami.db.models_keys import SigningKeyEntity


async def get_active_key(
    session: AsyncSession,
) -> SigningKeyEntity | None:
    """Return the currently active signing key."""
    stmt = select(SigningKeyEntity).where(SigningKeyEntity.is_active.is_(True))
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def get_all_keys(
    session: AsyncSession,
) -> list[SigningKeyEntity]:
    """Return all signing keys (active + rotated) for JWKS."""
    stmt = select(SigningKeyEntity).order_by(SigningKeyEntity.created_at.desc())
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def store_key(
    session: AsyncSession, entity: SigningKeyEntity
) -> SigningKeyEntity:
    """Persist a new signing key."""
    session.add(entity)
    await session.flush()
    return entity


async def deactivate_all(session: AsyncSession) -> None:
    """Mark all existing keys as inactive (pre-rotation)."""
    stmt = (
        update(SigningKeyEntity)
        .where(SigningKeyEntity.is_active.is_(True))
        .values(is_active=False)
    )
    await session.execute(stmt)
    await session.flush()


async def ensure_active_key(session: AsyncSession, fernet_key: str) -> SigningKeyEntity:
    """Return the active key, or generate one if none exists."""
    active = await get_active_key(session)
    if active is not None:
        return active

    keypair = generate_rsa_keypair()
    encrypted_private = encrypt_private_key(keypair.private_key_pem, fernet_key)
    entity = SigningKeyEntity(
        kid=keypair.kid,
        algorithm="RS256",
        private_key_pem=encrypted_private,
        public_key_pem=keypair.public_key_pem,
        is_active=True,
    )
    return await store_key(session, entity)
