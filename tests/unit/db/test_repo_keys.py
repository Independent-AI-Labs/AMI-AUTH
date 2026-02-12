"""Tests for signing key repository operations."""

from cryptography.fernet import Fernet
from sqlalchemy.ext.asyncio import AsyncSession

from ami.crypto.keys import encrypt_private_key, generate_rsa_keypair
from ami.db.models_keys import SigningKeyEntity
from ami.db.repo_keys import (
    deactivate_all,
    ensure_active_key,
    get_active_key,
    get_all_keys,
    store_key,
)

FERNET_KEY = Fernet.generate_key().decode()


async def _insert_key(
    session: AsyncSession, *, active: bool = True
) -> SigningKeyEntity:
    kp = generate_rsa_keypair()
    entity = SigningKeyEntity(
        kid=kp.kid,
        algorithm="RS256",
        private_key_pem=encrypt_private_key(kp.private_key_pem, FERNET_KEY),
        public_key_pem=kp.public_key_pem,
        is_active=active,
    )
    session.add(entity)
    await session.flush()
    return entity


class TestGetActiveKey:
    """Tests for get_active_key."""

    async def test_returns_active_key(self, db_session: AsyncSession) -> None:
        inserted = await _insert_key(db_session, active=True)
        result = await get_active_key(db_session)
        assert result is not None
        assert result.kid == inserted.kid

    async def test_returns_none_when_no_active(self, db_session: AsyncSession) -> None:
        await _insert_key(db_session, active=False)
        result = await get_active_key(db_session)
        assert result is None

    async def test_returns_none_when_empty(self, db_session: AsyncSession) -> None:
        result = await get_active_key(db_session)
        assert result is None


class TestGetAllKeys:
    """Tests for get_all_keys."""

    async def test_returns_all_keys(self, db_session: AsyncSession) -> None:
        await _insert_key(db_session, active=True)
        await _insert_key(db_session, active=False)
        results = await get_all_keys(db_session)
        assert len(results) == 2

    async def test_empty_when_no_keys(self, db_session: AsyncSession) -> None:
        results = await get_all_keys(db_session)
        assert results == []


class TestStoreKey:
    """Tests for store_key."""

    async def test_persists_key(self, db_session: AsyncSession) -> None:
        kp = generate_rsa_keypair()
        entity = SigningKeyEntity(
            kid=kp.kid,
            algorithm="RS256",
            private_key_pem=encrypt_private_key(kp.private_key_pem, FERNET_KEY),
            public_key_pem=kp.public_key_pem,
            is_active=True,
        )
        stored = await store_key(db_session, entity)
        assert stored.kid == kp.kid
        fetched = await get_active_key(db_session)
        assert fetched is not None
        assert fetched.kid == kp.kid


class TestDeactivateAll:
    """Tests for deactivate_all."""

    async def test_deactivates_active_keys(self, db_session: AsyncSession) -> None:
        await _insert_key(db_session, active=True)
        await _insert_key(db_session, active=True)
        await deactivate_all(db_session)
        active = await get_active_key(db_session)
        assert active is None
        all_keys = await get_all_keys(db_session)
        assert len(all_keys) == 2


class TestEnsureActiveKey:
    """Tests for ensure_active_key."""

    async def test_creates_key_when_none(self, db_session: AsyncSession) -> None:
        key = await ensure_active_key(db_session, FERNET_KEY)
        assert key.is_active is True
        assert key.kid

    async def test_returns_existing_active_key(self, db_session: AsyncSession) -> None:
        existing = await _insert_key(db_session, active=True)
        key = await ensure_active_key(db_session, FERNET_KEY)
        assert key.kid == existing.kid
