"""Tests for authorization code DB operations (create + redeem)."""

import hashlib
from base64 import urlsafe_b64encode

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from ami.db.models_oauth import OAuthClientEntity
from ami.db.models_user import UserEntity
from ami.oidc.auth_code import (
    AuthCodeParams,
    create_authorization_code,
    redeem_authorization_code,
)

CLIENT_ID = "ac-client-1"
USER_ID = "ac-user-1"
REDIRECT_URI = "http://localhost:3000/cb"
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"


def _make_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@pytest.fixture
async def seed_data(db_session: AsyncSession) -> None:
    """Insert client + user needed for FK constraints."""
    db_session.add(
        OAuthClientEntity(
            id=CLIENT_ID,
            client_name="AC App",
            redirect_uris=[REDIRECT_URI],
        )
    )
    db_session.add(UserEntity(id=USER_ID, email="ac@example.com"))
    await db_session.flush()


class TestCreateAuthorizationCode:
    """Tests for create_authorization_code."""

    async def test_creates_code(
        self, db_session: AsyncSession, seed_data: None
    ) -> None:
        code = await create_authorization_code(
            db_session,
            AuthCodeParams(
                client_id=CLIENT_ID,
                user_id=USER_ID,
                redirect_uri=REDIRECT_URI,
                scope="openid",
                nonce="n1",
                code_challenge=_make_challenge(VERIFIER),
            ),
        )
        assert len(code) > 20
        assert isinstance(code, str)

    async def test_codes_are_unique(
        self, db_session: AsyncSession, seed_data: None
    ) -> None:
        codes = set()
        for _ in range(10):
            c = await create_authorization_code(
                db_session,
                AuthCodeParams(
                    client_id=CLIENT_ID,
                    user_id=USER_ID,
                    redirect_uri=REDIRECT_URI,
                    scope="openid",
                    nonce=None,
                    code_challenge=_make_challenge(VERIFIER),
                ),
            )
            codes.add(c)
        assert len(codes) == 10


class TestRedeemAuthorizationCode:
    """Tests for redeem_authorization_code."""

    async def test_valid_redemption(
        self, db_session: AsyncSession, seed_data: None
    ) -> None:
        challenge = _make_challenge(VERIFIER)
        code = await create_authorization_code(
            db_session,
            AuthCodeParams(
                client_id=CLIENT_ID,
                user_id=USER_ID,
                redirect_uri=REDIRECT_URI,
                scope="openid",
                nonce="nonce1",
                code_challenge=challenge,
            ),
        )
        entity = await redeem_authorization_code(
            db_session,
            code=code,
            client_id=CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            code_verifier=VERIFIER,
        )
        assert entity is not None
        assert entity.user_id == USER_ID
        assert entity.scope == "openid"
        assert entity.nonce == "nonce1"

    async def test_reuse_returns_none(
        self, db_session: AsyncSession, seed_data: None
    ) -> None:
        challenge = _make_challenge(VERIFIER)
        code = await create_authorization_code(
            db_session,
            AuthCodeParams(
                client_id=CLIENT_ID,
                user_id=USER_ID,
                redirect_uri=REDIRECT_URI,
                scope="openid",
                nonce=None,
                code_challenge=challenge,
            ),
        )
        await redeem_authorization_code(
            db_session,
            code=code,
            client_id=CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            code_verifier=VERIFIER,
        )
        second = await redeem_authorization_code(
            db_session,
            code=code,
            client_id=CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            code_verifier=VERIFIER,
        )
        assert second is None

    async def test_wrong_verifier_returns_none(
        self, db_session: AsyncSession, seed_data: None
    ) -> None:
        challenge = _make_challenge(VERIFIER)
        code = await create_authorization_code(
            db_session,
            AuthCodeParams(
                client_id=CLIENT_ID,
                user_id=USER_ID,
                redirect_uri=REDIRECT_URI,
                scope="openid",
                nonce=None,
                code_challenge=challenge,
            ),
        )
        result = await redeem_authorization_code(
            db_session,
            code=code,
            client_id=CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            code_verifier="wrong-verifier",
        )
        assert result is None

    async def test_wrong_client_returns_none(
        self, db_session: AsyncSession, seed_data: None
    ) -> None:
        challenge = _make_challenge(VERIFIER)
        code = await create_authorization_code(
            db_session,
            AuthCodeParams(
                client_id=CLIENT_ID,
                user_id=USER_ID,
                redirect_uri=REDIRECT_URI,
                scope="openid",
                nonce=None,
                code_challenge=challenge,
            ),
        )
        result = await redeem_authorization_code(
            db_session,
            code=code,
            client_id="other-client",
            redirect_uri=REDIRECT_URI,
            code_verifier=VERIFIER,
        )
        assert result is None

    async def test_wrong_redirect_returns_none(
        self, db_session: AsyncSession, seed_data: None
    ) -> None:
        challenge = _make_challenge(VERIFIER)
        code = await create_authorization_code(
            db_session,
            AuthCodeParams(
                client_id=CLIENT_ID,
                user_id=USER_ID,
                redirect_uri=REDIRECT_URI,
                scope="openid",
                nonce=None,
                code_challenge=challenge,
            ),
        )
        result = await redeem_authorization_code(
            db_session,
            code=code,
            client_id=CLIENT_ID,
            redirect_uri="http://evil.com/cb",
            code_verifier=VERIFIER,
        )
        assert result is None

    async def test_nonexistent_code_returns_none(
        self, db_session: AsyncSession, seed_data: None
    ) -> None:
        result = await redeem_authorization_code(
            db_session,
            code="no-such-code",
            client_id=CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            code_verifier=VERIFIER,
        )
        assert result is None

    async def test_expired_code_returns_none(
        self, db_session: AsyncSession, seed_data: None
    ) -> None:
        challenge = _make_challenge(VERIFIER)
        code = await create_authorization_code(
            db_session,
            AuthCodeParams(
                client_id=CLIENT_ID,
                user_id=USER_ID,
                redirect_uri=REDIRECT_URI,
                scope="openid",
                nonce=None,
                code_challenge=challenge,
                ttl_seconds=-1,
            ),
        )
        result = await redeem_authorization_code(
            db_session,
            code=code,
            client_id=CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            code_verifier=VERIFIER,
        )
        assert result is None
