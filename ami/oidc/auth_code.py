"""Authorization code creation and redemption with PKCE."""

import hashlib
import secrets
from base64 import urlsafe_b64encode
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ami.db.models_oauth import AuthorizationCodeEntity

AUTH_CODE_TTL_SECONDS = 60


class AuthCodeParams(BaseModel):
    """Parameters for creating an authorization code."""

    client_id: str
    user_id: str
    redirect_uri: str
    scope: str
    nonce: str | None = None
    code_challenge: str
    ttl_seconds: int = AUTH_CODE_TTL_SECONDS


def generate_code() -> str:
    """Generate a cryptographically random authorization code."""
    return secrets.token_urlsafe(32)


def verify_pkce(code_verifier: str, code_challenge: str) -> bool:
    """Verify S256 PKCE: SHA256(verifier) == challenge."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return secrets.compare_digest(computed, code_challenge)


async def create_authorization_code(
    session: AsyncSession, params: AuthCodeParams
) -> str:
    """Create and store a new authorization code."""
    code = generate_code()
    entity = AuthorizationCodeEntity(
        code=code,
        client_id=params.client_id,
        user_id=params.user_id,
        redirect_uri=params.redirect_uri,
        scope=params.scope,
        nonce=params.nonce,
        code_challenge=params.code_challenge,
        code_challenge_method="S256",
        expires_at=datetime.now(UTC) + timedelta(seconds=params.ttl_seconds),
        used=False,
    )
    session.add(entity)
    await session.flush()
    return code


def _is_code_invalid(
    entity: AuthorizationCodeEntity,
    client_id: str,
    redirect_uri: str,
    code_verifier: str,
) -> bool:
    """Return True if the code cannot be redeemed."""
    if entity.used or entity.client_id != client_id:
        return True
    if entity.redirect_uri != redirect_uri:
        return True
    now = datetime.now(UTC)
    expiry = entity.expires_at
    if expiry.tzinfo is None:
        now = now.replace(tzinfo=None)
    if now > expiry:
        return True
    return not verify_pkce(code_verifier, entity.code_challenge)


async def redeem_authorization_code(
    session: AsyncSession,
    *,
    code: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str,
) -> AuthorizationCodeEntity | None:
    """Redeem an auth code. Returns None if invalid."""
    stmt = select(AuthorizationCodeEntity).where(AuthorizationCodeEntity.code == code)
    result = await session.execute(stmt)
    entity = result.scalar_one_or_none()

    if entity is None:
        return None
    if _is_code_invalid(entity, client_id, redirect_uri, code_verifier):
        return None

    entity.used = True
    await session.flush()
    return entity
