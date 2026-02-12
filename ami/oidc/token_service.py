"""OAuth token issuance, refresh, and revocation."""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

import uuid_utils
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ami.crypto.types import TokenClaims
from ami.db.models_oauth import OAuthTokenEntity
from ami.oidc.types import TokenIssuanceParams, TokenResponse


def generate_refresh_token() -> str:
    """Generate a cryptographically random opaque refresh token."""
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    """SHA-256 hash a token for database storage."""
    return hashlib.sha256(token.encode()).hexdigest()


async def issue_tokens(
    session: AsyncSession, params: TokenIssuanceParams
) -> TokenResponse:
    """Create and store an access + refresh token pair."""
    claims = TokenClaims(
        sub=params.user_id,
        aud=params.client_id,
        scope=params.scope,
        email=params.email,
        name=params.name,
        nonce=params.nonce,
        ttl_seconds=params.access_ttl,
    )
    access_jwt = params.jwt_mgr.create_access_token(claims)
    id_token = params.jwt_mgr.create_id_token(claims)
    refresh = generate_refresh_token()
    now = datetime.now(UTC)

    entity = OAuthTokenEntity(
        id=str(uuid_utils.uuid7()),
        client_id=params.client_id,
        user_id=params.user_id,
        access_token_hash=hash_token(access_jwt),
        refresh_token_hash=hash_token(refresh),
        scope=params.scope,
        token_type="Bearer",
        expires_at=now + timedelta(seconds=params.access_ttl),
        refresh_expires_at=now + timedelta(seconds=params.refresh_ttl),
        revoked=False,
    )
    session.add(entity)
    await session.flush()

    return TokenResponse(
        access_token=access_jwt,
        token_type="Bearer",
        expires_in=params.access_ttl,
        refresh_token=refresh,
        id_token=id_token,
        scope=params.scope,
    )


async def refresh_tokens(
    session: AsyncSession, params: TokenIssuanceParams, refresh_token: str
) -> TokenResponse | None:
    """Validate a refresh token and issue a new token pair."""
    token_hash = hash_token(refresh_token)
    stmt = select(OAuthTokenEntity).where(
        OAuthTokenEntity.refresh_token_hash == token_hash,
        OAuthTokenEntity.client_id == params.client_id,
        OAuthTokenEntity.revoked.is_(False),
    )
    result = await session.execute(stmt)
    entity = result.scalar_one_or_none()

    if entity is None:
        return None
    if entity.refresh_expires_at:
        now = datetime.now(UTC)
        expiry = entity.refresh_expires_at
        if expiry.tzinfo is None:
            now = now.replace(tzinfo=None)
        if now > expiry:
            return None

    entity.revoked = True
    await session.flush()

    params_copy = params.model_copy(
        update={"scope": entity.scope, "user_id": entity.user_id or ""}
    )
    return await issue_tokens(session, params_copy)


async def revoke_token(session: AsyncSession, *, token: str) -> bool:
    """Revoke a token by its raw value (access or refresh)."""
    token_hash = hash_token(token)

    stmt = select(OAuthTokenEntity).where(
        OAuthTokenEntity.access_token_hash == token_hash,
        OAuthTokenEntity.revoked.is_(False),
    )
    result = await session.execute(stmt)
    entity = result.scalar_one_or_none()

    if entity is None:
        stmt = select(OAuthTokenEntity).where(
            OAuthTokenEntity.refresh_token_hash == token_hash,
            OAuthTokenEntity.revoked.is_(False),
        )
        result = await session.execute(stmt)
        entity = result.scalar_one_or_none()

    if entity is None:
        return True

    entity.revoked = True
    await session.flush()
    return True
