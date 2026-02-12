"""Repository for OAuth client operations."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ami.db.models_oauth import OAuthClientEntity


async def get_client(session: AsyncSession, client_id: str) -> OAuthClientEntity | None:
    """Look up an active OAuth client by ID."""
    stmt = select(OAuthClientEntity).where(
        OAuthClientEntity.id == client_id,
        OAuthClientEntity.is_active.is_(True),
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


def validate_redirect_uri(client: OAuthClientEntity, redirect_uri: str) -> bool:
    """Check that redirect_uri is registered for this client."""
    return redirect_uri in (client.redirect_uris or [])
