"""OIDC discovery and JWKS endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, Response
from sqlalchemy.ext.asyncio import AsyncSession

from ami.core.settings import AuthSettings
from ami.crypto.keys import pem_to_jwk_entry
from ami.crypto.types import JWKSResponse
from ami.db.engine import get_session
from ami.db.repo_keys import get_all_keys
from ami.oidc.discovery import DiscoveryDocument, build_discovery

router = APIRouter()

JWKS_CACHE_CONTROL = "public, max-age=3600"


def _load_settings() -> AuthSettings:
    return AuthSettings()


@router.get("/.well-known/openid-configuration")
async def openid_configuration(
    settings: Annotated[AuthSettings, Depends(_load_settings)],
) -> DiscoveryDocument:
    """OpenID Connect Discovery 1.0."""
    return build_discovery(settings)


@router.get("/oauth/jwks")
async def jwks(
    response: Response,
    db: Annotated[AsyncSession, Depends(get_session)],
) -> JWKSResponse:
    """JSON Web Key Set endpoint."""
    keys = await get_all_keys(db)
    entries = [pem_to_jwk_entry(k.public_key_pem, k.kid) for k in keys]
    response.headers["Cache-Control"] = JWKS_CACHE_CONTROL
    return JWKSResponse(keys=entries)
