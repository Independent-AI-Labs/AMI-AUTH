"""OIDC userinfo endpoint."""

from typing import Annotated

import jwt
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import JSONResponse

from ami.core.settings import AuthSettings
from ami.crypto.jwt_manager import JWTManager
from ami.crypto.keys import decrypt_private_key
from ami.db.engine import get_session
from ami.db.repo_keys import get_active_key
from ami.db.repo_user import get_user_by_id

router = APIRouter()

HTTP_UNAUTHORIZED = 401


def _load_settings() -> AuthSettings:
    return AuthSettings()


def _extract_bearer(request: Request) -> str | None:
    """Extract Bearer token from Authorization header."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer ") :]
    return None


@router.get("/oauth/userinfo")
async def userinfo(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[AuthSettings, Depends(_load_settings)],
) -> JSONResponse:
    """GET /oauth/userinfo -- return claims for the authenticated user."""
    token = _extract_bearer(request)
    if not token:
        return JSONResponse(
            {"error": "invalid_token"},
            status_code=HTTP_UNAUTHORIZED,
        )

    key = await get_active_key(db)
    if key is None:
        return JSONResponse(
            {"error": "server_error"},
            status_code=500,
        )

    private_pem = decrypt_private_key(
        key.private_key_pem, settings.signing_key_encryption_key
    )
    jwt_mgr = JWTManager(
        private_key_pem=private_pem,
        public_key_pem=key.public_key_pem,
        kid=key.kid,
        issuer=settings.issuer_url,
    )

    try:
        claims = jwt_mgr.verify_token(token)
    except (jwt.PyJWTError, ValueError, KeyError):
        return JSONResponse(
            {"error": "invalid_token"},
            status_code=HTTP_UNAUTHORIZED,
        )

    user = await get_user_by_id(db, claims.sub)

    body: object = {
        "sub": claims.sub,
        "email": claims.email,
        "name": claims.name,
    }
    if user is not None:
        body = {
            "sub": claims.sub,
            "email": claims.email,
            "name": claims.name,
            "roles": user.roles or [],
            "groups": user.groups or [],
            "tenant_id": user.tenant_id,
        }

    return JSONResponse(body)
