"""OIDC token endpoint."""

from typing import Annotated

from fastapi import APIRouter, Depends, Form
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import JSONResponse

from ami.core.settings import AuthSettings
from ami.crypto.jwt_manager import JWTManager
from ami.crypto.keys import decrypt_private_key
from ami.db.engine import get_session
from ami.db.repo_keys import get_active_key
from ami.db.repo_user import get_user_by_id
from ami.oidc.auth_code import redeem_authorization_code
from ami.oidc.token_service import issue_tokens, refresh_tokens
from ami.oidc.types import TokenIssuanceParams, TokenResponse

router = APIRouter()

HTTP_BAD_REQUEST = 400


class _TokenForm(BaseModel):
    """Bundle form fields for the token endpoint."""

    grant_type: str
    code: str | None = None
    redirect_uri: str | None = None
    client_id: str | None = None
    code_verifier: str | None = None
    refresh_token: str | None = None


def _load_settings() -> AuthSettings:
    return AuthSettings()


async def _build_jwt_manager(
    db: AsyncSession, settings: AuthSettings
) -> JWTManager | None:
    """Build a JWTManager from the active signing key."""
    key = await get_active_key(db)
    if key is None:
        return None
    private_pem = decrypt_private_key(
        key.private_key_pem, settings.signing_key_encryption_key
    )
    return JWTManager(
        private_key_pem=private_pem,
        public_key_pem=key.public_key_pem,
        kid=key.kid,
        issuer=settings.issuer_url,
    )


@router.post("/oauth/token", response_model=None)
async def token_endpoint(
    db: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[AuthSettings, Depends(_load_settings)],
    form: Annotated[_TokenForm, Form()],
) -> TokenResponse | JSONResponse:
    """POST /oauth/token -- exchange auth code or refresh token."""
    jwt_mgr = await _build_jwt_manager(db, settings)
    if jwt_mgr is None:
        return JSONResponse(
            {"error": "server_error", "error_description": "No signing key"},
            status_code=500,
        )

    if form.grant_type == "authorization_code":
        return await _handle_auth_code(db, settings, jwt_mgr, form)
    if form.grant_type == "refresh_token":
        return await _handle_refresh(db, settings, jwt_mgr, form)

    return JSONResponse(
        {"error": "unsupported_grant_type"},
        status_code=HTTP_BAD_REQUEST,
    )


async def _handle_auth_code(
    db: AsyncSession,
    settings: AuthSettings,
    jwt_mgr: JWTManager,
    form: _TokenForm,
) -> TokenResponse | JSONResponse:
    """Handle grant_type=authorization_code."""
    if not form.code or not form.redirect_uri or not form.client_id:
        return JSONResponse({"error": "invalid_request"}, status_code=HTTP_BAD_REQUEST)
    if not form.code_verifier:
        return JSONResponse({"error": "invalid_request"}, status_code=HTTP_BAD_REQUEST)

    auth_code = await redeem_authorization_code(
        db,
        code=form.code,
        client_id=form.client_id,
        redirect_uri=form.redirect_uri,
        code_verifier=form.code_verifier,
    )
    if auth_code is None:
        return JSONResponse({"error": "invalid_grant"}, status_code=HTTP_BAD_REQUEST)

    user = await get_user_by_id(db, auth_code.user_id)
    params = TokenIssuanceParams(
        client_id=form.client_id,
        user_id=auth_code.user_id,
        scope=auth_code.scope,
        email=user.email if user else "",
        name=user.name if user else None,
        nonce=auth_code.nonce,
        jwt_mgr=jwt_mgr,
        access_ttl=settings.access_token_ttl,
        refresh_ttl=settings.refresh_token_ttl,
    )
    return await issue_tokens(db, params)


async def _handle_refresh(
    db: AsyncSession,
    settings: AuthSettings,
    jwt_mgr: JWTManager,
    form: _TokenForm,
) -> TokenResponse | JSONResponse:
    """Handle grant_type=refresh_token."""
    if not form.refresh_token or not form.client_id:
        return JSONResponse({"error": "invalid_request"}, status_code=HTTP_BAD_REQUEST)

    params = TokenIssuanceParams(
        client_id=form.client_id,
        user_id="",
        scope="",
        email="",
        name=None,
        jwt_mgr=jwt_mgr,
        access_ttl=settings.access_token_ttl,
        refresh_ttl=settings.refresh_token_ttl,
    )
    result = await refresh_tokens(db, params, form.refresh_token)
    if result is None:
        return JSONResponse({"error": "invalid_grant"}, status_code=HTTP_BAD_REQUEST)
    return result
