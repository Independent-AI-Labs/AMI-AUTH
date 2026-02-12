"""OIDC authorization endpoint."""

from typing import Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Query
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import JSONResponse

from ami.db.engine import get_session
from ami.db.repo_oauth import get_client, validate_redirect_uri
from ami.oidc.auth_code import AuthCodeParams, create_authorization_code

router = APIRouter()

HTTP_BAD_REQUEST = 400


class _AuthQuery(BaseModel):
    """Bundle query params for the authorize endpoint."""

    client_id: str
    redirect_uri: str
    response_type: str
    scope: str = "openid"
    state: str | None = None
    nonce: str | None = None
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    user_id: str | None = None


def _validate_request(q: _AuthQuery) -> JSONResponse | None:
    """Return an error response if the request is invalid, else None."""
    if q.response_type != "code":
        return JSONResponse(
            {"error": "unsupported_response_type"},
            status_code=HTTP_BAD_REQUEST,
        )
    if not q.code_challenge:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "PKCE required"},
            status_code=HTTP_BAD_REQUEST,
        )
    if q.code_challenge_method and q.code_challenge_method != "S256":
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Only S256"},
            status_code=HTTP_BAD_REQUEST,
        )
    if not q.user_id:
        return JSONResponse(
            {"error": "login_required"},
            status_code=HTTP_BAD_REQUEST,
        )
    return None


@router.get("/oauth/authorize", response_model=None)
async def authorize(
    db: Annotated[AsyncSession, Depends(get_session)],
    q: Annotated[_AuthQuery, Query()],
) -> RedirectResponse | JSONResponse:
    """GET /oauth/authorize -- OIDC authorization endpoint."""
    error = _validate_request(q)
    if error is not None:
        return error

    client = await get_client(db, q.client_id)
    if client is None:
        return JSONResponse({"error": "invalid_client"}, status_code=HTTP_BAD_REQUEST)

    if not validate_redirect_uri(client, q.redirect_uri):
        return JSONResponse(
            {"error": "invalid_redirect_uri"}, status_code=HTTP_BAD_REQUEST
        )

    params = AuthCodeParams(
        client_id=q.client_id,
        user_id=q.user_id or "",
        redirect_uri=q.redirect_uri,
        scope=q.scope,
        nonce=q.nonce,
        code_challenge=q.code_challenge or "",
    )
    code = await create_authorization_code(db, params)

    redir_params = {"code": code}
    if q.state:
        redir_params["state"] = q.state
    return RedirectResponse(
        url=f"{q.redirect_uri}?{urlencode(redir_params)}",
        status_code=302,
    )
