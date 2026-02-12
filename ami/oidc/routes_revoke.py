"""OAuth token revocation endpoint."""

from typing import Annotated

from fastapi import APIRouter, Depends, Form
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import JSONResponse

from ami.db.engine import get_session
from ami.oidc.token_service import revoke_token

router = APIRouter()


@router.post("/oauth/revoke")
async def revoke(
    db: Annotated[AsyncSession, Depends(get_session)],
    token: Annotated[str, Form()],
) -> JSONResponse:
    """POST /oauth/revoke -- revoke a token (idempotent per RFC 7009)."""
    await revoke_token(db, token=token)
    return JSONResponse({}, status_code=200)
