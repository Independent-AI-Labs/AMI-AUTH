"""FastAPI dependency injection for internal API authentication."""

from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ami.core.settings import AuthSettings

_security = HTTPBearer()


def _load_settings() -> AuthSettings:
    return AuthSettings()


async def require_internal_token(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(_security)],
    settings: Annotated[AuthSettings, Depends(_load_settings)],
) -> str:
    """Verify the DATAOPS_INTERNAL_TOKEN Bearer token."""
    expected = settings.dataops_internal_token
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    if credentials.credentials != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    return credentials.credentials
