"""Type definitions for OIDC token operations."""

from pydantic import BaseModel, ConfigDict

from ami.crypto.jwt_manager import JWTManager


class TokenResponse(BaseModel):
    """OAuth token endpoint response."""

    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: str | None = None
    id_token: str | None = None
    scope: str | None = None


class TokenIssuanceParams(BaseModel):
    """Bundled parameters for token issuance and refresh."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    client_id: str
    user_id: str
    scope: str
    email: str
    name: str | None = None
    nonce: str | None = None
    jwt_mgr: JWTManager
    access_ttl: int = 3600
    refresh_ttl: int = 86400
