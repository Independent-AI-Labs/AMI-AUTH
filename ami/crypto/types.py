"""Type definitions for signing key, JWKS, and JWT operations."""

from pydantic import BaseModel, ConfigDict


class SigningKeyData(BaseModel):
    """An RSA keypair for JWT signing."""

    kid: str
    private_key_pem: str
    public_key_pem: str


class JWKEntry(BaseModel):
    """Single JWK entry in a JWKS response."""

    kty: str = "RSA"
    use: str = "sig"
    alg: str = "RS256"
    kid: str
    n: str
    e: str


class JWKSResponse(BaseModel):
    """JSON Web Key Set response."""

    keys: list[JWKEntry]


class TokenClaims(BaseModel):
    """Claims bundle for JWT token creation."""

    sub: str
    aud: str
    email: str
    name: str | None = None
    scope: str = ""
    nonce: str | None = None
    ttl_seconds: int = 3600


class DecodedToken(BaseModel):
    """Decoded and verified JWT token claims."""

    model_config = ConfigDict(extra="allow")

    sub: str = ""
    iss: str = ""
    aud: str = ""
    scope: str = ""
    email: str = ""
    name: str | None = None
    nonce: str | None = None
