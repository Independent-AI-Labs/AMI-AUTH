"""JWT creation and verification using RS256."""

from datetime import UTC, datetime, timedelta

import jwt
from jwt.types import Options

from ami.crypto.types import DecodedToken, TokenClaims

ACCESS_TOKEN_DEFAULT_TTL = 3600
ID_TOKEN_DEFAULT_TTL = 3600


class JWTManager:
    """Creates and verifies RS256-signed JWT tokens."""

    def __init__(
        self,
        private_key_pem: str,
        public_key_pem: str,
        kid: str,
        issuer: str,
    ) -> None:
        self._private_key_pem = private_key_pem
        self._public_key_pem = public_key_pem
        self._kid = kid
        self._issuer = issuer

    def create_access_token(self, claims: TokenClaims) -> str:
        """Create a signed RS256 JWT access token."""
        now = datetime.now(UTC)
        ttl = claims.ttl_seconds or ACCESS_TOKEN_DEFAULT_TTL
        payload = {
            "iss": self._issuer,
            "sub": claims.sub,
            "aud": claims.aud,
            "exp": now + timedelta(seconds=ttl),
            "iat": now,
            "scope": claims.scope,
            "email": claims.email,
        }
        if claims.name is not None:
            payload["name"] = claims.name
        return jwt.encode(
            payload,
            self._private_key_pem,
            algorithm="RS256",
            headers={"kid": self._kid},
        )

    def create_id_token(self, claims: TokenClaims) -> str:
        """Create a signed RS256 id_token per OIDC Core 1.0."""
        now = datetime.now(UTC)
        ttl = claims.ttl_seconds or ID_TOKEN_DEFAULT_TTL
        payload = {
            "iss": self._issuer,
            "sub": claims.sub,
            "aud": claims.aud,
            "exp": now + timedelta(seconds=ttl),
            "iat": now,
            "email": claims.email,
        }
        if claims.name is not None:
            payload["name"] = claims.name
        if claims.nonce is not None:
            payload["nonce"] = claims.nonce
        return jwt.encode(
            payload,
            self._private_key_pem,
            algorithm="RS256",
            headers={"kid": self._kid},
        )

    def verify_token(self, token: str, audience: str | None = None) -> DecodedToken:
        """Verify and decode an RS256 JWT token."""
        opts: Options = {}
        if audience is None:
            opts["verify_aud"] = False
        raw = jwt.decode(
            token,
            self._public_key_pem,
            algorithms=["RS256"],
            issuer=self._issuer,
            audience=audience,
            options=opts,
        )
        return DecodedToken.model_validate(raw)
