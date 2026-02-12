"""OpenID Connect Discovery endpoint builder."""

from pydantic import BaseModel

from ami.core.settings import AuthSettings


class DiscoveryDocument(BaseModel):
    """OIDC .well-known/openid-configuration response."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    revocation_endpoint: str
    response_types_supported: list[str]
    grant_types_supported: list[str]
    subject_types_supported: list[str]
    id_token_signing_alg_values_supported: list[str]
    scopes_supported: list[str]
    token_endpoint_auth_methods_supported: list[str]
    code_challenge_methods_supported: list[str]


def build_discovery(settings: AuthSettings) -> DiscoveryDocument:
    """Build the OIDC discovery document from settings."""
    issuer = settings.issuer_url.rstrip("/")
    return DiscoveryDocument(
        issuer=issuer,
        authorization_endpoint=f"{issuer}/oauth/authorize",
        token_endpoint=f"{issuer}/oauth/token",
        userinfo_endpoint=f"{issuer}/oauth/userinfo",
        jwks_uri=f"{issuer}/oauth/jwks",
        revocation_endpoint=f"{issuer}/oauth/revoke",
        response_types_supported=["code"],
        grant_types_supported=["authorization_code", "refresh_token"],
        subject_types_supported=["public"],
        id_token_signing_alg_values_supported=["RS256"],
        scopes_supported=["openid", "profile", "email"],
        token_endpoint_auth_methods_supported=["client_secret_post"],
        code_challenge_methods_supported=["S256"],
    )
