"""Tests for OIDC discovery document."""

from ami.core.settings import AuthSettings
from ami.oidc.discovery import build_discovery


class TestBuildDiscovery:
    """Tests for discovery document generation."""

    def test_has_all_required_fields(self) -> None:
        settings = AuthSettings(issuer_url="https://auth.example.com")
        doc = build_discovery(settings)
        assert doc.issuer == "https://auth.example.com"
        assert doc.authorization_endpoint.endswith("/oauth/authorize")
        assert doc.token_endpoint.endswith("/oauth/token")
        assert doc.userinfo_endpoint.endswith("/oauth/userinfo")
        assert doc.jwks_uri.endswith("/oauth/jwks")
        assert doc.revocation_endpoint.endswith("/oauth/revoke")

    def test_supported_values(self) -> None:
        settings = AuthSettings(issuer_url="https://auth.example.com")
        doc = build_discovery(settings)
        assert "code" in doc.response_types_supported
        assert "authorization_code" in doc.grant_types_supported
        assert "RS256" in doc.id_token_signing_alg_values_supported
        assert "S256" in doc.code_challenge_methods_supported
        assert "openid" in doc.scopes_supported

    def test_trailing_slash_stripped(self) -> None:
        settings = AuthSettings(issuer_url="https://auth.example.com/")
        doc = build_discovery(settings)
        assert doc.issuer == "https://auth.example.com"
