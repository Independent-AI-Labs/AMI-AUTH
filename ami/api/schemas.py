"""Pydantic schemas matching the TypeScript API contract."""

from pydantic import BaseModel, ConfigDict, EmailStr, Field


def _to_camel(name: str) -> str:
    """Convert snake_case to camelCase for JSON serialization."""
    parts = name.split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


class AuthenticatedUserResponse(BaseModel):
    """Mirrors TypeScript AuthenticatedUser type."""

    model_config = ConfigDict(
        from_attributes=True,
        alias_generator=_to_camel,
        populate_by_name=True,
    )

    id: str
    email: str
    name: str | None = None
    image: str | None = None
    roles: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)
    tenant_id: str | None = None


class UserEnvelope(BaseModel):
    """Wraps a single user response: {user: ... | null}."""

    user: AuthenticatedUserResponse | None = None


class CredentialsPayload(BaseModel):
    """Request body for POST /auth/verify."""

    email: EmailStr
    password: str


class VerifyResponse(BaseModel):
    """Response for POST /auth/verify."""

    user: AuthenticatedUserResponse | None = None
    reason: str | None = None


class CreateUserPayload(BaseModel):
    """Request body for POST /auth/users (upsert)."""

    model_config = ConfigDict(
        alias_generator=_to_camel,
        populate_by_name=True,
    )

    id: str | None = None
    email: EmailStr
    name: str | None = None
    image: str | None = None
    roles: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)
    tenant_id: str | None = None


class ProviderCatalogEntry(BaseModel):
    """Mirrors TypeScript OAuthProviderCatalogEntry."""

    model_config = ConfigDict(
        alias_generator=_to_camel,
        populate_by_name=True,
    )

    id: str
    provider_type: str
    mode: str = "oauth"
    client_id: str
    client_secret: str
    display_name: str | None = None
    scopes: list[str] | None = None
    tenant: str | None = None
    well_known: str | None = None


class ProviderCatalogResponse(BaseModel):
    """Response for GET /auth/providers/catalog."""

    providers: list[ProviderCatalogEntry] = Field(default_factory=list)
