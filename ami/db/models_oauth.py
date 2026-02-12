"""SQLAlchemy models for OAuth clients, authorization codes, and tokens."""

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column

from ami.db.base import BaseEntity


class OAuthClientEntity(BaseEntity):
    """Registered OAuth client (relying party)."""

    __tablename__ = "oauth_clients"

    id: Mapped[str] = mapped_column(String(48), primary_key=True)
    client_secret_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    client_name: Mapped[str] = mapped_column(String(255), nullable=False)
    redirect_uris: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    grant_types: Mapped[list[str]] = mapped_column(
        JSON, nullable=False, default=lambda: ["authorization_code"]
    )
    response_types: Mapped[list[str]] = mapped_column(
        JSON, nullable=False, default=lambda: ["code"]
    )
    scope: Mapped[str] = mapped_column(
        String(1024), nullable=False, default="openid profile email"
    )
    token_endpoint_auth_method: Mapped[str] = mapped_column(
        String(50), nullable=False, default="client_secret_post"
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AuthorizationCodeEntity(BaseEntity):
    """Single-use authorization code for the auth code flow."""

    __tablename__ = "authorization_codes"

    code: Mapped[str] = mapped_column(String(48), primary_key=True)
    client_id: Mapped[str] = mapped_column(
        String(48), ForeignKey("oauth_clients.id"), nullable=False
    )
    user_id: Mapped[str] = mapped_column(
        String(48), ForeignKey("users.id"), nullable=False
    )
    redirect_uri: Mapped[str] = mapped_column(String(2048), nullable=False)
    scope: Mapped[str] = mapped_column(String(1024), nullable=False)
    nonce: Mapped[str | None] = mapped_column(String(255), nullable=True)
    code_challenge: Mapped[str] = mapped_column(String(128), nullable=False)
    code_challenge_method: Mapped[str] = mapped_column(
        String(10), nullable=False, default="S256"
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class OAuthTokenEntity(BaseEntity):
    """Issued access and refresh token pair."""

    __tablename__ = "oauth_tokens"

    id: Mapped[str] = mapped_column(String(48), primary_key=True)
    client_id: Mapped[str] = mapped_column(
        String(48), ForeignKey("oauth_clients.id"), nullable=False
    )
    user_id: Mapped[str | None] = mapped_column(
        String(48), ForeignKey("users.id"), nullable=True
    )
    access_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    refresh_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    scope: Mapped[str] = mapped_column(String(1024), nullable=False)
    token_type: Mapped[str] = mapped_column(
        String(20), nullable=False, default="Bearer"
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    refresh_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
