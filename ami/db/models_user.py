"""SQLAlchemy model for the users table."""

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from ami.db.base import BaseEntity


class UserEntity(BaseEntity):
    """Represents a user in the OIDC identity provider."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(48), primary_key=True)
    email: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    image: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)

    roles: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    groups: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    tenant_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    user_metadata: Mapped[str | None] = mapped_column("metadata", JSON, nullable=True)

    login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_login: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
