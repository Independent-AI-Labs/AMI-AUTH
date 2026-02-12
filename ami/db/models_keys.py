"""SQLAlchemy model for JWT signing keys."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from ami.db.base import BaseEntity


class SigningKeyEntity(BaseEntity):
    """RSA signing key for JWT token issuance."""

    __tablename__ = "signing_keys"

    kid: Mapped[str] = mapped_column(String(50), primary_key=True)
    algorithm: Mapped[str] = mapped_column(
        String(10), nullable=False, server_default="RS256"
    )
    private_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    public_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="true"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    rotated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
