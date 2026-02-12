"""Declarative base for AMI-AUTH SQLAlchemy models."""

from sqlalchemy.orm import DeclarativeBase


class BaseEntity(DeclarativeBase):
    """Base class for all AMI-AUTH database entities."""
