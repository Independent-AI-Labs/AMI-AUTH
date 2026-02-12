"""DataOps-facing API endpoints for the TypeScript auth client."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from ami.api.deps import require_internal_token
from ami.api.schemas import (
    AuthenticatedUserResponse,
    CreateUserPayload,
    CredentialsPayload,
    ProviderCatalogResponse,
    UserEnvelope,
    VerifyResponse,
)
from ami.db.engine import get_session
from ami.db.models_user import UserEntity
from ami.db.repo_user import (
    UserUpsertData,
    get_user_by_email,
    get_user_by_id,
    upsert_user,
    verify_credentials,
)

router = APIRouter(prefix="/auth", tags=["dataops"])

DbSession = Annotated[AsyncSession, Depends(get_session)]
InternalToken = Annotated[str, Depends(require_internal_token)]


def _user_to_response(entity: UserEntity) -> AuthenticatedUserResponse:
    """Convert a UserEntity to an API response."""
    return AuthenticatedUserResponse(
        id=entity.id,
        email=entity.email,
        name=entity.name,
        image=entity.image,
        roles=entity.roles or [],
        groups=entity.groups or [],
        tenant_id=entity.tenant_id,
    )


@router.post("/verify")
async def verify_user_credentials(
    payload: CredentialsPayload,
    db: DbSession,
    _token: InternalToken,
) -> VerifyResponse:
    """POST /auth/verify -- verify email+password credentials."""
    user = await verify_credentials(db, payload.email, payload.password)
    if user is None:
        return VerifyResponse(user=None, reason="invalid_credentials")
    return VerifyResponse(user=_user_to_response(user))


@router.get("/users/by-email")
async def lookup_user_by_email(
    email: Annotated[str, Query()],
    db: DbSession,
    _token: InternalToken,
) -> UserEnvelope:
    """GET /auth/users/by-email?email=... -- lookup user by email."""
    user = await get_user_by_email(db, email)
    if user is None:
        return UserEnvelope(user=None)
    return UserEnvelope(user=_user_to_response(user))


@router.get("/users/{user_id}")
async def lookup_user_by_id(
    user_id: str,
    db: DbSession,
    _token: InternalToken,
) -> UserEnvelope:
    """GET /auth/users/{id} -- lookup user by ID."""
    user = await get_user_by_id(db, user_id)
    if user is None:
        return UserEnvelope(user=None)
    return UserEnvelope(user=_user_to_response(user))


@router.post("/users")
async def create_or_update_user(
    payload: CreateUserPayload,
    db: DbSession,
    _token: InternalToken,
) -> UserEnvelope:
    """POST /auth/users -- upsert a user record."""
    data = UserUpsertData(
        email=payload.email,
        user_id=payload.id,
        name=payload.name,
        image=payload.image,
        roles=payload.roles,
        groups=payload.groups,
        tenant_id=payload.tenant_id,
    )
    user = await upsert_user(db, data)
    return UserEnvelope(user=_user_to_response(user))


@router.get("/providers/catalog")
async def get_provider_catalog(
    _token: InternalToken,
) -> ProviderCatalogResponse:
    """GET /auth/providers/catalog -- return configured OAuth providers."""
    return ProviderCatalogResponse(providers=[])
