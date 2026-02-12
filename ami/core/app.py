"""FastAPI application factory for AMI-AUTH OIDC server."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ami.api.router_dataops import router as dataops_router
from ami.core.settings import AuthSettings
from ami.oidc.routes_authorize import router as authorize_router
from ami.oidc.routes_discovery import router as discovery_router
from ami.oidc.routes_revoke import router as revoke_router
from ami.oidc.routes_token import router as token_router
from ami.oidc.routes_userinfo import router as userinfo_router


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""
    settings = AuthSettings()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield

    app = FastAPI(
        title="AMI-AUTH OIDC Provider",
        version="0.1.0",
        lifespan=lifespan,
    )

    origins = settings.get_cors_origin_list()
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type"],
        )

    app.include_router(dataops_router)
    app.include_router(discovery_router)
    app.include_router(authorize_router)
    app.include_router(token_router)
    app.include_router(userinfo_router)
    app.include_router(revoke_router)

    return app
