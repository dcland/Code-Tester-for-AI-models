"""VaultNote application entrypoint.

Run with a single command:

    uvicorn app.main:app --reload
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI

from app.api.deps import get_container
from app.api.errors import register_error_handlers
from app.api.v1 import admin, analytics, auth, billing, files, notes, workspaces
from app.core.container import Container
from app.middleware.security_headers import SecurityHeadersMiddleware


def create_app(container: Container | None = None) -> FastAPI:
    container = container or Container()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await container.startup()
        yield
        await container.shutdown()

    app = FastAPI(
        title="VaultNote API",
        version="1.0.0",
        description=(
            "End-to-end-encrypted, multi-tenant collaborative workspace platform. "
            "GDPR / CCPA / SOC 2 aware by design."
        ),
        lifespan=lifespan,
        # Disable the interactive docs' external assets in production if desired.
    )
    app.state.container = container

    app.add_middleware(SecurityHeadersMiddleware)
    register_error_handlers(app)

    api_prefix = "/api/v1"
    app.include_router(auth.router, prefix=api_prefix)
    app.include_router(workspaces.router, prefix=api_prefix)
    app.include_router(notes.router, prefix=api_prefix)
    app.include_router(notes.public_router, prefix=api_prefix)
    app.include_router(files.router, prefix=api_prefix)
    app.include_router(billing.router, prefix=api_prefix)
    app.include_router(analytics.router, prefix=api_prefix)
    app.include_router(admin.router, prefix=api_prefix)

    @app.get("/health", tags=["system"])
    async def health(container: Container = Depends(get_container)) -> dict:
        return {"status": "ok", "app": container.settings.app_name,
                "version": app.version}

    return app


app = create_app()
