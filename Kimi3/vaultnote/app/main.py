"""
VaultNote application entry point.

Run with: uvicorn app.main:app --reload
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1 import admin, analytics, auth, billing, files, notes, workspaces
from app.core.config import settings
from app.core.privacy import redact_pii
from app.middleware.security import (
    RateLimitMiddleware,
    RequestIDMiddleware,
    SecurityHeadersMiddleware,
)
from app.models.database import async_session_factory, init_db
from app.utils.exceptions import VaultNoteError

logger = logging.getLogger("vaultnote")
logging.basicConfig(level=logging.INFO)


async def _retention_enforcement_loop() -> None:
    """Automatic GDPR Art. 5(1)(e) storage-limitation enforcement.

    Runs as a scheduled background job (not a manual endpoint) and applies
    each tenant's own plan retention window.
    """
    from app.services.compliance_service import ComplianceService

    while True:
        await asyncio.sleep(settings.RETENTION_PURGE_INTERVAL_SECONDS)
        try:
            async with async_session_factory() as session:
                totals = await ComplianceService(session).purge_all_tenants()
                await session.commit()
            logger.info("retention purge completed: %s", totals)
        except Exception:  # pragma: no cover - defensive: job must not die
            logger.exception("retention purge failed; will retry next cycle")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables on startup (use Alembic migrations in production)
    await init_db()
    # Automatic retention enforcement (scheduled system job)
    purge_task = asyncio.create_task(_retention_enforcement_loop())
    try:
        yield
    finally:
        purge_task.cancel()
        with suppress(asyncio.CancelledError):
            await purge_task


app = FastAPI(
    title=settings.APP_NAME,
    description="End-to-End Encrypted Multi-Tenant Collaborative Workspace Platform",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,  # disable docs in production
    redoc_url=None,
)

# ---- Middleware (order matters: outermost first) ---------------------------
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Organization-ID", "X-File-Name"],
)


# ---- Exception handlers ----------------------------------------------------
@app.exception_handler(VaultNoteError)
async def vaultnote_error_handler(request: Request, exc: VaultNoteError) -> JSONResponse:
    # Redact any accidental PII from error detail before returning
    return JSONResponse(status_code=exc.status_code, content={"detail": redact_pii(exc.detail)})


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    # Never leak internal errors to the client
    logger.error("unhandled error: %s", redact_pii(str(exc)))
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# ---- Routers -----------------------------------------------------------------
prefix = settings.API_V1_PREFIX
app.include_router(auth.router, prefix=prefix)
app.include_router(workspaces.router, prefix=prefix)
app.include_router(notes.router, prefix=prefix)
app.include_router(files.router, prefix=prefix)
app.include_router(billing.router, prefix=prefix)
app.include_router(analytics.router, prefix=prefix)
app.include_router(admin.router, prefix=prefix)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
