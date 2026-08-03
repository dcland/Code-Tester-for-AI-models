"""
VaultNote application entry point.

Run with: uvicorn app.main:app --reload
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1 import admin, analytics, auth, billing, files, notes, workspaces
from app.core.config import settings
from app.core.privacy import redact_pii
from app.middleware.security import RateLimitMiddleware, RequestIDMiddleware, SecurityHeadersMiddleware
from app.models.database import init_db
from app.utils.exceptions import VaultNoteError

logger = logging.getLogger("vaultnote")
logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables on startup (use Alembic migrations in production)
    await init_db()
    yield


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
    allow_headers=["Authorization", "Content-Type", "X-Organization-ID"],
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
