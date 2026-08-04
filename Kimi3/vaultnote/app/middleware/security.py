"""
Security headers middleware (OWASP) + request ID + rate limiting.
"""
from __future__ import annotations

import uuid

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from app.core.config import settings
from app.utils.rate_limiter import rate_limiter

_AUTH_PATHS = ("/api/v1/auth/login", "/api/v1/auth/register", "/api/v1/auth/password-reset")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """OWASP-recommended security response headers."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Attach a unique request ID for tracing (no PII)."""

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-user / per-IP sliding-window rate limiting."""

    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip rate limiting for health checks
        if request.url.path == "/health":
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path

        # Stricter limits for auth endpoints (credential-stuffing defense)
        if any(path.startswith(p) for p in _AUTH_PATHS):
            limit, window = settings.RATE_LIMIT_AUTH, settings.RATE_LIMIT_AUTH_WINDOW_SECONDS
            key = f"auth:{client_ip}"
        else:
            limit, window = settings.RATE_LIMIT_DEFAULT, settings.RATE_LIMIT_WINDOW_SECONDS
            key = f"api:{client_ip}"

        allowed = await rate_limiter.is_allowed(key, limit, window)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests"},
                headers={"Retry-After": str(window)},
            )
        return await call_next(request)
