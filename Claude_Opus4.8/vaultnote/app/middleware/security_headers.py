"""Security headers + request-id middleware (OWASP secure defaults)."""

from __future__ import annotations

import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# A strict, API-appropriate CSP. This service returns JSON only, so we forbid
# all active content and framing.
_CSP = (
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'none'"
)

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": _CSP,
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cache-Control": "no-store",
    # HSTS is set for HTTPS deployments; harmless over plain HTTP for the demo.
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = secrets.token_hex(8)
        request.state.request_id = request_id
        response = await call_next(request)
        for header, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        response.headers["X-Request-ID"] = request_id
        # Never advertise the server implementation.
        response.headers["Server"] = "VaultNote"
        return response
