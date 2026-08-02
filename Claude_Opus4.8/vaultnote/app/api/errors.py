"""Central exception handling with PII-safe error responses."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.core.exceptions import RateLimitedError, VaultNoteError
from app.core.privacy import redact

logger = logging.getLogger("vaultnote")


def _error_body(code: str, message: str, request_id: str) -> dict:
    # Message is redacted so no PII/secret can ever leak via an error.
    return {"error": {"code": code, "message": redact(message), "request_id": request_id}}


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(VaultNoteError)
    async def _vaultnote_error(request: Request, exc: VaultNoteError) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "-")
        headers = {}
        if isinstance(exc, RateLimitedError):
            headers["Retry-After"] = str(exc.retry_after)
        # Log only the action + code, never the message payload / PII.
        logger.info("app_error code=%s status=%s path=%s",
                    exc.code, exc.status_code, request.url.path)
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(exc.code, exc.message, request_id),
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request,
                                exc: RequestValidationError) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "-")
        # Redact each error detail (user-supplied values can contain PII).
        details = []
        for err in exc.errors():
            details.append({
                "loc": [str(p) for p in err.get("loc", [])],
                "type": err.get("type", "value_error"),
                "msg": redact(str(err.get("msg", "invalid"))),
            })
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "validation_error",
                    "message": "request validation failed",
                    "request_id": request_id,
                    "details": details,
                }
            },
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "-")
        # Never leak internal details to the client or logs (only the type name).
        logger.error("unhandled_error type=%s path=%s request_id=%s",
                     type(exc).__name__, request.url.path, request_id)
        return JSONResponse(
            status_code=500,
            content=_error_body("internal_error",
                                "an internal error occurred", request_id),
        )
