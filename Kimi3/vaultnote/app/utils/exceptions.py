"""
Custom exception hierarchy - clean error handling without leaking internals.
"""
from __future__ import annotations


class VaultNoteError(Exception):
    """Base application error."""
    status_code: int = 500
    detail: str = "Internal server error"

    def __init__(self, detail: str | None = None):
        super().__init__(detail or self.detail)
        if detail:
            self.detail = detail


class AuthenticationError(VaultNoteError):
    status_code = 401
    detail = "Authentication failed"


class AuthorizationError(VaultNoteError):
    status_code = 403
    detail = "Insufficient permissions"


class NotFoundError(VaultNoteError):
    status_code = 404
    detail = "Resource not found"


class ConflictError(VaultNoteError):
    status_code = 409
    detail = "Resource already exists"


class RateLimitError(VaultNoteError):
    status_code = 429
    detail = "Too many requests"


class ValidationError(VaultNoteError):
    status_code = 422
    detail = "Invalid input"


class QuotaExceededError(VaultNoteError):
    status_code = 402
    detail = "Plan quota exceeded"


class TenantIsolationError(VaultNoteError):
    status_code = 403
    detail = "Cross-tenant access denied"
