"""Custom exception hierarchy.

Every application error derives from :class:`VaultNoteError`, carries a stable
machine-readable ``code`` and an HTTP ``status_code``, and a *safe* message that
is guaranteed to contain no PII or secrets (see ``app.core.privacy.redact``).
"""

from __future__ import annotations


class VaultNoteError(Exception):
    """Base class for all application errors."""

    code: str = "error"
    status_code: int = 400
    message: str = "An error occurred."

    def __init__(self, message: str | None = None, *, code: str | None = None,
                 status_code: int | None = None) -> None:
        self.message = message or self.message
        if code is not None:
            self.code = code
        if status_code is not None:
            self.status_code = status_code
        super().__init__(self.message)


class AuthenticationError(VaultNoteError):
    code = "authentication_failed"
    status_code = 401
    message = "Authentication failed."


class InvalidTokenError(AuthenticationError):
    code = "invalid_token"
    message = "Invalid or expired token."


class AccountLockedError(AuthenticationError):
    code = "account_locked"
    status_code = 429
    message = "Account temporarily locked due to failed attempts."


class TwoFactorRequiredError(AuthenticationError):
    code = "two_factor_required"
    message = "Two-factor authentication required."


class AuthorizationError(VaultNoteError):
    code = "forbidden"
    status_code = 403
    message = "You do not have permission to perform this action."


class TenantIsolationError(AuthorizationError):
    code = "tenant_isolation"
    message = "Resource does not belong to the active tenant."


class NotFoundError(VaultNoteError):
    code = "not_found"
    status_code = 404
    message = "Resource not found."


class ConflictError(VaultNoteError):
    code = "conflict"
    status_code = 409
    message = "Resource conflict."


class ValidationError(VaultNoteError):
    code = "validation_error"
    status_code = 422
    message = "Validation failed."


class RateLimitedError(VaultNoteError):
    code = "rate_limited"
    status_code = 429
    message = "Too many requests."

    def __init__(self, retry_after: int = 1, **kwargs) -> None:
        super().__init__(**kwargs)
        self.retry_after = retry_after


class QuotaExceededError(VaultNoteError):
    code = "quota_exceeded"
    status_code = 402
    message = "Plan quota exceeded."


class FileValidationError(ValidationError):
    code = "file_rejected"
    message = "File failed validation."
