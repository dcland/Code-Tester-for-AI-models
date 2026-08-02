"""Compliance constants and the audit-event taxonomy.

Centralizes the vocabulary of auditable actions and retention rules so the rest
of the codebase references named constants rather than magic strings.
"""

from __future__ import annotations

from enum import StrEnum


class AuditAction(StrEnum):
    """Sensitive actions that MUST be recorded (SOC 2 CC7 / GDPR Art. 30).

    The audit log stores only these action codes plus non-PII references
    (opaque resource ids, pseudonymized actor). It never stores note titles,
    file names, emails, or secrets.
    """

    USER_REGISTERED = "user.registered"
    LOGIN_SUCCEEDED = "auth.login.succeeded"
    LOGIN_FAILED = "auth.login.failed"
    LOGOUT = "auth.logout"
    LOGOUT_ALL = "auth.logout_all"
    PASSWORD_CHANGED = "auth.password.changed"
    PASSWORD_RESET_REQUESTED = "auth.password.reset_requested"
    PASSWORD_RESET_COMPLETED = "auth.password.reset_completed"
    TWO_FACTOR_ENABLED = "auth.2fa.enabled"
    TWO_FACTOR_DISABLED = "auth.2fa.disabled"

    ORG_CREATED = "org.created"
    MEMBER_INVITED = "org.member.invited"
    MEMBER_ROLE_CHANGED = "org.member.role_changed"
    MEMBER_REMOVED = "org.member.removed"

    NOTE_CREATED = "note.created"
    NOTE_UPDATED = "note.updated"
    NOTE_DELETED = "note.deleted"
    NOTE_SHARED = "note.shared"
    SHARE_LINK_CREATED = "share.link.created"

    FILE_UPLOADED = "file.uploaded"
    FILE_DOWNLOADED = "file.downloaded"
    FILE_DELETED = "file.deleted"

    KEY_ROTATED = "security.key.rotated"

    BILLING_PLAN_CHANGED = "billing.plan.changed"
    INVOICE_GENERATED = "billing.invoice.generated"

    CONSENT_GRANTED = "privacy.consent.granted"
    CONSENT_WITHDRAWN = "privacy.consent.withdrawn"
    DATA_EXPORTED = "privacy.data.exported"          # GDPR Art. 15 / CCPA
    USER_ERASED = "privacy.user.erased"              # GDPR Art. 17
    ORG_ERASED = "privacy.org.erased"                # GDPR Art. 17
    RETENTION_PURGE = "privacy.retention.purged"     # GDPR Art. 5(1)(e)


class ConsentType(StrEnum):
    TERMS_OF_SERVICE = "terms_of_service"
    ANALYTICS = "analytics"
    MARKETING = "marketing"


# GDPR Art. 5(1)(e) — storage limitation. Soft-deleted content is purged after
# the retention window that corresponds to the tenant's plan tier.
RETENTION_DAYS = {
    "free": 30,
    "pro": 365,
    "business": 365,
    "enterprise": 365,
}
