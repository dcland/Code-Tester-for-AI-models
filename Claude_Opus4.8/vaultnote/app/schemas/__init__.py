"""Pydantic v2 request/response schemas. Strict validation on every endpoint."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)

# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

# Self-contained email validation (no external email-validator dependency).
# Intentionally conservative; normalizes to lowercase for stable lookups.
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def _validate_email(v: str) -> str:
    v = v.strip().lower()
    if len(v) > 320 or not _EMAIL_RE.match(v):
        raise ValueError("invalid email address")
    return v


EmailStr = Annotated[str, AfterValidator(_validate_email)]


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

PASSWORD_MIN = 12
PASSWORD_MAX = 128


def _validate_password_strength(v: str) -> str:
    if len(v) < PASSWORD_MIN:
        raise ValueError(f"password must be at least {PASSWORD_MIN} characters")
    classes = sum(
        bool(cond)
        for cond in (
            any(c.islower() for c in v),
            any(c.isupper() for c in v),
            any(c.isdigit() for c in v),
            any(not c.isalnum() for c in v),
        )
    )
    if classes < 3:
        raise ValueError("password must mix upper, lower, digit and symbol")
    return v


class RegisterRequest(ApiModel):
    email: EmailStr
    password: str = Field(min_length=PASSWORD_MIN, max_length=PASSWORD_MAX)
    display_name: str = Field(default="", max_length=120)
    organization_name: str = Field(min_length=1, max_length=200)

    _pw = field_validator("password")(_validate_password_strength)


class LoginRequest(ApiModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=PASSWORD_MAX)
    totp_code: str | None = Field(default=None, max_length=8)


class TokenResponse(ApiModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(ApiModel):
    refresh_token: str = Field(min_length=10, max_length=200)


class PasswordResetRequest(ApiModel):
    email: EmailStr


class PasswordResetConfirm(ApiModel):
    token: str = Field(min_length=10, max_length=200)
    new_password: str = Field(min_length=PASSWORD_MIN, max_length=PASSWORD_MAX)

    _pw = field_validator("new_password")(_validate_password_strength)


class PasswordChangeRequest(ApiModel):
    current_password: str = Field(min_length=1, max_length=PASSWORD_MAX)
    new_password: str = Field(min_length=PASSWORD_MIN, max_length=PASSWORD_MAX)

    _pw = field_validator("new_password")(_validate_password_strength)


class TotpEnableResponse(ApiModel):
    secret: str
    otpauth_uri: str


class TotpVerifyRequest(ApiModel):
    code: str = Field(min_length=6, max_length=8)


# ---------------------------------------------------------------------------
# Workspaces / membership
# ---------------------------------------------------------------------------

RoleName = Literal["owner", "admin", "member", "viewer"]


class OrganizationOut(ApiModel):
    id: str
    name: str
    plan: str
    role: RoleName
    created_at: datetime


class InviteRequest(ApiModel):
    email: EmailStr
    role: RoleName = "member"


class RoleChangeRequest(ApiModel):
    role: RoleName


class MemberOut(ApiModel):
    user_id: str
    role: RoleName
    joined_at: datetime


# ---------------------------------------------------------------------------
# Notes / folders
# ---------------------------------------------------------------------------


class FolderCreate(ApiModel):
    name: str = Field(min_length=1, max_length=200)
    parent_id: str | None = Field(default=None, max_length=32)


class FolderOut(ApiModel):
    id: str
    name: str
    parent_id: str | None
    created_at: datetime


class NoteCreate(ApiModel):
    title: str = Field(max_length=500)
    body: str = Field(default="", max_length=1_000_000)
    folder_id: str | None = Field(default=None, max_length=32)


class NoteUpdate(ApiModel):
    title: str | None = Field(default=None, max_length=500)
    body: str | None = Field(default=None, max_length=1_000_000)
    # Optimistic concurrency token from the client's last read.
    expected_version: int | None = Field(default=None, ge=1)


class NoteOut(ApiModel):
    id: str
    title: str
    body: str
    folder_id: str | None
    owner_id: str
    version: int
    created_at: datetime
    updated_at: datetime


class NoteSummary(ApiModel):
    id: str
    title: str
    folder_id: str | None
    version: int
    updated_at: datetime


# ---------------------------------------------------------------------------
# Sharing
# ---------------------------------------------------------------------------

Permission = Literal["read", "write", "admin"]
ResourceType = Literal["note", "folder"]


class ShareCreate(ApiModel):
    grantee_user_id: str = Field(min_length=1, max_length=32)
    permission: Permission = "read"


class ShareLinkCreate(ApiModel):
    permission: Literal["read", "write"] = "read"
    password: str | None = Field(default=None, min_length=4, max_length=128)
    expires_in_seconds: int | None = Field(default=None, ge=60, le=60 * 60 * 24 * 30)


class ShareLinkOut(ApiModel):
    url_token: str
    permission: str
    expires_at: datetime | None


class ShareLinkAccess(ApiModel):
    password: str | None = Field(default=None, max_length=128)


# ---------------------------------------------------------------------------
# Collaboration
# ---------------------------------------------------------------------------


class PresenceOut(ApiModel):
    note_id: str
    active_user_ids: list[str]


class NoteOperation(ApiModel):
    """A simplified operational-transform edit against a known base version."""

    base_version: int = Field(ge=1)
    op: Literal["insert", "delete"]
    position: int = Field(ge=0)
    text: str = Field(default="", max_length=100_000)
    length: int = Field(default=0, ge=0)


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------


class FileOut(ApiModel):
    id: str
    filename: str
    content_type: str
    size_bytes: int
    created_at: datetime


class DownloadTokenOut(ApiModel):
    token: str
    expires_in: int


# ---------------------------------------------------------------------------
# Billing
# ---------------------------------------------------------------------------

PlanName = Literal["free", "pro", "business", "enterprise"]


class PlanChangeRequest(ApiModel):
    plan: PlanName
    seats: int = Field(default=1, ge=1, le=1000)
    # Opaque processor token only. Rejects anything that looks like a PAN.
    payment_token: str | None = Field(default=None, max_length=64)

    @field_validator("payment_token")
    @classmethod
    def _no_card_numbers(cls, v: str | None) -> str | None:
        if v and sum(c.isdigit() for c in v) >= 13 and v.replace(" ", "").isdigit():
            # PCI-DSS: refuse to accept raw card numbers.
            raise ValueError("raw card data is not accepted; provide a processor token")
        return v


class SubscriptionOut(ApiModel):
    plan: str
    seats: int
    status: str
    current_period_end: datetime


class InvoiceOut(ApiModel):
    number: str
    amount_cents: int
    currency: str
    status: str
    period_start: datetime
    period_end: datetime
    line_items: list[dict]


class UsageOut(ApiModel):
    storage_bytes: int
    seats: int
    api_calls: int
    storage_limit_bytes: int
    seat_limit: int


# ---------------------------------------------------------------------------
# Consent / compliance
# ---------------------------------------------------------------------------

ConsentName = Literal["terms_of_service", "analytics", "marketing"]


class ConsentRequest(ApiModel):
    consent_type: ConsentName
    granted: bool


class ConsentOut(ApiModel):
    consent_type: str
    granted: bool
    updated_at: datetime


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------


class AnalyticsOut(ApiModel):
    epsilon: float
    note_count: int
    file_count: int
    active_members: int
    storage_bytes: int
    note: str
