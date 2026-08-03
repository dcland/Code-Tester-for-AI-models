"""
Pydantic v2 request/response schemas with strict validation.

OWASP: all external input is validated before touching business logic.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Pure-Python email validation (avoids external email-validator dependency).
# RFC 5322 simplified - sufficient for input validation.
import re as _re

_EMAIL_RE = _re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def _validate_email(v: str) -> str:
    v = v.strip().lower()
    if not _EMAIL_RE.match(v) or len(v) > 320:
        raise ValueError("Invalid email address")
    return v


class _EmailBase(BaseModel):
    @field_validator("email", mode="before", check_fields=False)
    @classmethod
    def _check_email(cls, v: str) -> str:
        return _validate_email(v)

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class RegisterRequest(_EmailBase):
    model_config = ConfigDict(str_strip_whitespace=True)
    email: str
    password: str = Field(min_length=12, max_length=128)
    full_name: str = Field(default="", max_length=200)
    organization_name: str = Field(min_length=2, max_length=200)

    @field_validator("password")
    @classmethod
    def _password_strength(cls, v: str) -> str:
        # OWASP: enforce basic complexity
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain an uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain a lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain a digit")
        return v


class LoginRequest(_EmailBase):
    email: str
    password: str = Field(min_length=1, max_length=128)
    totp_code: Optional[str] = Field(default=None, min_length=6, max_length=6)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=10)


class PasswordResetRequest(_EmailBase):
    email: str


class PasswordResetConfirm(BaseModel):
    token: str = Field(min_length=10)
    new_password: str = Field(min_length=12, max_length=128)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=128)


class Enable2FAResponse(BaseModel):
    secret: str
    uri: str


class Verify2FARequest(BaseModel):
    code: str = Field(min_length=6, max_length=6)


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------

class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


# ---------------------------------------------------------------------------
# Workspaces / Notes / Folders
# ---------------------------------------------------------------------------

class WorkspaceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class FolderCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    parent_id: Optional[str] = None


class NoteCreate(BaseModel):
    title: str = Field(min_length=1, max_length=500)
    content: str = Field(default="")
    folder_id: Optional[str] = None


class NoteUpdate(BaseModel):
    title: Optional[str] = Field(default=None, max_length=500)
    content: Optional[str] = None


class ShareGrantCreate(BaseModel):
    grantee_user_id: str
    permission: Literal["read", "write", "admin"] = "read"


class ShareLinkCreate(BaseModel):
    password: Optional[str] = Field(default=None, min_length=4, max_length=64)
    permission: Literal["read", "write"] = "read"
    expires_in_hours: Optional[int] = Field(default=None, ge=1, le=720)


# ---------------------------------------------------------------------------
# Collaboration
# ---------------------------------------------------------------------------

class OperationSubmit(BaseModel):
    op_type: Literal["insert", "delete"]
    position: int = Field(ge=0)
    content: str = ""


class PresenceUpdate(BaseModel):
    cursor_position: int = Field(ge=0, default=0)


# ---------------------------------------------------------------------------
# Billing
# ---------------------------------------------------------------------------

class PlanChange(BaseModel):
    plan: Literal["free", "pro", "business", "enterprise"]
    payment_token: Optional[str] = None  # PCI-DSS: tokenized payment only


# ---------------------------------------------------------------------------
# Consent
# ---------------------------------------------------------------------------

class ConsentUpdate(BaseModel):
    purpose: str = Field(min_length=1, max_length=100)
    granted: bool
