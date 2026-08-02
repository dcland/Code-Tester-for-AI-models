"""User identity, sessions, password resets, and consent records."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, new_id


class User(Base, TimestampMixin):
    __tablename__ = "users"
    __table_args__ = (Index("ix_users_email", "email", unique=True),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    # Email is the login identifier. It is PII: it is NEVER written to logs or
    # audit entries (see privacy.redact / pseudonymize).
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), default="", nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # TOTP secret stored encrypted-at-rest is out of scope for the demo; it is
    # kept null unless 2FA is enabled, and cleared on disable.
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    failed_login_count: Mapped[int] = mapped_column(default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Bumped on password change / logout-all to invalidate all live sessions.
    token_epoch: Mapped[int] = mapped_column(default=0, nullable=False)

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class Session(Base, TimestampMixin):
    """A refresh-token-backed session. The refresh token is stored hashed."""

    __tablename__ = "sessions"
    __table_args__ = (
        Index("ix_sessions_user", "user_id"),
        Index("ix_sessions_token_hash", "token_hash", unique=True),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    org_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Coarse client fingerprint for the user's own session list. No IP stored.
    user_agent_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)


class PasswordReset(Base, TimestampMixin):
    __tablename__ = "password_resets"
    __table_args__ = (Index("ix_pwreset_token_hash", "token_hash", unique=True),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class Consent(Base, TimestampMixin):
    """Consent ledger (GDPR Art. 7 — demonstrable, withdrawable consent)."""

    __tablename__ = "consents"
    __table_args__ = (Index("ix_consent_user", "user_id"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    consent_type: Mapped[str] = mapped_column(String(40), nullable=False)
    granted: Mapped[bool] = mapped_column(Boolean, nullable=False)
