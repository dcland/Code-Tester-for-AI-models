"""Fine-grained shares and public share links."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, new_id


class Share(Base, TimestampMixin):
    """Direct grant of a permission on a resource to a user within a tenant."""

    __tablename__ = "shares"
    __table_args__ = (
        UniqueConstraint(
            "resource_type", "resource_id", "grantee_user_id",
            name="uq_share_resource_grantee",
        ),
        Index("ix_shares_grantee", "grantee_user_id"),
        Index("ix_shares_resource", "resource_type", "resource_id"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    resource_type: Mapped[str] = mapped_column(String(20), nullable=False)  # note|folder
    resource_id: Mapped[str] = mapped_column(String(32), nullable=False)
    grantee_user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    permission: Mapped[str] = mapped_column(String(10), nullable=False)  # read|write|admin
    created_by: Mapped[str] = mapped_column(String(32), nullable=False)


class ShareLink(Base, TimestampMixin):
    """Public link with optional password (hashed) and expiration."""

    __tablename__ = "share_links"
    __table_args__ = (Index("ix_sharelink_token", "token_hash", unique=True),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    resource_type: Mapped[str] = mapped_column(String(20), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(32), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # Optional link password (Argon2 hash). Null => no password.
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    permission: Mapped[str] = mapped_column(String(10), default="read", nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_by: Mapped[str] = mapped_column(String(32), nullable=False)
