"""Tenant (organization) and membership models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    LargeBinary,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, new_id


class Role(StrEnum):
    """Least-privilege role ladder within a tenant."""

    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"

    @property
    def rank(self) -> int:
        return {"viewer": 0, "member": 1, "admin": 2, "owner": 3}[self.value]

    def at_least(self, other: "Role") -> bool:
        return self.rank >= other.rank


class Organization(Base, TimestampMixin):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    plan: Mapped[str] = mapped_column(String(20), default="free", nullable=False)
    # Wrapped tenant master key (encrypted under the env KEK). Never plaintext.
    wrapped_master_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_version: Mapped[int] = mapped_column(default=1, nullable=False)
    retention_days: Mapped[int] = mapped_column(default=30, nullable=False)
    # GDPR Art. 17 — soft-delete marker before cascading hard purge.
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class Membership(Base, TimestampMixin):
    __tablename__ = "memberships"
    __table_args__ = (
        UniqueConstraint("org_id", "user_id", name="uq_membership_org_user"),
        Index("ix_membership_user", "user_id"),
        Index("ix_membership_org", "org_id"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(20), default=Role.MEMBER, nullable=False)
