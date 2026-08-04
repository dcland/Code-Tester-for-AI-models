"""
SQLAlchemy ORM models for VaultNote.

Multi-tenant design: every tenant-scoped table carries organization_id.
Indexes are placed on all hot query paths to avoid N+1 and full scans.
"""
from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Role(str, enum.Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class PlanTier(str, enum.Enum):
    FREE = "free"
    PRO = "pro"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"


class Permission(str, enum.Enum):
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    # Encrypted tenant KEK (wrapped with master key)
    kek_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    kek_nonce: Mapped[str] = mapped_column(Text, nullable=False)
    plan: Mapped[PlanTier] = mapped_column(Enum(PlanTier), default=PlanTier.FREE)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    members: Mapped[list[Membership]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    workspaces: Mapped[list[Workspace]] = relationship(back_populates="organization", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(Text, nullable=False)
    full_name: Mapped[str] = mapped_column(String(200), default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    memberships: Mapped[list[Membership]] = relationship(back_populates="user", cascade="all, delete-orphan")
    refresh_tokens: Mapped[list[RefreshToken]] = relationship(back_populates="user", cascade="all, delete-orphan")


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (
        Index("ix_membership_user_org", "user_id", "organization_id", unique=True),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.MEMBER)

    user: Mapped[User] = relationship(back_populates="memberships")
    organization: Mapped[Organization] = relationship(back_populates="members")


class RefreshToken(Base):
    """Refresh tokens stored as SHA-256 hashes (never in plaintext)."""
    __tablename__ = "refresh_tokens"
    __table_args__ = (Index("ix_refresh_user", "user_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    user: Mapped[User] = relationship(back_populates="refresh_tokens")


class PasswordReset(Base):
    """Password-reset tokens stored as SHA-256 hashes with expiry.

    The raw token is only ever sent out-of-band (email); the API response
    never contains it, so account existence is not leaked.
    """
    __tablename__ = "password_resets"
    __table_args__ = (Index("ix_reset_user", "user_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class AuditEventRecord(Base):
    """Durable, HMAC-signed, hash-chained audit event (SOC 2 CC7.2).

    Persisted in the database so the trail survives restarts. Each row is
    MACed with a server-side key over its canonical payload plus the hash of
    the previous row, making tampering, reordering, or deletion detectable.
    """
    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_tenant", "tenant_id"),)

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, default=_uuid)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(100), nullable=False)  # pseudonymous
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(100), nullable=False)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash: Mapped[str] = mapped_column(String(64), nullable=False)


class Workspace(Base):
    __tablename__ = "workspaces"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    organization: Mapped[Organization] = relationship(back_populates="workspaces")
    folders: Mapped[list[Folder]] = relationship(back_populates="workspace", cascade="all, delete-orphan")
    notes: Mapped[list[Note]] = relationship(back_populates="workspace", cascade="all, delete-orphan")


class Folder(Base):
    __tablename__ = "folders"
    __table_args__ = (Index("ix_folder_workspace_parent", "workspace_id", "parent_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    parent_id: Mapped[str | None] = mapped_column(ForeignKey("folders.id", ondelete="CASCADE"), nullable=True)
    name_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    name_nonce: Mapped[str] = mapped_column(Text, nullable=False)
    dek_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    dek_nonce: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    workspace: Mapped[Workspace] = relationship(back_populates="folders")
    children: Mapped[list[Folder]] = relationship(back_populates="parent", cascade="all, delete-orphan")
    parent: Mapped[Folder | None] = relationship(back_populates="children", remote_side=[id])


class Note(Base):
    __tablename__ = "notes"
    __table_args__ = (
        Index("ix_note_workspace", "workspace_id"),
        Index("ix_note_org", "organization_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    folder_id: Mapped[str | None] = mapped_column(ForeignKey("folders.id", ondelete="SET NULL"), nullable=True)
    title_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    title_nonce: Mapped[str] = mapped_column(Text, nullable=False)
    content_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    content_nonce: Mapped[str] = mapped_column(Text, nullable=False)
    dek_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    dek_nonce: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str] = mapped_column(String(36), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    workspace: Mapped[Workspace] = relationship(back_populates="notes")


class FileAsset(Base):
    __tablename__ = "file_assets"
    __table_args__ = (Index("ix_file_org", "organization_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    filename_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    filename_nonce: Mapped[str] = mapped_column(Text, nullable=False)
    dek_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    dek_nonce: Mapped[str] = mapped_column(Text, nullable=False)
    storage_path: Mapped[str] = mapped_column(Text, nullable=False)  # random, no traversal
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(100), nullable=False)
    uploaded_by: Mapped[str] = mapped_column(String(36), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ShareLink(Base):
    __tablename__ = "share_links"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(20), nullable=False)  # note|folder
    resource_id: Mapped[str] = mapped_column(String(36), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    password_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    permission: Mapped[Permission] = mapped_column(Enum(Permission), default=Permission.READ)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(36), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class ShareGrant(Base):
    """Fine-grained ACL sharing of notes/folders with users."""
    __tablename__ = "share_grants"
    __table_args__ = (Index("ix_grant_resource", "resource_type", "resource_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(20), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(36), nullable=False)
    grantee_user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    permission: Mapped[Permission] = mapped_column(Enum(Permission), default=Permission.READ)
    created_by: Mapped[str] = mapped_column(String(36), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Subscription(Base):
    __tablename__ = "subscriptions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), unique=True, nullable=False)
    plan: Mapped[PlanTier] = mapped_column(Enum(PlanTier), default=PlanTier.FREE)
    # PCI-DSS: store only a payment token, never raw card data
    payment_token: Mapped[str | None] = mapped_column(String(128), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    current_period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class UsageRecord(Base):
    """Aggregated usage metering per org per day (no individual PII)."""
    __tablename__ = "usage_records"
    __table_args__ = (Index("ix_usage_org_date", "organization_id", "date"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    date: Mapped[str] = mapped_column(String(10), nullable=False)  # YYYY-MM-DD
    storage_bytes: Mapped[int] = mapped_column(Integer, default=0)
    seats: Mapped[int] = mapped_column(Integer, default=0)
    api_calls: Mapped[int] = mapped_column(Integer, default=0)


class Invoice(Base):
    __tablename__ = "invoices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    amount_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), default="USD")
    description: Mapped[str] = mapped_column(Text, default="")
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    paid: Mapped[bool] = mapped_column(Boolean, default=False)


class ConsentRecord(Base):
    """GDPR Art. 7 - consent management."""
    __tablename__ = "consent_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    purpose: Mapped[str] = mapped_column(String(100), nullable=False)
    granted: Mapped[bool] = mapped_column(Boolean, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class DownloadToken(Base):
    """Short-lived, single-purpose file download tokens (stored hashed)."""
    __tablename__ = "download_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    file_id: Mapped[str] = mapped_column(ForeignKey("file_assets.id", ondelete="CASCADE"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class PresenceState(Base):
    """Real-time collaboration presence simulation."""
    __tablename__ = "presence_states"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    note_id: Mapped[str] = mapped_column(ForeignKey("notes.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False)
    cursor_position: Mapped[int] = mapped_column(Integer, default=0)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class NoteOperation(Base):
    """CRDT-ready operation log for real-time collaboration."""
    __tablename__ = "note_operations"
    __table_args__ = (Index("ix_noteop_note", "note_id", "lamport"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    note_id: Mapped[str] = mapped_column(ForeignKey("notes.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False)
    lamport: Mapped[int] = mapped_column(Integer, nullable=False)  # logical clock
    op_type: Mapped[str] = mapped_column(String(10), nullable=False)  # insert|delete
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    content_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    content_nonce: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
