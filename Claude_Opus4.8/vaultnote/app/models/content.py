"""Encrypted content: folders, notes, and files.

All user-facing text (folder names, note titles/bodies, file names) is stored as
AES-256-GCM ciphertext with a per-object wrapped DEK. The database never holds
plaintext content or plaintext DEKs.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    LargeBinary,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, new_id


class Folder(Base, TimestampMixin):
    __tablename__ = "folders"
    __table_args__ = (
        Index("ix_folders_org", "org_id"),
        Index("ix_folders_parent", "parent_id"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    parent_id: Mapped[str | None] = mapped_column(
        ForeignKey("folders.id", ondelete="CASCADE"), nullable=True
    )
    owner_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    name_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_version: Mapped[int] = mapped_column(default=1, nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class Note(Base, TimestampMixin):
    __tablename__ = "notes"
    __table_args__ = (
        Index("ix_notes_org", "org_id"),
        Index("ix_notes_folder", "folder_id"),
        Index("ix_notes_org_updated", "org_id", "updated_at"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    folder_id: Mapped[str | None] = mapped_column(
        ForeignKey("folders.id", ondelete="SET NULL"), nullable=True
    )
    owner_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    title_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    body_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_version: Mapped[int] = mapped_column(default=1, nullable=False)
    # Monotonic version for optimistic concurrency / OT sequencing.
    version: Mapped[int] = mapped_column(default=1, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class File(Base, TimestampMixin):
    __tablename__ = "files"
    __table_args__ = (
        Index("ix_files_org", "org_id"),
        Index("ix_files_folder", "folder_id"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    folder_id: Mapped[str | None] = mapped_column(
        ForeignKey("folders.id", ondelete="SET NULL"), nullable=True
    )
    owner_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    filename_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    content_type: Mapped[str] = mapped_column(String(120), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    # Opaque storage key on disk (encrypted blob path). Never derived from the
    # user-supplied file name (path-traversal resistance).
    storage_key: Mapped[str] = mapped_column(String(80), nullable=False)
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_version: Mapped[int] = mapped_column(default=1, nullable=False)
    # SHA-256 of plaintext, for integrity verification on download.
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
