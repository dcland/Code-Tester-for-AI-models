"""Immutable audit log (SOC 2 CC7.2 / GDPR Art. 30).

Rows are append-only: the repository exposes no update or single-row delete.
Entries record *what* happened (action code), *where* (opaque org/resource ids)
and *who* (a pseudonymized actor), plus a non-PII metadata JSON. They never
contain emails, names, note titles, file names, tokens, or secrets.

Each row carries a hash chained to the previous row for the same tenant, making
silent tampering detectable (tamper-evident log).
"""

from __future__ import annotations

from sqlalchemy import Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, new_id


class AuditLog(Base, TimestampMixin):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_org_created", "org_id", "created_at"),
        Index("ix_audit_action", "action"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    actor_pseudonym: Mapped[str | None] = mapped_column(String(40), nullable=True)
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(20), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    outcome: Mapped[str] = mapped_column(String(10), default="success", nullable=False)
    # JSON string of non-PII metadata (already redacted at write time).
    context: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    # Tamper-evidence: sha256(prev_hash || canonical(this row)).
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
