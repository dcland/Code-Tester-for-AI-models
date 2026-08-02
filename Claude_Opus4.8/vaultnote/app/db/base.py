"""Declarative base and common column helpers."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def new_id() -> str:
    """Opaque, non-sequential identifier (UUID4 hex).

    Non-sequential ids avoid leaking record counts / creation order (IDOR and
    enumeration resistance).
    """
    return uuid.uuid4().hex


def utcnow() -> datetime:
    """Naive UTC timestamp.

    We standardize on naive-UTC because SQLite does not persist tz info; storing
    aware values would round-trip as naive and break comparisons. All timestamps
    in the system are UTC by convention.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
