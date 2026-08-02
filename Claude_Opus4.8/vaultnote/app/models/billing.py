"""Billing: subscriptions, invoices, usage metering.

PCI-DSS: no PAN/CVV/expiry is ever stored. Only an opaque processor token
(``payment_token``) representing a card held by the payment processor.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, new_id


class Subscription(Base, TimestampMixin):
    __tablename__ = "subscriptions"
    __table_args__ = (UniqueConstraint("org_id", name="uq_subscription_org"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    plan: Mapped[str] = mapped_column(String(20), default="free", nullable=False)
    seats: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    # PCI-DSS SAQ-A: store ONLY a processor token, never card data.
    payment_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    current_period_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    current_period_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class Invoice(Base, TimestampMixin):
    __tablename__ = "invoices"
    __table_args__ = (Index("ix_invoice_org", "org_id"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    number: Mapped[str] = mapped_column(String(40), nullable=False)
    amount_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), default="USD", nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="paid", nullable=False)
    period_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    period_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    # JSON-encoded non-PII line items.
    line_items: Mapped[str] = mapped_column(Text, nullable=False)


class UsageRecord(Base, TimestampMixin):
    """Per-tenant metered counter for a metric within a billing period."""

    __tablename__ = "usage_records"
    __table_args__ = (
        UniqueConstraint("org_id", "metric", "period", name="uq_usage"),
        Index("ix_usage_org", "org_id"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    metric: Mapped[str] = mapped_column(String(30), nullable=False)  # api_calls|storage|seats
    period: Mapped[str] = mapped_column(String(7), nullable=False)   # YYYY-MM
    value: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
