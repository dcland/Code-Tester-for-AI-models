"""Billing repository: subscriptions, invoices, usage metering."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.billing import Invoice, Subscription, UsageRecord


class BillingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    # --- Subscription ------------------------------------------------------
    async def add_subscription(self, sub: Subscription) -> Subscription:
        self._s.add(sub)
        await self._s.flush()
        return sub

    async def get_subscription(self, org_id: str) -> Subscription | None:
        stmt = select(Subscription).where(Subscription.org_id == org_id)
        return (await self._s.execute(stmt)).scalar_one_or_none()

    # --- Invoices ----------------------------------------------------------
    async def add_invoice(self, invoice: Invoice) -> Invoice:
        self._s.add(invoice)
        await self._s.flush()
        return invoice

    async def list_invoices(self, org_id: str) -> list[Invoice]:
        stmt = (
            select(Invoice)
            .where(Invoice.org_id == org_id)
            .order_by(Invoice.created_at.desc())
        )
        return list((await self._s.execute(stmt)).scalars())

    # --- Usage metering ----------------------------------------------------
    async def increment_usage(self, org_id: str, metric: str, period: str,
                              amount: int = 1) -> None:
        """Atomic upsert-and-increment of a usage counter (O(1))."""
        stmt = sqlite_insert(UsageRecord).values(
            org_id=org_id, metric=metric, period=period, value=amount
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=["org_id", "metric", "period"],
            set_={"value": UsageRecord.value + amount},
        )
        await self._s.execute(stmt)

    async def get_usage(self, org_id: str, metric: str, period: str) -> int:
        stmt = select(UsageRecord.value).where(
            UsageRecord.org_id == org_id,
            UsageRecord.metric == metric,
            UsageRecord.period == period,
        )
        val = (await self._s.execute(stmt)).scalar_one_or_none()
        return int(val or 0)
