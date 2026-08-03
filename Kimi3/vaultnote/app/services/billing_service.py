"""
Billing & subscription service with proration and usage metering.

PCI-DSS: only payment tokens are stored, never raw card data.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entities import Invoice, PlanTier, Subscription
from app.repositories.repositories import InvoiceRepository, SubscriptionRepository, UsageRepository
from app.utils.exceptions import NotFoundError

# Price per seat per month in cents
_PLAN_PRICES = {
    PlanTier.FREE: 0,
    PlanTier.PRO: 1200,
    PlanTier.BUSINESS: 3600,
    PlanTier.ENTERPRISE: 12000,
}


class BillingService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.subs = SubscriptionRepository(session)
        self.invoices = InvoiceRepository(session)
        self.usage = UsageRepository(session)

    async def get_subscription(self, org_id: str) -> Subscription:
        sub = await self.subs.get_by_org(org_id)
        if sub is None:
            raise NotFoundError("Subscription not found")
        return sub

    async def change_plan(self, org_id: str, new_plan: PlanTier, payment_token: str | None = None) -> dict:
        sub = await self.get_subscription(org_id)
        old_plan = sub.plan
        old_price = _PLAN_PRICES[old_plan]
        new_price = _PLAN_PRICES[new_plan]

        # Proration: compute unused portion of current plan vs new plan
        now = datetime.now(timezone.utc)
        # SQLite returns naive datetimes - normalize for arithmetic
        period_start = sub.current_period_start
        if period_start.tzinfo is None:
            period_start = period_start.replace(tzinfo=timezone.utc)
        days_in_period = 30
        elapsed = max((now - period_start).days, 0)
        remaining_ratio = max(days_in_period - elapsed, 0) / days_in_period
        proration_credit = int(old_price * remaining_ratio)
        amount_due = max(new_price - proration_credit, 0)

        sub.plan = new_plan
        if payment_token:
            sub.payment_token = payment_token
        sub.current_period_start = now
        await self.session.flush()

        invoice = Invoice(
            organization_id=org_id,
            amount_cents=amount_due,
            description=f"Plan change {old_plan.value} -> {new_plan.value} (prorated)",
        )
        await self.invoices.create(invoice)
        return {
            "plan": new_plan.value,
            "amount_due_cents": amount_due,
            "proration_credit_cents": proration_credit,
            "invoice_id": invoice.id,
        }

    async def record_usage(self, org_id: str, storage_bytes: int = 0, seats: int = 0, api_calls: int = 0) -> None:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        rec = await self.usage.get_or_create_today(org_id, today)
        rec.storage_bytes += storage_bytes
        rec.seats = max(rec.seats, seats)
        rec.api_calls += api_calls
        await self.session.flush()

    async def list_invoices(self, org_id: str) -> list[dict]:
        invoices = await self.invoices.list_by_org(org_id)
        return [
            {"id": i.id, "amount_cents": i.amount_cents, "currency": i.currency,
             "description": i.description, "paid": i.paid}
            for i in invoices
        ]
