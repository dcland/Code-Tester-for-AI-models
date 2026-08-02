"""Billing & subscription engine: plans, metering, proration, invoices.

PCI-DSS: only opaque processor tokens are ever accepted or stored. No PAN/CVV.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.compliance import AuditAction
from app.core.config import Settings
from app.core.exceptions import AuthorizationError, ValidationError
from app.db.base import new_id, utcnow
from app.models.billing import Invoice, Subscription
from app.models.organization import Role
from app.repositories import (
    BillingRepository,
    FileRepository,
    MembershipRepository,
    OrganizationRepository,
)
from app.services.audit_service import AuditService


@dataclass(frozen=True)
class PlanLimits:
    name: str
    price_per_seat_cents: int
    storage_bytes: int
    max_seats: int
    api_calls_per_month: int


GIB = 1024 ** 3
MIB = 1024 ** 2

PLAN_LIMITS: dict[str, PlanLimits] = {
    "free": PlanLimits("free", 0, 100 * MIB, 3, 10_000),
    "pro": PlanLimits("pro", 1200, 5 * GIB, 25, 500_000),
    "business": PlanLimits("business", 2500, 100 * GIB, 200, 5_000_000),
    "enterprise": PlanLimits("enterprise", 5000, 1024 * GIB, 100_000, 100_000_000),
}

BILLING_PERIOD_DAYS = 30


def _period_key(dt: datetime) -> str:
    return dt.strftime("%Y-%m")


class BillingService:
    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._s = session
        self._settings = settings
        self._billing = BillingRepository(session)
        self._orgs = OrganizationRepository(session)
        self._members = MembershipRepository(session)
        self._files = FileRepository(session)
        self._audit = AuditService(session, settings)

    async def ensure_subscription(self, org_id: str) -> Subscription:
        sub = await self._billing.get_subscription(org_id)
        if sub is None:
            now = utcnow()
            sub = Subscription(
                org_id=org_id, plan="free", seats=1, status="active",
                current_period_start=now,
                current_period_end=now + timedelta(days=BILLING_PERIOD_DAYS),
            )
            await self._billing.add_subscription(sub)
            await self._s.flush()
        return sub

    async def _require_billing_admin(self, org_id: str, user_id: str) -> None:
        role = await self._members.get_role(org_id, user_id)
        if role is None or not role.at_least(Role.ADMIN):
            raise AuthorizationError("only owners/admins can manage billing")

    async def change_plan(self, org_id: str, user_id: str, *, plan: str,
                          seats: int, payment_token: str | None) -> Subscription:
        await self._require_billing_admin(org_id, user_id)
        if plan not in PLAN_LIMITS:
            raise ValidationError("unknown plan")
        limits = PLAN_LIMITS[plan]
        if seats > limits.max_seats:
            raise ValidationError("seat count exceeds plan maximum")

        member_count = await self._members.count_for_org(org_id)
        if seats < member_count:
            raise ValidationError("seats cannot be fewer than current members")

        sub = await self.ensure_subscription(org_id)
        now = utcnow()

        # --- Proration -----------------------------------------------------
        # Credit unused time on the old plan, charge prorated new plan for the
        # remainder of the current period.
        total_secs = max(
            1, (sub.current_period_end - sub.current_period_start).total_seconds()
        )
        remaining_secs = max(0, (sub.current_period_end - now).total_seconds())
        fraction_remaining = remaining_secs / total_secs

        old_limits = PLAN_LIMITS[sub.plan]
        old_monthly = old_limits.price_per_seat_cents * sub.seats
        new_monthly = limits.price_per_seat_cents * seats
        credit = round(old_monthly * fraction_remaining)
        charge = round(new_monthly * fraction_remaining)
        proration_cents = max(0, charge - credit)

        org = await self._orgs.get(org_id)
        org.plan = plan
        org.retention_days = (
            self._settings.retention_days_free if plan == "free"
            else self._settings.retention_days_paid
        )
        sub.plan = plan
        sub.seats = seats
        if payment_token:
            sub.payment_token = payment_token  # opaque token only

        # Issue an invoice for the proration delta (if any).
        if proration_cents > 0:
            await self._generate_invoice(
                org_id, amount_cents=proration_cents,
                line_items=[{
                    "description": f"Proration: upgrade to {plan}",
                    "quantity": seats, "unit_cents": limits.price_per_seat_cents,
                    "proration_fraction": round(fraction_remaining, 4),
                }],
                period_start=now, period_end=sub.current_period_end,
            )

        await self._audit.record(
            action=AuditAction.BILLING_PLAN_CHANGED, org_id=org_id,
            actor_user_id=user_id, context={"plan": plan, "seats": seats},
        )
        await self._s.commit()
        return sub

    async def _generate_invoice(self, org_id: str, *, amount_cents: int,
                                line_items: list[dict], period_start: datetime,
                                period_end: datetime) -> Invoice:
        invoice = Invoice(
            org_id=org_id,
            number=f"INV-{new_id()[:12].upper()}",
            amount_cents=amount_cents,
            currency="USD",
            status="paid" if amount_cents == 0 else "due",
            period_start=period_start,
            period_end=period_end,
            line_items=json.dumps(line_items),
        )
        await self._billing.add_invoice(invoice)
        await self._audit.record(
            action=AuditAction.INVOICE_GENERATED, org_id=org_id, actor_user_id=None,
            resource_type="invoice", resource_id=invoice.id,
            context={"amount_cents": amount_cents},
        )
        return invoice

    async def run_period_billing(self, org_id: str, user_id: str) -> Invoice:
        """Close the current period and generate a full invoice for it."""
        await self._require_billing_admin(org_id, user_id)
        sub = await self.ensure_subscription(org_id)
        limits = PLAN_LIMITS[sub.plan]
        amount = limits.price_per_seat_cents * sub.seats
        invoice = await self._generate_invoice(
            org_id, amount_cents=amount,
            line_items=[{
                "description": f"{sub.plan} plan",
                "quantity": sub.seats,
                "unit_cents": limits.price_per_seat_cents,
            }],
            period_start=sub.current_period_start,
            period_end=sub.current_period_end,
        )
        sub.current_period_start = sub.current_period_end
        sub.current_period_end = sub.current_period_end + timedelta(
            days=BILLING_PERIOD_DAYS
        )
        await self._s.commit()
        return invoice

    # --- Metering ----------------------------------------------------------
    async def record_api_call(self, org_id: str) -> None:
        await self._billing.increment_usage(
            org_id, "api_calls", _period_key(utcnow()), 1
        )

    async def get_usage(self, org_id: str, user_id: str) -> dict:
        await self._members.get_role(org_id, user_id)  # membership implied by caller
        sub = await self.ensure_subscription(org_id)
        limits = PLAN_LIMITS[sub.plan]
        storage = await self._files.total_storage(org_id)
        seats = await self._members.count_for_org(org_id)
        api_calls = await self._billing.get_usage(
            org_id, "api_calls", _period_key(utcnow())
        )
        return {
            "storage_bytes": storage,
            "seats": seats,
            "api_calls": api_calls,
            "storage_limit_bytes": limits.storage_bytes,
            "seat_limit": limits.max_seats,
        }

    async def list_invoices(self, org_id: str, user_id: str) -> list[Invoice]:
        await self._require_billing_admin(org_id, user_id)
        return await self._billing.list_invoices(org_id)
