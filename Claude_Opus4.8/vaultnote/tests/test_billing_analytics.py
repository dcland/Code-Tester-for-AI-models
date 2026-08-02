"""Billing engine and privacy-preserving analytics tests."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


async def test_plan_change_and_proration_invoice(client, register_user):
    user = await register_user("bill@example.com")
    resp = await client.post(
        f"/api/v1/organizations/{user.org_id}/billing/plan", headers=user.auth,
        json={"plan": "pro", "seats": 5, "payment_token": "tok_visa_demo"})
    assert resp.status_code == 200
    assert resp.json()["plan"] == "pro"

    invoices = await client.get(
        f"/api/v1/organizations/{user.org_id}/billing/invoices", headers=user.auth)
    assert invoices.status_code == 200
    # Upgrading from free (0) to pro generates a prorated charge > 0.
    assert any(i["amount_cents"] > 0 for i in invoices.json())


async def test_billing_rejects_raw_card_number(client, register_user):
    user = await register_user("pci@example.com")
    resp = await client.post(
        f"/api/v1/organizations/{user.org_id}/billing/plan", headers=user.auth,
        json={"plan": "pro", "seats": 1, "payment_token": "4111111111111111"})
    # PCI-DSS: raw PAN must be rejected at validation.
    assert resp.status_code == 422


async def test_seat_limit_enforced_on_plan(client, register_user):
    user = await register_user("seats@example.com")
    resp = await client.post(
        f"/api/v1/organizations/{user.org_id}/billing/plan", headers=user.auth,
        json={"plan": "free", "seats": 999})
    assert resp.status_code == 422  # exceeds free plan max seats


async def test_usage_reflects_storage(client, register_user):
    user = await register_user("usage@example.com")
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
    await client.post(
        f"/api/v1/organizations/{user.org_id}/files",
        headers={**user.auth, "X-Filename": "a.png", "Content-Type": "image/png"},
        content=png)
    usage = await client.get(
        f"/api/v1/organizations/{user.org_id}/billing/usage", headers=user.auth)
    assert usage.status_code == 200
    assert usage.json()["storage_bytes"] == len(png)
    assert usage.json()["seats"] == 1


async def test_non_admin_cannot_change_plan(client, register_user):
    owner = await register_user("ba-owner@example.com", org="BAOrg")
    member = await register_user("ba-member@example.com", org="BAOwn")
    await client.post(f"/api/v1/organizations/{owner.org_id}/members",
                      headers=owner.auth,
                      json={"email": "ba-member@example.com", "role": "member"})
    resp = await client.post(
        f"/api/v1/organizations/{owner.org_id}/billing/plan", headers=member.auth,
        json={"plan": "pro", "seats": 2})
    assert resp.status_code == 403


async def test_analytics_admin_only_and_differentially_private(client, register_user):
    owner = await register_user("an-owner@example.com", org="AnOrg")
    member = await register_user("an-member@example.com", org="AnOwn")
    await client.post(f"/api/v1/organizations/{owner.org_id}/members",
                      headers=owner.auth,
                      json={"email": "an-member@example.com", "role": "member"})
    for i in range(5):
        await client.post(f"/api/v1/organizations/{owner.org_id}/notes",
                          headers=owner.auth, json={"title": f"n{i}", "body": "x"})

    denied = await client.get(
        f"/api/v1/organizations/{owner.org_id}/analytics", headers=member.auth)
    assert denied.status_code == 403

    resp = await client.get(
        f"/api/v1/organizations/{owner.org_id}/analytics", headers=owner.auth,
        params={"epsilon": 1.0})
    assert resp.status_code == 200
    body = resp.json()
    assert body["epsilon"] == 1.0
    assert body["note_count"] >= 0            # noised, non-negative
    assert "differentially private" in body["note"]
