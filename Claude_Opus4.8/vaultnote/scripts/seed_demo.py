"""Seed two demo organizations with users, notes, folders, and files.

Run:  python -m scripts.seed_demo

Creates a ready-to-explore dataset in the configured database (the on-disk
SQLite file by default) so the API can be demoed immediately. Idempotent-ish:
re-running creates fresh orgs; existing emails are skipped.
"""

from __future__ import annotations

import asyncio

import httpx
from httpx import ASGITransport

from app.core.container import Container
from app.main import create_app

DEMO_PASSWORD = "Demo!Password123"


async def _register_or_login(client: httpx.AsyncClient, email: str, org: str) -> dict:
    resp = await client.post("/api/v1/auth/register", json={
        "email": email, "password": DEMO_PASSWORD,
        "display_name": email.split("@")[0], "organization_name": org,
    })
    if resp.status_code == 201:
        return resp.json()
    # Already exists — log in instead.
    login = await client.post("/api/v1/auth/login",
                              json={"email": email, "password": DEMO_PASSWORD})
    login.raise_for_status()
    return login.json()


async def _seed_org(client: httpx.AsyncClient, owner_email: str, org_name: str,
                    member_email: str) -> None:
    owner = await _register_or_login(client, owner_email, org_name)
    headers = {"Authorization": f"Bearer {owner['access_token']}"}
    org_id = (await client.get("/api/v1/me/organizations", headers=headers)).json()[0]["id"]

    # A folder + a couple of encrypted notes.
    folder = await client.post(f"/api/v1/organizations/{org_id}/folders",
                               headers=headers, json={"name": "Onboarding"})
    folder_id = folder.json()["id"]
    for title, body in [
        ("Welcome", "This note is encrypted at rest with AES-256-GCM."),
        ("Roadmap", "Q3: real-time collaboration. Q4: mobile clients."),
    ]:
        await client.post(f"/api/v1/organizations/{org_id}/notes", headers=headers,
                          json={"title": title, "body": body, "folder_id": folder_id})

    # An encrypted file (a tiny PNG).
    png = b"\x89PNG\r\n\x1a\n" + b"demo-image-bytes" + b"\x00" * 32
    await client.post(
        f"/api/v1/organizations/{org_id}/files",
        headers={**headers, "X-Filename": "logo.png", "Content-Type": "image/png"},
        content=png)

    # Invite a second user as a member (must exist first).
    await _register_or_login(client, member_email, f"{org_name} (personal)")
    await client.post(f"/api/v1/organizations/{org_id}/members", headers=headers,
                      json={"email": member_email, "role": "member"})

    # Upgrade to a paid plan (proration invoice generated).
    await client.post(f"/api/v1/organizations/{org_id}/billing/plan", headers=headers,
                      json={"plan": "pro", "seats": 5, "payment_token": "tok_demo"})

    print(f"  seeded org '{org_name}' (id={org_id}) owner={owner_email}")


async def main() -> None:
    container = Container()
    await container.startup()
    app = create_app(container)
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport,
                                 base_url="http://demo") as client:
        print("Seeding demo data...")
        await _seed_org(client, "founder@acme.test", "Acme Corp", "eng@acme.test")
        await _seed_org(client, "owner@globex.test", "Globex Ltd", "ops@globex.test")
    await container.shutdown()
    print("Done. Demo users share the password:", DEMO_PASSWORD)


if __name__ == "__main__":
    asyncio.run(main())
