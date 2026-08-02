"""Sharing and public share-link tests."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


async def _make_note(client, user, title="S", body="B"):
    resp = await client.post(f"/api/v1/organizations/{user.org_id}/notes",
                             headers=user.auth, json={"title": title, "body": body})
    return resp.json()


async def test_direct_share_grants_read(client, register_user):
    owner = await register_user("s-owner@example.com", org="ShareOrg")
    grantee = await register_user("s-grantee@example.com", org="GranteeOwn")
    await client.post(f"/api/v1/organizations/{owner.org_id}/members",
                      headers=owner.auth,
                      json={"email": "s-grantee@example.com", "role": "member"})
    note = await _make_note(client, owner, "Shared note", "secret body")

    # Before sharing: grantee cannot read.
    denied = await client.get(
        f"/api/v1/organizations/{owner.org_id}/notes/{note['id']}",
        headers=grantee.auth)
    assert denied.status_code == 403

    share = await client.post(
        f"/api/v1/organizations/{owner.org_id}/notes/{note['id']}/shares",
        headers=owner.auth,
        json={"grantee_user_id": grantee.user_id, "permission": "read"})
    assert share.status_code == 204

    allowed = await client.get(
        f"/api/v1/organizations/{owner.org_id}/notes/{note['id']}",
        headers=grantee.auth)
    assert allowed.status_code == 200
    assert allowed.json()["body"] == "secret body"


async def test_read_share_cannot_write(client, register_user):
    owner = await register_user("s2-owner@example.com", org="RW")
    grantee = await register_user("s2-grantee@example.com", org="RWown")
    await client.post(f"/api/v1/organizations/{owner.org_id}/members",
                      headers=owner.auth,
                      json={"email": "s2-grantee@example.com", "role": "member"})
    note = await _make_note(client, owner)
    await client.post(
        f"/api/v1/organizations/{owner.org_id}/notes/{note['id']}/shares",
        headers=owner.auth,
        json={"grantee_user_id": grantee.user_id, "permission": "read"})
    # Read granted, but write must be denied.
    resp = await client.patch(
        f"/api/v1/organizations/{owner.org_id}/notes/{note['id']}",
        headers=grantee.auth, json={"body": "hacked"})
    assert resp.status_code == 403


async def test_public_share_link_with_password_and_expiry(client, register_user):
    owner = await register_user("link@example.com")
    note = await _make_note(client, owner, "Link note", "link body")
    created = await client.post(
        f"/api/v1/organizations/{owner.org_id}/notes/{note['id']}/share-links",
        headers=owner.auth,
        json={"permission": "read", "password": "hunter2", "expires_in_seconds": 3600})
    assert created.status_code == 201
    token = created.json()["url_token"]

    # Wrong password rejected.
    bad = await client.post(f"/api/v1/shared/{token}", json={"password": "wrong"})
    assert bad.status_code == 401
    # Correct password grants read without any account/session.
    good = await client.post(f"/api/v1/shared/{token}", json={"password": "hunter2"})
    assert good.status_code == 200
    assert good.json()["body"] == "link body"


async def test_invalid_share_link_404(client):
    resp = await client.post("/api/v1/shared/nonexistenttoken", json={})
    assert resp.status_code == 404


async def test_cannot_share_with_non_member(client, register_user):
    owner = await register_user("ns-owner@example.com")
    outsider = await register_user("ns-out@example.com", org="Outsider")
    note = await _make_note(client, owner)
    resp = await client.post(
        f"/api/v1/organizations/{owner.org_id}/notes/{note['id']}/shares",
        headers=owner.auth,
        json={"grantee_user_id": outsider.user_id, "permission": "read"})
    assert resp.status_code == 422  # grantee not a member of this tenant
