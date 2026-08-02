"""Performance smoke tests (generous CI-safe thresholds)."""

from __future__ import annotations

import time

import pytest

from app.core.encryption import EnvelopeEncryptor

# asyncio_mode=auto auto-detects coroutine tests; the 10MB test is synchronous.


def test_encrypt_decrypt_10mb_is_fast():
    enc = EnvelopeEncryptor(b"K" * 32)
    tmk = enc.create_tenant_master_key()
    payload = b"\x00" * (10 * 1024 * 1024)

    start = time.perf_counter()
    env = enc.encrypt(tmk, payload)
    plain = enc.decrypt(tmk, env)
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert plain == payload
    # AES-NI hardware acceleration keeps this well under budget.
    assert elapsed_ms < 500, f"10MB round trip took {elapsed_ms:.1f}ms"


async def test_get_note_latency_p95(client, register_user):
    user = await register_user("perf@example.com")
    note = await client.post(f"/api/v1/organizations/{user.org_id}/notes",
                             headers=user.auth,
                             json={"title": "perf", "body": "x" * 1000})
    note_id = note.json()["id"]

    timings = []
    for _ in range(30):
        start = time.perf_counter()
        resp = await client.get(
            f"/api/v1/organizations/{user.org_id}/notes/{note_id}", headers=user.auth)
        timings.append((time.perf_counter() - start) * 1000)
        assert resp.status_code == 200

    timings.sort()
    p95 = timings[int(len(timings) * 0.95)]
    # Generous ceiling for CI; the LRU cache keeps hot reads fast.
    assert p95 < 250, f"p95 was {p95:.1f}ms"


async def test_hot_note_cache_is_used(container, register_user, client):
    user = await register_user("cache@example.com")
    note = await client.post(f"/api/v1/organizations/{user.org_id}/notes",
                             headers=user.auth, json={"title": "c", "body": "y"})
    note_id = note.json()["id"]
    container.note_cache.hits = 0
    container.note_cache.misses = 0
    for _ in range(5):
        await client.get(
            f"/api/v1/organizations/{user.org_id}/notes/{note_id}", headers=user.auth)
    # After the first read, subsequent decrypts should hit the cache.
    assert container.note_cache.hits >= 3
