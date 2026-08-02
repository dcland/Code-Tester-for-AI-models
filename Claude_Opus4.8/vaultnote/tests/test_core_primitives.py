"""Unit tests for security/privacy/crypto primitives (no DB / HTTP)."""

from __future__ import annotations

import time

import pytest

from app.core.cache import LRUCache
from app.core.encryption import EncryptionError, EnvelopeEncryptor, generate_key
from app.core.privacy import DifferentialPrivacy, pseudonymize, redact
from app.core.ratelimit import RateLimit, InMemorySlidingWindow


def test_envelope_round_trip():
    enc = EnvelopeEncryptor(b"K" * 32)
    tmk = enc.create_tenant_master_key()
    env = enc.encrypt(tmk, b"top secret note")
    assert enc.decrypt(tmk, env) == b"top secret note"


def test_envelope_detects_tampering():
    enc = EnvelopeEncryptor(b"K" * 32)
    tmk = enc.create_tenant_master_key()
    env = enc.encrypt(tmk, b"data")
    tampered = type(env)(ciphertext=env.ciphertext[:-1] + bytes([env.ciphertext[-1] ^ 1]),
                         wrapped_dek=env.wrapped_dek)
    with pytest.raises(EncryptionError):
        enc.decrypt(tmk, tampered)


def test_envelope_aad_binding_prevents_replay():
    enc = EnvelopeEncryptor(b"K" * 32)
    tmk = enc.create_tenant_master_key()
    (ct,), wrapped = enc.encrypt_many(tmk, [b"body"], aad=b"note:org1:n1")
    # Same ciphertext cannot be decrypted under a different AAD (object/tenant).
    with pytest.raises(EncryptionError):
        enc.decrypt_many(tmk, wrapped, [ct], aad=b"note:org2:n1")


def test_key_rotation_preserves_plaintext():
    enc = EnvelopeEncryptor(b"K" * 32)
    tmk = enc.create_tenant_master_key()
    (ct,), wrapped = enc.encrypt_many(tmk, [b"hello"])
    new_tmk, (new_wrapped,) = enc.rotate_tenant_key(tmk, [wrapped])
    assert enc.decrypt_many(new_tmk, new_wrapped, [ct]) == [b"hello"]
    # Old wrapped DEK no longer opens under the new tenant key.
    with pytest.raises(EncryptionError):
        enc.decrypt_many(new_tmk, wrapped, [ct])


def test_wrong_master_kek_cannot_unwrap():
    enc = EnvelopeEncryptor(b"K" * 32)
    tmk = enc.create_tenant_master_key()
    other = EnvelopeEncryptor(b"Z" * 32)
    with pytest.raises(EncryptionError):
        other.decrypt(tmk, enc.encrypt(tmk, b"x"))


def test_redact_masks_pii():
    msg = "user alice@example.com from 10.1.2.3 token Bearer abc.def.ghi"
    out = redact(msg)
    assert "alice@example.com" not in out
    assert "10.1.2.3" not in out
    assert "[REDACTED_EMAIL]" in out


def test_pseudonymize_is_stable_and_keyed():
    a = pseudonymize("user-123", "salt")
    b = pseudonymize("user-123", "salt")
    c = pseudonymize("user-123", "other-salt")
    assert a == b and a != c
    assert "user-123" not in a


def test_differential_privacy_is_noisy_but_bounded():
    dp = DifferentialPrivacy(epsilon=0.5)
    samples = [dp.privatize_count(100) for _ in range(200)]
    assert any(s != 100 for s in samples)         # noise is actually applied
    assert all(s >= 0 for s in samples)           # never negative
    assert abs(sum(samples) / len(samples) - 100) < 15  # roughly unbiased


def test_dp_rejects_bad_epsilon():
    with pytest.raises(ValueError):
        DifferentialPrivacy(0)


def test_lru_cache_evicts_and_expires():
    clock = [0.0]
    cache: LRUCache = LRUCache(capacity=2, ttl_seconds=10, clock=lambda: clock[0])
    cache.put("a", 1)
    cache.put("b", 2)
    cache.put("c", 3)          # evicts "a" (LRU)
    assert cache.get("a") is None
    assert cache.get("b") == 2
    clock[0] = 100             # everything now expired
    assert cache.get("b") is None


@pytest.mark.asyncio
async def test_rate_limiter_sliding_window():
    clock = [0.0]
    rl = InMemorySlidingWindow(clock=lambda: clock[0])
    rule = RateLimit(limit=3, window_seconds=60)
    for _ in range(3):
        assert (await rl.check("k", rule)).allowed
    blocked = await rl.check("k", rule)
    assert not blocked.allowed and blocked.retry_after >= 1
    clock[0] = 61              # window slides forward
    assert (await rl.check("k", rule)).allowed
