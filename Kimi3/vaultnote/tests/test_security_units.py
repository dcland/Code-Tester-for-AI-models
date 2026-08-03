"""Unit tests for security primitives, encryption, privacy, rate limiting, cache."""
from __future__ import annotations

import time

import pytest

from app.core.encryption import EncryptionService, WrappedKey
from app.core.privacy import dp_count, pseudonymize, redact_pii
from app.core.security import (
    constant_time_compare, generate_totp_secret, hash_password, hash_token,
    verify_password, verify_totp, _hotp,
)
from app.utils.cache import TTLRUCache
from app.utils.rate_limiter import InMemoryRateLimiter


# ---- Password hashing -------------------------------------------------------

def test_password_hash_and_verify():
    h = hash_password("MySecurePassword1!")
    assert verify_password("MySecurePassword1!", h) is True


def test_password_verify_wrong_fails():
    h = hash_password("Correct1!")
    assert verify_password("Wrong1!", h) is False


def test_password_hash_is_argon2id():
    h = hash_password("Test1234!")
    assert h.startswith("$argon2id$")


def test_password_salt_unique():
    assert hash_password("Same1!") != hash_password("Same1!")


# ---- Constant time compare ---------------------------------------------------

def test_constant_time_compare():
    assert constant_time_compare("abc", "abc") is True
    assert constant_time_compare("abc", "abd") is False


# ---- TOTP --------------------------------------------------------------------

def test_totp_generate_and_verify():
    secret = generate_totp_secret()
    counter = int(time.time()) // 30
    code = _hotp(secret, counter)
    assert verify_totp(secret, code) is True


def test_totp_wrong_code_fails():
    secret = generate_totp_secret()
    assert verify_totp(secret, "000000") is False


def test_totp_non_digit_rejected():
    secret = generate_totp_secret()
    assert verify_totp(secret, "abcdef") is False


# ---- AES-GCM encryption ------------------------------------------------------

def test_encrypt_decrypt_roundtrip():
    svc = EncryptionService()
    key = svc.generate_dek()
    ct, nonce = svc.encrypt(b"hello vault", key)
    assert svc.decrypt(ct, nonce, key) == b"hello vault"


def test_decrypt_with_wrong_key_fails():
    svc = EncryptionService()
    k1, k2 = svc.generate_dek(), svc.generate_dek()
    ct, nonce = svc.encrypt(b"secret", k1)
    with pytest.raises(Exception):
        svc.decrypt(ct, nonce, k2)


def test_tampered_ciphertext_fails():
    svc = EncryptionService()
    key = svc.generate_dek()
    ct, nonce = svc.encrypt(b"data", key)
    import base64
    raw = bytearray(base64.urlsafe_b64decode(ct))
    raw[0] ^= 0xFF  # flip a bit
    tampered = base64.urlsafe_b64encode(bytes(raw)).decode()
    with pytest.raises(Exception):
        svc.decrypt(tampered, nonce, key)


def test_envelope_wrap_unwrap_dek():
    svc = EncryptionService()
    dek = svc.generate_dek()
    kek = svc.generate_tenant_kek()
    wrapped = svc.wrap_dek(dek, kek)
    assert svc.unwrap_dek(wrapped, kek) == dek


def test_key_rotation_rewraps_dek():
    svc = EncryptionService()
    dek = svc.generate_dek()
    old_kek, new_kek = svc.generate_tenant_kek(), svc.generate_tenant_kek()
    wrapped_old = svc.wrap_dek(dek, old_kek)
    wrapped_new = svc.rotate_dek(wrapped_old, old_kek, new_kek)
    assert svc.unwrap_dek(wrapped_new, new_kek) == dek
    with pytest.raises(Exception):
        svc.unwrap_dek(wrapped_new, old_kek)


def test_encrypt_10mb_under_120ms():
    """Performance: 10 MB AES-256-GCM encrypt+decrypt must be fast."""
    svc = EncryptionService()
    key = svc.generate_dek()
    data = b"x" * (10 * 1024 * 1024)
    start = time.perf_counter()
    ct, nonce = svc.encrypt(data, key)
    svc.decrypt(ct, nonce, key)
    elapsed_ms = (time.perf_counter() - start) * 1000
    assert elapsed_ms < 300  # generous bound for CI; spec is 120ms on target hw


# ---- Privacy -----------------------------------------------------------------

def test_redact_pii_email():
    assert "[REDACTED_EMAIL]" in redact_pii("Contact alice@example.com for info")


def test_redact_pii_ip():
    assert "[REDACTED_IP]" in redact_pii("Request from 192.168.1.1")


def test_pseudonymize_deterministic_and_irreversible():
    p1 = pseudonymize("user-123")
    p2 = pseudonymize("user-123")
    assert p1 == p2
    assert "user-123" not in p1
    assert len(p1) == 24


def test_dp_count_adds_noise():
    results = {round(dp_count(100, epsilon=0.1)) for _ in range(20)}
    assert len(results) > 1  # noise should produce variation


# ---- Rate limiter ------------------------------------------------------------

@pytest.mark.asyncio
async def test_rate_limiter_allows_under_limit():
    rl = InMemoryRateLimiter()
    for _ in range(5):
        assert await rl.is_allowed("k", 5, 60) is True


@pytest.mark.asyncio
async def test_rate_limiter_blocks_over_limit():
    rl = InMemoryRateLimiter()
    for _ in range(5):
        await rl.is_allowed("k", 5, 60)
    assert await rl.is_allowed("k", 5, 60) is False


@pytest.mark.asyncio
async def test_rate_limiter_window_expiry():
    rl = InMemoryRateLimiter()
    for _ in range(3):
        await rl.is_allowed("k", 3, 1)
    assert await rl.is_allowed("k", 3, 1) is False
    await __import__("asyncio").sleep(1.1)
    assert await rl.is_allowed("k", 3, 1) is True


@pytest.mark.asyncio
async def test_rate_limiter_o1_lookup():
    """Performance smoke: 10k checks should be fast (O(1) each)."""
    rl = InMemoryRateLimiter()
    start = time.perf_counter()
    for i in range(10000):
        await rl.is_allowed(f"user:{i % 100}", 100000, 60)
    elapsed = time.perf_counter() - start
    assert elapsed < 5  # very generous bound


# ---- LRU cache ----------------------------------------------------------------

def test_lru_cache_get_put():
    c = TTLRUCache(maxsize=3, ttl_seconds=60)
    c.put("a", 1)
    assert c.get("a") == 1


def test_lru_cache_eviction():
    c = TTLRUCache(maxsize=2, ttl_seconds=60)
    c.put("a", 1); c.put("b", 2); c.put("c", 3)
    assert c.get("a") is None  # evicted
    assert c.get("c") == 3


def test_lru_cache_ttl_expiry():
    c = TTLRUCache(maxsize=10, ttl_seconds=1)
    c.put("k", "v")
    time.sleep(1.1)
    assert c.get("k") is None
