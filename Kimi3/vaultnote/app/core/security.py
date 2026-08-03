"""
Security primitives: password hashing (Argon2id + pepper), JWT tokens,
TOTP 2FA, constant-time comparison helpers, token generation.

OWASP ASVS L2 compliant.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError, VerifyMismatchError
from jose import JWTError, jwt

from app.core.config import settings

# Argon2id parameters per OWASP recommendation (memory-hard, side-channel resistant)
_ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MiB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def hash_password(password: str) -> str:
    """Hash password with Argon2id + server-side pepper.

    The pepper is a secret stored outside the DB so a DB dump alone
    cannot be used for offline password cracking.
    """
    peppered = password + settings.PASSWORD_PEPPER
    return _ph.hash(peppered)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Constant-time password verification.

    Returns False on any error (never raises) to avoid oracle leaks.
    """
    try:
        peppered = plain_password + settings.PASSWORD_PEPPER
        return _ph.verify(hashed_password, peppered)
    except (VerifyMismatchError, VerificationError, InvalidHash, Exception):
        return False


def constant_time_compare(a: str | bytes, b: str | bytes) -> bool:
    """Timing-attack-safe comparison (OWASP)."""
    if isinstance(a, str):
        a = a.encode()
    if isinstance(b, str):
        b = b.encode()
    return hmac.compare_digest(a, b)


def hash_token(token: str) -> str:
    """SHA-256 hash of a refresh token for at-rest storage.

    Refresh tokens are stored hashed so a DB leak does not expose live sessions.
    """
    return hashlib.sha256(token.encode()).hexdigest()


def create_access_token(subject: str | UUID, extra_claims: dict[str, Any] | None = None) -> str:
    """Create a short-lived JWT access token."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload: dict[str, Any] = {
        "sub": str(subject),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": str(uuid4()),
        "type": "access",
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict[str, Any] | None:
    """Decode and validate a JWT. Returns None on any failure (no oracle)."""
    try:
        return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        return None


def generate_refresh_token() -> str:
    """Cryptographically secure random refresh token."""
    return secrets.token_urlsafe(64)


def generate_secure_token(nbytes: int = 32) -> str:
    """General-purpose secure token (password reset, download links, etc.)."""
    return secrets.token_urlsafe(nbytes)


# ---------------------------------------------------------------------------
# TOTP (RFC 6238) - pure-Python implementation, no external dependency
# ---------------------------------------------------------------------------

def generate_totp_secret() -> str:
    """Base32-encoded TOTP secret."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret: str, counter: int, digits: int = 6) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """Verify a TOTP code with a +/-window tolerance for clock drift.

    Uses constant-time comparison on each candidate to prevent timing attacks.
    """
    if not code or not code.isdigit():
        return False
    counter = int(time.time()) // 30
    for w in range(-window, window + 1):
        expected = _hotp(secret, counter + w)
        if constant_time_compare(expected, code):
            return True
    return False
