"""Password hashing, token issuance, TOTP, and constant-time helpers.

- Passwords: Argon2id with a *server-side pepper* (HMAC applied before hashing),
  so a database leak alone cannot be brute-forced without the env pepper.
- Tokens: short-lived JWT access tokens + opaque rotating refresh tokens stored
  only as SHA-256 hashes.
- All secret comparisons are constant-time (OWASP — timing attack resistance).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError

from app.core.config import Settings

class SecurityService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._pepper = settings.password_pepper.encode()
        self._hasher = PasswordHasher(
            time_cost=settings.argon2_time_cost,
            memory_cost=settings.argon2_memory_cost,
            parallelism=settings.argon2_parallelism,
            type=Type.ID,
        )
        # Real dummy hash for constant-time "user not found" path.
        self._dummy_hash = self._hasher.hash(self._pepper_password("x" * 16))

    # --- Password hashing --------------------------------------------------
    def _pepper_password(self, password: str) -> str:
        """Apply the server-side pepper via HMAC-SHA256 before Argon2.

        Encoding to base64 keeps the input printable and bounded in length,
        preventing Argon2 password-length DoS with huge inputs.
        """
        mac = hmac.new(self._pepper, password.encode("utf-8"), hashlib.sha256)
        return base64.b64encode(mac.digest()).decode("ascii")

    def hash_password(self, password: str) -> str:
        return self._hasher.hash(self._pepper_password(password))

    def verify_password(self, password: str, stored_hash: str | None) -> bool:
        """Constant-ish time password verify.

        When ``stored_hash`` is None (unknown user) we still perform a hash
        verification against a dummy to keep timing uniform.
        """
        candidate = self._pepper_password(password)
        target = stored_hash or self._dummy_hash
        try:
            self._hasher.verify(target, candidate)
            return stored_hash is not None
        except VerifyMismatchError:
            return False
        except Exception:
            return False

    def needs_rehash(self, stored_hash: str) -> bool:
        return self._hasher.check_needs_rehash(stored_hash)

    # --- JWT access tokens -------------------------------------------------
    def issue_access_token(self, *, user_id: str, org_id: str | None,
                           role: str | None, session_id: str) -> str:
        now = int(time.time())
        payload = {
            "sub": user_id,
            "org": org_id,
            "role": role,
            "sid": session_id,
            "type": "access",
            "iat": now,
            "nbf": now,
            "exp": now + self._settings.access_token_ttl_seconds,
            "jti": secrets.token_urlsafe(12),
        }
        return jwt.encode(payload, self._settings.jwt_secret,
                          algorithm=self._settings.jwt_algorithm)

    def decode_access_token(self, token: str) -> dict:
        return jwt.decode(
            token,
            self._settings.jwt_secret,
            algorithms=[self._settings.jwt_algorithm],
            options={"require": ["exp", "sub", "type"]},
        )

    def issue_scoped_token(self, *, purpose: str, ttl_seconds: int,
                           claims: dict) -> str:
        """Issue a short-lived signed token for a narrow purpose (e.g. download).

        Bound to ``purpose`` so a token minted for one action can't be replayed
        for another.
        """
        now = int(time.time())
        payload = {
            **claims,
            "type": purpose,
            "iat": now,
            "nbf": now,
            "exp": now + ttl_seconds,
            "jti": secrets.token_urlsafe(9),
        }
        return jwt.encode(payload, self._settings.jwt_secret,
                          algorithm=self._settings.jwt_algorithm)

    def decode_scoped_token(self, token: str, *, purpose: str) -> dict:
        payload = jwt.decode(
            token, self._settings.jwt_secret,
            algorithms=[self._settings.jwt_algorithm],
            options={"require": ["exp", "type"]},
        )
        if payload.get("type") != purpose:
            from app.core.exceptions import InvalidTokenError
            raise InvalidTokenError("token purpose mismatch")
        return payload

    # --- Refresh tokens (opaque, hashed at rest) ---------------------------
    @staticmethod
    def generate_refresh_token() -> str:
        return secrets.token_urlsafe(48)

    @staticmethod
    def hash_token(token: str) -> str:
        """SHA-256 is appropriate for high-entropy random tokens (not passwords)."""
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def constant_time_equals(a: str, b: str) -> bool:
        return hmac.compare_digest(a.encode(), b.encode())

    # --- Opaque single-use secrets (password reset, share links) -----------
    @staticmethod
    def generate_opaque_secret(nbytes: int = 32) -> str:
        return secrets.token_urlsafe(nbytes)

    # --- TOTP 2FA (RFC 6238) ----------------------------------------------
    @staticmethod
    def generate_totp_secret() -> str:
        return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")

    @staticmethod
    def _hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
        key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
        msg = struct.pack(">Q", counter)
        digest = hmac.new(key, msg, hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF)
        return str(code % (10 ** digits)).zfill(digits)

    @classmethod
    def verify_totp(cls, secret_b32: str, code: str, *, window: int = 1,
                    period: int = 30, at: int | None = None) -> bool:
        if not code or not code.isdigit():
            return False
        now = int(at if at is not None else time.time())
        counter = now // period
        for drift in range(-window, window + 1):
            expected = cls._hotp(secret_b32, counter + drift)
            if hmac.compare_digest(expected, code):
                return True
        return False

    def now(self) -> datetime:
        # Naive UTC to match the DB convention (see app.db.base.utcnow).
        return datetime.now(timezone.utc).replace(tzinfo=None)

    def refresh_expiry(self) -> datetime:
        return self.now() + timedelta(seconds=self._settings.refresh_token_ttl_seconds)
