"""
VaultNote configuration management.

SECURITY: All secrets MUST come from environment variables.
No secrets are ever hardcoded or committed to source control.

Fail-closed: when ENVIRONMENT is production, the application refuses to
start unless every secret is explicitly provided. Random per-process
fallbacks exist for local development only.
"""
from __future__ import annotations

import logging
import secrets
from functools import lru_cache

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("vaultnote.config")

_PRODUCTION_VALUES = {"production", "prod"}


class Settings(BaseSettings):
    """Application settings loaded exclusively from environment variables.

    GDPR Art. 25 - Data protection by design and by default:
    defaults are the most privacy-preserving values.
    """

    model_config = SettingsConfigDict(env_prefix="VAULTNOTE_", env_file=".env", extra="ignore")

    # --- Core ---
    APP_NAME: str = "VaultNote"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"

    # --- Security secrets (MUST be set in production) ---
    # These default to None so we can detect "unset" and fail closed in
    # production. In development a random per-process value is generated.
    JWT_SECRET_KEY: str | None = None
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    PASSWORD_RESET_TTL_SECONDS: int = 900  # 15 minutes

    # Argon2 server-side pepper - adds defense-in-depth beyond per-user salt
    PASSWORD_PEPPER: str | None = None

    # Master key for envelope encryption of tenant KEKs (32 bytes, base64-urlsafe)
    # In production this should come from a KMS/HSM. For demo we derive from env.
    MASTER_ENCRYPTION_KEY: str | None = None

    # Dedicated salt for HMAC-based pseudonymization (GDPR Art. 4(5)).
    # Kept separate from the JWT secret so pseudonyms cannot be cross-linked
    # with token-signing material.
    PSEUDONYM_SALT: str | None = None

    # Key used to HMAC-sign audit log entries (tamper-evident chain).
    AUDIT_HMAC_KEY: str | None = None

    # --- Database ---
    DATABASE_URL: str = "sqlite+aiosqlite:///./vaultnote.db"

    # --- Redis (optional; pure-Python fallback if unavailable) ---
    REDIS_URL: str | None = None

    # --- Rate limiting ---
    RATE_LIMIT_DEFAULT: int = 100  # requests per window
    RATE_LIMIT_WINDOW_SECONDS: int = 60
    RATE_LIMIT_AUTH: int = 10  # stricter for auth endpoints
    RATE_LIMIT_AUTH_WINDOW_SECONDS: int = 300

    # --- Files ---
    MAX_FILE_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB
    FILE_STORAGE_PATH: str = "./storage/files"
    DOWNLOAD_TOKEN_EXPIRE_SECONDS: int = 300  # 5 minutes

    # --- Billing ---
    BILLING_ENABLED: bool = True

    # --- Privacy / Analytics ---
    # Differential privacy epsilon (lower = more privacy, more noise)
    DP_EPSILON: float = 1.0

    # --- Compliance / Retention (GDPR Art. 5(1)(e) storage limitation) ---
    RETENTION_DAYS_FREE: int = 30
    RETENTION_DAYS_PAID: int = 365
    AUDIT_LOG_RETENTION_DAYS: int = 2555  # 7 years for SOC 2
    # Automatic retention enforcement interval (24h). The scheduled job runs
    # in the background and applies each tenant's plan-specific window.
    RETENTION_PURGE_INTERVAL_SECONDS: int = 24 * 60 * 60

    # --- CORS ---
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]

    @field_validator("JWT_ALGORITHM")
    @classmethod
    def _alg_must_be_secure(cls, v: str) -> str:
        # OWASP: forbid 'none' and weak algorithms
        if v.lower() in ("none", "hs224"):
            raise ValueError("Insecure JWT algorithm")
        return v

    @model_validator(mode="after")
    def _enforce_secrets(self) -> Settings:
        """Fail closed in production; generate ephemeral secrets in dev only.

        A production deployment without managed secrets would silently
        invalidate every token and all encrypted data on restart, so it is
        safer to refuse to boot.
        """
        required = (
            "JWT_SECRET_KEY",
            "PASSWORD_PEPPER",
            "MASTER_ENCRYPTION_KEY",
            "PSEUDONYM_SALT",
            "AUDIT_HMAC_KEY",
        )
        if self.ENVIRONMENT.lower() in _PRODUCTION_VALUES:
            missing = [name for name in required if not getattr(self, name)]
            if missing:
                raise ValueError(
                    "Production secrets missing; refusing to start. "
                    f"Set these environment variables: {', '.join(missing)}"
                )
        else:
            for name in required:
                if not getattr(self, name):
                    object.__setattr__(self, name, secrets.token_urlsafe(48))
                    logger.warning(
                        "%s not set; generated an ephemeral development value. "
                        "Do NOT run like this in production.", name,
                    )
        return self


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton - O(1) access after first load."""
    return Settings()


settings = get_settings()
