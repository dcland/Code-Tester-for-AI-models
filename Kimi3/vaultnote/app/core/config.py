"""
VaultNote configuration management.

SECURITY: All secrets MUST come from environment variables.
No secrets are ever hardcoded or committed to source control.
"""
from __future__ import annotations

import secrets
from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    # JWT signing key - load from env; dev fallback is randomly generated per process
    JWT_SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(64))
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Argon2 server-side pepper - adds defense-in-depth beyond per-user salt
    PASSWORD_PEPPER: str = Field(default_factory=lambda: secrets.token_urlsafe(32))

    # Master key for envelope encryption of tenant KEKs (32 bytes, base64-urlsafe)
    # In production this should come from a KMS/HSM. For demo we derive from env.
    MASTER_ENCRYPTION_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))

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

    # --- CORS ---
    CORS_ORIGINS: List[str] = ["http://localhost:3000"]

    @field_validator("JWT_ALGORITHM")
    @classmethod
    def _alg_must_be_secure(cls, v: str) -> str:
        # OWASP: forbid 'none' and weak algorithms
        if v.lower() in ("none", "hs224"):
            raise ValueError("Insecure JWT algorithm")
        return v


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton - O(1) access after first load."""
    return Settings()


settings = get_settings()
