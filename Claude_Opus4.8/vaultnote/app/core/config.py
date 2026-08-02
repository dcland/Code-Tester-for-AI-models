"""Application configuration.

Security by Design (GDPR Art. 25): every secret (JWT signing key, encryption
master key, password pepper) is loaded from the environment only. Nothing
sensitive is ever hard-coded. In a non-production environment we deterministically
derive throwaway development secrets so the demo runs with a single command, but
`ENVIRONMENT=production` forces every secret to be supplied explicitly.
"""

from __future__ import annotations

import base64
import hashlib
import os
from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _dev_secret(label: str, length: int = 32) -> str:
    """Derive a deterministic, non-secret development key.

    Used ONLY when ENVIRONMENT != production so the app boots without manual
    setup. Never used in production because `Settings` rejects missing secrets
    there.
    """
    digest = hashlib.sha256(f"vaultnote-dev::{label}".encode()).digest()[:length]
    return base64.urlsafe_b64encode(digest).decode()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="VAULTNOTE_",
        env_file=os.getenv("VAULTNOTE_ENV_FILE", ".env"),
        extra="ignore",
    )

    # --- Environment -------------------------------------------------------
    environment: Literal["development", "test", "production"] = "development"
    app_name: str = "VaultNote"
    debug: bool = False

    # --- Database ----------------------------------------------------------
    # Async SQLAlchemy URL. Defaults to an on-disk SQLite file for the demo.
    database_url: str = "sqlite+aiosqlite:///./vaultnote.db"

    # --- Secrets (env only) ------------------------------------------------
    jwt_secret: str = Field(default="")
    password_pepper: str = Field(default="")
    # Base64 urlsafe 32-byte key encrypting per-tenant master keys (the KEK).
    master_kek: str = Field(default="")

    # --- Auth / tokens -----------------------------------------------------
    jwt_algorithm: str = "HS256"
    access_token_ttl_seconds: int = 15 * 60           # 15 minutes
    refresh_token_ttl_seconds: int = 7 * 24 * 60 * 60  # 7 days
    password_reset_ttl_seconds: int = 30 * 60          # 30 minutes
    max_failed_logins: int = 5
    lockout_seconds: int = 15 * 60

    # --- Argon2id parameters (OWASP-recommended baseline) ------------------
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 64 * 1024  # 64 MiB
    argon2_parallelism: int = 2

    # --- Rate limiting -----------------------------------------------------
    redis_url: str | None = None  # if None -> pure-Python in-memory fallback

    # --- Files -------------------------------------------------------------
    storage_dir: str = "./var/storage"
    max_upload_bytes: int = 25 * 1024 * 1024  # 25 MiB
    download_token_ttl_seconds: int = 5 * 60

    # --- Privacy / analytics ----------------------------------------------
    default_dp_epsilon: float = 1.0
    analytics_pseudonym_salt: str = Field(default="")

    # --- Compliance --------------------------------------------------------
    retention_days_free: int = 30    # GDPR Art. 5(1)(e) storage limitation
    retention_days_paid: int = 365

    @field_validator("jwt_secret", "password_pepper", "master_kek",
                     "analytics_pseudonym_salt", mode="before")
    @classmethod
    def _fill_dev_secret(cls, v, info):  # type: ignore[no-untyped-def]
        if v:
            return v
        # Only auto-fill outside production.
        env = os.getenv("VAULTNOTE_ENVIRONMENT", "development")
        if env == "production":
            return v  # leave empty -> validated below
        return _dev_secret(info.field_name)

    @field_validator("master_kek")
    @classmethod
    def _validate_kek(cls, v: str) -> str:
        # Ensure the KEK decodes to exactly 32 bytes (AES-256).
        raw = base64.urlsafe_b64decode(v.encode())
        if len(raw) != 32:
            raise ValueError("master_kek must decode to 32 bytes (AES-256)")
        return v

    def require_production_secrets(self) -> None:
        if self.environment == "production":
            missing = [
                name for name in ("jwt_secret", "password_pepper", "master_kek",
                                  "analytics_pseudonym_salt")
                if not getattr(self, name)
            ]
            if missing:
                raise RuntimeError(
                    f"Missing required production secrets: {', '.join(missing)}"
                )

    @property
    def master_kek_bytes(self) -> bytes:
        return base64.urlsafe_b64decode(self.master_kek.encode())


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.require_production_secrets()
    return settings
