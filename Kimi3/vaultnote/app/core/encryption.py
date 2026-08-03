"""
Envelope encryption using AES-256-GCM.

Architecture (zero-knowledge friendly):
    - Each note/file has a unique Data Encryption Key (DEK).
    - Each DEK is encrypted ("wrapped") with the tenant Key Encryption Key (KEK).
    - Each tenant KEK is encrypted with the application Master Key.
    - Key rotation re-wraps DEKs with a new KEK without touching plaintext.

AES-GCM provides authenticated encryption (confidentiality + integrity).
"""
from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings

_NONCE_LEN = 12  # 96-bit nonce recommended for AES-GCM
_KEY_LEN = 32    # AES-256


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode())


def _master_key() -> bytes:
    """Derive a 32-byte master key from the configured secret.

    In production this would come from a KMS/HSM; here we SHA-256 the env secret.
    """
    import hashlib
    return hashlib.sha256(settings.MASTER_ENCRYPTION_KEY.encode()).digest()


@dataclass(frozen=True)
class WrappedKey:
    """An encrypted DEK together with its nonce (safe to store in DB)."""
    ciphertext: str
    nonce: str


class EncryptionService:
    """Server-side envelope encryption service."""

    # ---- DEK lifecycle -------------------------------------------------
    @staticmethod
    def generate_dek() -> bytes:
        """Generate a fresh 256-bit Data Encryption Key."""
        return AESGCM.generate_key(bit_length=256)

    # ---- Symmetric encrypt/decrypt ------------------------------------
    @staticmethod
    def encrypt(data: bytes, key: bytes) -> tuple[str, str]:
        """Encrypt data with AES-256-GCM. Returns (ciphertext_b64, nonce_b64)."""
        if len(key) != _KEY_LEN:
            raise ValueError("Key must be 32 bytes for AES-256")
        nonce = os.urandom(_NONCE_LEN)
        ct = AESGCM(key).encrypt(nonce, data, None)
        return _b64e(ct), _b64e(nonce)

    @staticmethod
    def decrypt(ciphertext_b64: str, nonce_b64: str, key: bytes) -> bytes:
        """Decrypt AES-256-GCM ciphertext. Raises on tampering (auth tag check)."""
        return AESGCM(key).decrypt(_b64d(nonce_b64), _b64d(ciphertext_b64), None)

    # ---- Envelope: wrap/unwrap DEK with KEK ---------------------------
    @classmethod
    def wrap_dek(cls, dek: bytes, kek: bytes) -> WrappedKey:
        ct, nonce = cls.encrypt(dek, kek)
        return WrappedKey(ciphertext=ct, nonce=nonce)

    @classmethod
    def unwrap_dek(cls, wrapped: WrappedKey, kek: bytes) -> bytes:
        return cls.decrypt(wrapped.ciphertext, wrapped.nonce, kek)

    # ---- Tenant KEK lifecycle -----------------------------------------
    @classmethod
    def generate_tenant_kek(cls) -> bytes:
        return AESGCM.generate_key(bit_length=256)

    @classmethod
    def encrypt_kek(cls, kek: bytes) -> WrappedKey:
        """Encrypt tenant KEK with master key for storage."""
        return cls.wrap_dek(kek, _master_key())

    @classmethod
    def decrypt_kek(cls, wrapped: WrappedKey) -> bytes:
        return cls.unwrap_dek(wrapped, _master_key())

    # ---- Key rotation ---------------------------------------------------
    @classmethod
    def rotate_dek(cls, wrapped: WrappedKey, old_kek: bytes, new_kek: bytes) -> WrappedKey:
        """Re-wrap a DEK under a new KEK (key rotation).

        GDPR Art. 32 - supports cryptographic key rotation without data loss.
        """
        dek = cls.unwrap_dek(wrapped, old_kek)
        return cls.wrap_dek(dek, new_kek)


# Convenience singleton
encryption_service = EncryptionService()
