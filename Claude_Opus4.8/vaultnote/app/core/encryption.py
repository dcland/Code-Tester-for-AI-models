"""Envelope encryption using AES-256-GCM.

Design (zero-knowledge friendly, GDPR Art. 32 — encryption of personal data):

    master KEK (env only, 32 bytes)
        └─ encrypts each *tenant master key* (TMK, 32 bytes, per organization)
                └─ encrypts each *data encryption key* (DEK, 32 bytes, per note/file)
                        └─ encrypts the actual note body / file bytes

Only the DEK ever touches plaintext data, and DEKs are themselves stored
encrypted. Rotating a tenant master key only requires re-wrapping DEKs, never
re-encrypting note/file payloads — an O(number-of-objects) metadata operation.

AES-GCM provides confidentiality *and* integrity (auth tag). Every operation
uses a fresh 96-bit random nonce; nonce||ciphertext||tag is returned as one blob.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12  # 96-bit nonce recommended for GCM
KEY_SIZE = 32    # AES-256


class EncryptionError(Exception):
    """Raised when decryption fails (tampering, wrong key, corruption)."""


def generate_key() -> bytes:
    """Return a fresh 256-bit key from a CSPRNG."""
    return os.urandom(KEY_SIZE)


def _seal(key: bytes, plaintext: bytes, aad: bytes | None = None) -> bytes:
    if len(key) != KEY_SIZE:
        raise EncryptionError("invalid key length")
    nonce = os.urandom(NONCE_SIZE)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ct


def _open(key: bytes, blob: bytes, aad: bytes | None = None) -> bytes:
    if len(key) != KEY_SIZE:
        raise EncryptionError("invalid key length")
    if len(blob) < NONCE_SIZE + 16:
        raise EncryptionError("ciphertext too short")
    nonce, ct = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    try:
        return AESGCM(key).decrypt(nonce, ct, aad)
    except Exception as exc:  # cryptography raises InvalidTag
        raise EncryptionError("decryption failed") from exc


@dataclass(frozen=True)
class Envelope:
    """A payload plus the wrapped DEK required to open it."""

    ciphertext: bytes       # nonce||ct||tag of the payload under the DEK
    wrapped_dek: bytes      # nonce||ct||tag of the DEK under the TMK


class EnvelopeEncryptor:
    """Performs the three-tier envelope operations.

    ``master_kek`` is the root key from the environment. Tenant master keys are
    supplied wrapped (as stored in the DB) and unwrapped on demand — the
    unwrapped TMK is never persisted.
    """

    def __init__(self, master_kek: bytes) -> None:
        if len(master_kek) != KEY_SIZE:
            raise EncryptionError("master_kek must be 32 bytes")
        self._kek = master_kek

    # --- Tenant master key lifecycle --------------------------------------
    def create_tenant_master_key(self) -> bytes:
        """Return a *wrapped* fresh tenant master key (safe to store)."""
        tmk = generate_key()
        return _seal(self._kek, tmk)

    def _unwrap_tmk(self, wrapped_tmk: bytes) -> bytes:
        return _open(self._kek, wrapped_tmk)

    def rewrap_tenant_master_key(self, wrapped_tmk: bytes) -> bytes:
        """Re-wrap an existing TMK (e.g. after KEK rotation)."""
        return _seal(self._kek, self._unwrap_tmk(wrapped_tmk))

    # --- Data envelope operations -----------------------------------------
    def encrypt(self, wrapped_tmk: bytes, plaintext: bytes,
                aad: bytes | None = None) -> Envelope:
        """Encrypt ``plaintext`` under a fresh DEK wrapped by the tenant key."""
        tmk = self._unwrap_tmk(wrapped_tmk)
        dek = generate_key()
        try:
            ciphertext = _seal(dek, plaintext, aad)
            wrapped_dek = _seal(tmk, dek)
        finally:
            del dek, tmk
        return Envelope(ciphertext=ciphertext, wrapped_dek=wrapped_dek)

    def decrypt(self, wrapped_tmk: bytes, envelope: Envelope,
                aad: bytes | None = None) -> bytes:
        """Recover plaintext from an envelope."""
        tmk = self._unwrap_tmk(wrapped_tmk)
        dek = _open(tmk, envelope.wrapped_dek)
        try:
            return _open(dek, envelope.ciphertext, aad)
        finally:
            del dek, tmk

    def encrypt_many(self, wrapped_tmk: bytes, payloads: list[bytes],
                     aad: bytes | None = None) -> tuple[list[bytes], bytes]:
        """Encrypt several payloads under ONE fresh DEK.

        Returns ``([ciphertexts], wrapped_dek)`` so related fields (e.g. a note's
        title and body) share a single wrapped key column.
        """
        tmk = self._unwrap_tmk(wrapped_tmk)
        dek = generate_key()
        try:
            cts = [_seal(dek, p, aad) for p in payloads]
            wrapped_dek = _seal(tmk, dek)
        finally:
            del dek, tmk
        return cts, wrapped_dek

    def decrypt_many(self, wrapped_tmk: bytes, wrapped_dek: bytes,
                     ciphertexts: list[bytes], aad: bytes | None = None) -> list[bytes]:
        tmk = self._unwrap_tmk(wrapped_tmk)
        dek = _open(tmk, wrapped_dek)
        try:
            return [_open(dek, c, aad) for c in ciphertexts]
        finally:
            del dek, tmk

    def rewrap_dek(self, wrapped_tmk: bytes, wrapped_dek: bytes) -> bytes:
        """Re-wrap a single DEK under the (current) tenant key — used per-object
        during key rotation without re-encrypting payloads."""
        tmk = self._unwrap_tmk(wrapped_tmk)
        try:
            dek = _open(tmk, wrapped_dek)
            return _seal(tmk, dek)
        finally:
            del tmk

    def rotate_tenant_key(self, old_wrapped_tmk: bytes,
                          wrapped_deks: list[bytes]) -> tuple[bytes, list[bytes]]:
        """Rotate the tenant master key.

        Returns ``(new_wrapped_tmk, [re-wrapped DEKs])``. Note payloads are
        untouched — only DEK wrappers change. GDPR Art. 32 (ability to restore
        and re-key). Old TMK material is discarded.
        """
        old_tmk = self._unwrap_tmk(old_wrapped_tmk)
        new_tmk = generate_key()
        rewrapped: list[bytes] = []
        try:
            for w in wrapped_deks:
                dek = _open(old_tmk, w)
                rewrapped.append(_seal(new_tmk, dek))
                del dek
            new_wrapped_tmk = _seal(self._kek, new_tmk)
        finally:
            del old_tmk, new_tmk
        return new_wrapped_tmk, rewrapped
