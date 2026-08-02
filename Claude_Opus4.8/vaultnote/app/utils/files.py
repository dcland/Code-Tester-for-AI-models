"""File validation and encrypted-at-rest blob storage.

Security controls:
- Magic-byte sniffing (never trust the client-supplied content type).
- Size limits enforced before and after buffering.
- Path-traversal resistance: storage keys are random opaque ids; the user file
  name is never used to build a path.
- Virus-scan interface (stub) that a real ClamAV/ICAP hook can implement.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from app.core.exceptions import FileValidationError


@dataclass(frozen=True)
class SniffResult:
    content_type: str
    extension: str


# (magic-byte prefix, content-type, extension). Order matters (longest/first win).
_MAGIC_SIGNATURES: list[tuple[bytes, str, str]] = [
    (b"\x89PNG\r\n\x1a\n", "image/png", "png"),
    (b"\xff\xd8\xff", "image/jpeg", "jpg"),
    (b"GIF87a", "image/gif", "gif"),
    (b"GIF89a", "image/gif", "gif"),
    (b"%PDF-", "application/pdf", "pdf"),
    (b"PK\x03\x04", "application/zip", "zip"),
    (b"\x1f\x8b", "application/gzip", "gz"),
    (b"ID3", "audio/mpeg", "mp3"),
]

_ALLOWED_CONTENT_TYPES = {
    "image/png", "image/jpeg", "image/gif", "application/pdf",
    "application/zip", "application/gzip", "audio/mpeg", "text/plain",
    "application/octet-stream",
}

# Bytes that make content plausibly UTF-8 text (fallback classification).
def _looks_like_text(sample: bytes) -> bool:
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def sniff_content_type(data: bytes) -> SniffResult:
    """Determine content type from magic bytes, ignoring the client's claim."""
    for prefix, ctype, ext in _MAGIC_SIGNATURES:
        if data.startswith(prefix):
            return SniffResult(ctype, ext)
    if _looks_like_text(data[:4096]):
        return SniffResult("text/plain", "txt")
    return SniffResult("application/octet-stream", "bin")


# Executable / script signatures are rejected outright regardless of the
# declared type (defense against uploading runnable payloads).
_DANGEROUS_SIGNATURES: tuple[bytes, ...] = (
    b"MZ",              # DOS/Windows PE
    b"\x7fELF",         # Linux ELF
    b"\xfe\xed\xfa\xce", # Mach-O 32
    b"\xfe\xed\xfa\xcf", # Mach-O 64
    b"\xcf\xfa\xed\xfe", # Mach-O little-endian
    b"\xca\xfe\xba\xbe", # Java class / Mach-O fat
    b"#!",              # shebang script
)


def validate_upload(data: bytes, *, max_bytes: int,
                    declared_content_type: str | None) -> SniffResult:
    if not data:
        raise FileValidationError("empty file rejected")
    if len(data) > max_bytes:
        raise FileValidationError("file exceeds maximum allowed size")
    if any(data.startswith(sig) for sig in _DANGEROUS_SIGNATURES):
        raise FileValidationError("executable content is not permitted")
    sniffed = sniff_content_type(data)
    if sniffed.content_type not in _ALLOWED_CONTENT_TYPES:
        raise FileValidationError("file type not permitted")
    # If the client lied about the type in a dangerous way, reject.
    if declared_content_type and declared_content_type not in _ALLOWED_CONTENT_TYPES:
        raise FileValidationError("declared content type not permitted")
    return sniffed


def scan_for_malware(data: bytes) -> None:
    """Virus-scan hook (stub).

    A production deployment wires this to ClamAV/ICAP. The stub rejects the
    standard EICAR test string so the control is demonstrably active.
    """
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"
    if eicar in data[:1024]:
        raise FileValidationError("file failed malware scan")


class BlobStore:
    """Stores already-encrypted blobs on disk under opaque random keys."""

    def __init__(self, base_dir: str) -> None:
        self._base = Path(base_dir).resolve()
        self._base.mkdir(parents=True, exist_ok=True)

    def _path_for(self, storage_key: str) -> Path:
        # storage_key is a hex id we generated; still hard-validate it and
        # confirm the resolved path stays inside the base dir.
        if not storage_key.isalnum() or len(storage_key) > 80:
            raise FileValidationError("invalid storage key")
        path = (self._base / storage_key).resolve()
        if not str(path).startswith(str(self._base) + os.sep):
            raise FileValidationError("path traversal detected")
        return path

    def write(self, storage_key: str, blob: bytes) -> None:
        path = self._path_for(storage_key)
        # Write atomically with restrictive permissions.
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, blob)
        finally:
            os.close(fd)
        os.replace(tmp, path)

    def read(self, storage_key: str) -> bytes:
        path = self._path_for(storage_key)
        if not path.exists():
            raise FileValidationError("blob not found")
        return path.read_bytes()

    def delete(self, storage_key: str) -> None:
        path = self._path_for(storage_key)
        if path.exists():
            # Best-effort secure delete: overwrite then unlink.
            try:
                size = path.stat().st_size
                with open(path, "r+b") as f:
                    f.write(b"\x00" * size)
                    f.flush()
                    os.fsync(f.fileno())
            except OSError:
                pass
            path.unlink(missing_ok=True)
