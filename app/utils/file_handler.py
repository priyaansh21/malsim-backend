"""
utils/file_handler.py — Safe file persistence & validation utilities.

Responsibilities:
  - Validate extension and file size
  - Persist uploaded bytes to the configured upload directory
  - Compute MD5 / SHA1 / SHA256 hashes
  - Estimate Shannon entropy
  - Clean up files after analysis (optional)
"""

import hashlib
import math
import os
import shutil
import uuid
from pathlib import Path
from typing import Optional

import aiofiles

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ── Constants ─────────────────────────────────────────────────────────────────
CHUNK_SIZE = 64 * 1024   # 64 KB read buffer


# ══════════════════════════════════════════════════════════════════════════════
# VALIDATION
# ══════════════════════════════════════════════════════════════════════════════

class FileValidationError(ValueError):
    """Raised when an uploaded file fails pre-storage validation."""
    pass


def validate_extension(filename: str) -> str:
    """
    Return the (lower-cased) file extension if allowed, else raise.
    """
    suffix = Path(filename).suffix.lower()
    if suffix not in settings.ALLOWED_EXTENSIONS:
        raise FileValidationError(
            f"Extension '{suffix}' is not accepted. "
            f"Allowed: {', '.join(sorted(settings.ALLOWED_EXTENSIONS))}"
        )
    return suffix


def validate_file_size(size_bytes: int) -> None:
    """Raise FileValidationError if size exceeds the configured maximum."""
    if size_bytes > settings.MAX_FILE_SIZE_BYTES:
        limit_mb = settings.MAX_FILE_SIZE_BYTES // (1024 * 1024)
        actual_mb = size_bytes / (1024 * 1024)
        raise FileValidationError(
            f"File size {actual_mb:.1f} MB exceeds the {limit_mb} MB limit."
        )


# ══════════════════════════════════════════════════════════════════════════════
# PERSISTENCE
# ══════════════════════════════════════════════════════════════════════════════

async def save_upload(file_bytes: bytes, original_name: str, file_id: str) -> Path:
    """
    Write raw bytes to the upload directory under a UUID-prefixed filename.
    Returns the absolute Path of the saved file.
    """
    ext = Path(original_name).suffix.lower()
    safe_name = f"{file_id}{ext}"
    dest = settings.UPLOAD_DIR / safe_name

    async with aiofiles.open(dest, "wb") as fh:
        await fh.write(file_bytes)

    logger.info("Saved upload: %s (%d bytes) → %s", original_name, len(file_bytes), dest)
    return dest


def delete_upload(storage_path: Optional[str]) -> None:
    """Remove the stored file if it exists (used post-analysis or on cleanup)."""
    if not storage_path:
        return
    p = Path(storage_path)
    if p.exists():
        p.unlink(missing_ok=True)
        logger.info("Deleted upload: %s", p)


# ══════════════════════════════════════════════════════════════════════════════
# CRYPTOGRAPHIC HASHING
# ══════════════════════════════════════════════════════════════════════════════

def compute_hashes(data: bytes) -> dict[str, str]:
    """
    Compute MD5, SHA-1, and SHA-256 of raw bytes in a single pass.
    Returns a dict:  {"md5": "...", "sha1": "...", "sha256": "..."}
    """
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()

    # Process in 64 KB chunks (fast even for large files already in memory)
    for offset in range(0, len(data), CHUNK_SIZE):
        chunk = data[offset : offset + CHUNK_SIZE]
        md5.update(chunk)
        sha1.update(chunk)
        sha256.update(chunk)

    return {
        "md5":    md5.hexdigest(),
        "sha1":   sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


# ══════════════════════════════════════════════════════════════════════════════
# ENTROPY
# ══════════════════════════════════════════════════════════════════════════════

def compute_entropy(data: bytes) -> float:
    """
    Calculate the Shannon entropy of a byte sequence.
    Perfect randomness (fully encrypted / compressed) → 8.0
    Plain text → typically 3.5–5.0
    """
    if not data:
        return 0.0

    freq: dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1

    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return round(entropy, 4)


def entropy_label(entropy: float) -> str:
    """Human-readable entropy classification."""
    if entropy >= 7.5:
        return "HIGHLY PACKED — Possible obfuscation/encryption"
    if entropy >= 6.0:
        return "PACKED — Possible compression"
    if entropy >= 4.0:
        return "NORMAL — Typical binary"
    return "LOW — Possible plaintext / script"


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def human_readable_size(size_bytes: int) -> str:
    """Convert bytes to a human-readable string, e.g. '847,312 bytes (827 KB)'."""
    if size_bytes < 1024:
        return f"{size_bytes:,} bytes"
    kb = size_bytes / 1024
    if kb < 1024:
        return f"{size_bytes:,} bytes ({kb:.0f} KB)"
    mb = kb / 1024
    return f"{size_bytes:,} bytes ({mb:.1f} MB)"
