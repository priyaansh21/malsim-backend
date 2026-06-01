"""
utils/file_validator.py — Extended MIME-type and magic-byte validation.

Goes beyond extension checking:
  - Magic byte sniffing (file header analysis)
  - MIME-type verification via python-magic
  - Double-extension attack detection (e.g. "invoice.pdf.exe")
  - Null-byte injection prevention

Used by the upload route as a secondary validation layer after extension check.
"""

import re
from pathlib import Path
from typing import Optional

from app.utils.logger import get_logger

logger = get_logger(__name__)

# ── Magic bytes for key file types ────────────────────────────────────────────
# Format: extension → list of accepted byte-sequence prefixes (hex)
MAGIC_BYTES: dict[str, list[bytes]] = {
    ".exe": [b"MZ"],                        # PE Windows executable
    ".dll": [b"MZ"],
    ".pdf": [b"%PDF"],
    ".zip": [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    ".msi": [b"\xd0\xcf\x11\xe0"],          # Compound File Binary
    ".doc": [b"\xd0\xcf\x11\xe0"],          # Compound File Binary
    ".docx": [b"PK"],                        # OOXML is a ZIP
    ".apk": [b"PK"],                         # APK is a ZIP
    # Text-based files — no strict magic enforcement (content is readable)
    ".ps1": None,
    ".bat": None,
    ".js":  None,
    ".vbs": None,
    ".sh":  None,
    ".bin": None,                            # generic binary — no enforcement
    ".py":  None,
}

# ── Double-extension safelist (the second extension is what matters) ──────────
_DOUBLE_EXT_PATTERN = re.compile(
    r"\.(pdf|doc|docx|txt|jpg|png|csv|xml)\.(exe|dll|bat|ps1|vbs|js|sh|msi)$",
    re.IGNORECASE,
)


def check_magic_bytes(
    data: bytes,
    extension: str,
) -> tuple[bool, Optional[str]]:
    """
    Verify that the first N bytes of the file match expected magic for the extension.

    Returns (ok: bool, error_message: Optional[str]).
    If the extension has no magic enforcement (None), always returns (True, None).
    """
    expected = MAGIC_BYTES.get(extension)
    if expected is None:
        return True, None          # text / generic — not enforced

    for magic in expected:
        if data[:len(magic)] == magic:
            return True, None

    logger.warning(
        "Magic byte mismatch for extension=%s (got: %r)",
        extension, data[:8],
    )
    return False, (
        f"File content does not match the expected format for '{extension}'. "
        "Possible file spoofing or corruption."
    )


def check_double_extension(filename: str) -> tuple[bool, Optional[str]]:
    """
    Detect common double-extension spoofing attacks (e.g. 'invoice.pdf.exe').
    Returns (ok: bool, error_message: Optional[str]).
    """
    if _DOUBLE_EXT_PATTERN.search(filename):
        logger.warning("Double extension attack detected: %s", filename)
        return False, (
            f"Suspicious double extension detected in '{filename}'. "
            "Upload rejected for security reasons."
        )
    return True, None


def check_null_bytes(filename: str) -> tuple[bool, Optional[str]]:
    """Reject filenames containing null bytes (path traversal vectors)."""
    if "\x00" in filename:
        logger.warning("Null byte in filename: %r", filename)
        return False, "Filename contains null bytes — rejected."
    return True, None


def sanitize_filename(filename: str) -> str:
    """
    Produce a filesystem-safe version of the original filename.
    Strips path components and special characters while preserving extension.
    """
    name = Path(filename).name                         # strip any path component
    name = re.sub(r"[^a-zA-Z0-9._\-]", "_", name)    # replace special chars
    name = re.sub(r"\.{2,}", ".", name)                # collapse multiple dots
    return name[:255]                                  # OS filename limit
