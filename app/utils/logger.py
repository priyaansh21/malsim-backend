"""
utils/logger.py — Structured, rotating file logger factory.

All modules call get_logger(__name__) to get a consistently configured
logger that writes to both the console and a daily-rotating log file.
"""

import logging
import sys
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

from app.config import settings

# ── Formatter ─────────────────────────────────────────────────────────────────
LOG_FMT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
DATE_FMT = "%Y-%m-%dT%H:%M:%S"

_configured: set[str] = set()


def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger.  First call configures handlers (idempotent).
    """
    logger = logging.getLogger(name)

    if name in _configured:
        return logger

    _configured.add(name)
    level = logging.DEBUG if settings.DEBUG else logging.INFO
    logger.setLevel(level)

    formatter = logging.Formatter(fmt=LOG_FMT, datefmt=DATE_FMT)

    # ── Console handler ───────────────────────────────────────────────────────
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(level)

    # ── File handler (daily rotation, keep 14 days) ───────────────────────────
    log_file = settings.LOG_DIR / "malsim.log"
    file_handler = TimedRotatingFileHandler(
        filename=log_file,
        when="midnight",
        backupCount=14,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)
    logger.propagate = False

    return logger
