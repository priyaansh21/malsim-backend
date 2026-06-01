"""
models/file_record.py — ORM model for uploaded file metadata and analysis state.

Table: file_records
Each row represents one submitted file and carries the full lifecycle:
  queued → processing → completed (or failed)
"""

import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum

from sqlalchemy import Column, String, Integer, Float, DateTime, Enum, Text, JSON
from sqlalchemy.dialects.sqlite import TEXT

from app.database import Base


# ── State Machine ─────────────────────────────────────────────────────────────
class AnalysisStatus(str, PyEnum):
    QUEUED     = "queued"
    PROCESSING = "processing"
    COMPLETED  = "completed"
    FAILED     = "failed"


class RiskLevel(str, PyEnum):
    CLEAN  = "CLEAN"
    LOW    = "LOW"
    MEDIUM = "MEDIUM"
    HIGH   = "HIGH"


# ── ORM Model ─────────────────────────────────────────────────────────────────
class FileRecord(Base):
    __tablename__ = "file_records"

    # ── Identity ──────────────────────────────────────────────────────────────
    id          = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    filename    = Column(String(255), nullable=False, index=True)
    original_name = Column(String(255), nullable=False)

    # ── File Attributes ───────────────────────────────────────────────────────
    file_size   = Column(Integer, nullable=False)       # bytes
    mime_type   = Column(String(120), nullable=True)    # detected MIME
    extension   = Column(String(20), nullable=True)

    # ── Cryptographic Hashes (computed server-side) ───────────────────────────
    md5         = Column(String(32), nullable=True)
    sha1        = Column(String(40), nullable=True)
    sha256      = Column(String(64), nullable=True)

    # ── Analysis State ────────────────────────────────────────────────────────
    status      = Column(
        Enum(AnalysisStatus),
        default=AnalysisStatus.QUEUED,
        nullable=False,
        index=True,
    )

    # ── Threat Intelligence ───────────────────────────────────────────────────
    threat_score   = Column(Float, nullable=True)         # 0–100
    risk_level     = Column(Enum(RiskLevel), nullable=True)
    threat_category = Column(String(100), nullable=True)  # e.g. "Trojan.Dropper"
    recommendation  = Column(String(50), nullable=True)   # ISOLATE / MONITOR / CLEAN

    # ── Sub-scores (stored flat for fast retrieval) ───────────────────────────
    static_score   = Column(Float, nullable=True)
    dynamic_score  = Column(Float, nullable=True)
    yara_score     = Column(Float, nullable=True)
    network_score  = Column(Float, nullable=True)

    # ── Analysis Results (serialised JSON blobs) ──────────────────────────────
    static_result  = Column(JSON, nullable=True)
    dynamic_result = Column(JSON, nullable=True)
    yara_result    = Column(JSON, nullable=True)
    network_result = Column(JSON, nullable=True)

    # ── Error Handling ────────────────────────────────────────────────────────
    error_message  = Column(Text, nullable=True)

    # ── Timestamps ────────────────────────────────────────────────────────────
    created_at     = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at     = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    completed_at   = Column(DateTime, nullable=True)

    # ── Storage ───────────────────────────────────────────────────────────────
    storage_path   = Column(Text, nullable=True)    # absolute path on disk

    def __repr__(self) -> str:
        return (
            f"<FileRecord id={self.id!r} name={self.original_name!r} "
            f"status={self.status} score={self.threat_score}>"
        )
