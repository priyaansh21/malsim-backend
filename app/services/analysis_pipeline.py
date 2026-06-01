"""
services/analysis_pipeline.py — Async analysis orchestrator.

This is the central coordinator that:
  1. Transitions state: queued → processing → completed/failed
  2. Runs static, dynamic, and scoring phases sequentially
  3. Persists intermediate and final results to the database
  4. Is invoked via asyncio.create_task() so it runs in the background
     without blocking the upload HTTP response.

Architecture note: Each phase updates the DB so polling clients
always see the latest partial state.
"""

import asyncio
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal
from app.models.file_record import FileRecord, AnalysisStatus, RiskLevel
from app.services.static_analysis import run_static_analysis
from app.services.dynamic_analysis import run_dynamic_analysis
from app.services.threat_scoring import run_threat_scoring
from app.utils.logger import get_logger

logger = get_logger(__name__)


async def execute_analysis_pipeline(
    file_id: str,
    file_bytes: bytes,
    original_name: str,
    extension: str,
    md5: str,
    sha1: str,
    sha256: str,
) -> None:
    """
    Full async pipeline:  queued → processing → completed (or failed).
    
    Runs as a background task — never blocks HTTP.
    Each phase commits to the DB so GET endpoints reflect live state.
    """
    logger.info("[%s] Pipeline started for '%s'", file_id, original_name)

    # ── Transition to PROCESSING ───────────────────────────────────────────────
    async with AsyncSessionLocal() as db:
        record = await db.get(FileRecord, file_id)
        if not record:
            logger.error("[%s] Record not found — aborting pipeline", file_id)
            return
        record.status = AnalysisStatus.PROCESSING
        await db.commit()
        logger.info("[%s] Status → PROCESSING", file_id)

    try:
        # ── Phase 1: Static Analysis ───────────────────────────────────────────
        logger.info("[%s] Phase 1: Static analysis", file_id)
        static_result = await run_static_analysis(
            file_bytes=file_bytes,
            original_name=original_name,
            file_id=file_id,
            extension=extension,
            md5=md5, sha1=sha1, sha256=sha256,
        )
        async with AsyncSessionLocal() as db:
            rec = await db.get(FileRecord, file_id)
            rec.static_result = static_result
            rec.static_score  = static_result.get("static_score")
            await db.commit()

        # ── Phase 2: Dynamic Analysis ──────────────────────────────────────────
        logger.info("[%s] Phase 2: Dynamic analysis", file_id)
        dynamic_result = await run_dynamic_analysis(
            original_name=original_name,
            file_id=file_id,
        )
        async with AsyncSessionLocal() as db:
            rec = await db.get(FileRecord, file_id)
            rec.dynamic_result = dynamic_result
            rec.dynamic_score  = dynamic_result.get("dynamic_score")
            rec.network_score  = dynamic_result.get("network_score")
            await db.commit()

        # ── Phase 3: Threat Scoring ────────────────────────────────────────────
        logger.info("[%s] Phase 3: Threat scoring", file_id)
        score_result = await run_threat_scoring(
            original_name=original_name,
            file_id=file_id,
            static_result=static_result,
            dynamic_result=dynamic_result,
        )
        async with AsyncSessionLocal() as db:
            rec = await db.get(FileRecord, file_id)
            rec.yara_result    = score_result
            rec.network_result = {
                "network_iocs": score_result.get("network_iocs", []),
            }
            rec.yara_score       = score_result.get("yara_score")
            rec.threat_score     = score_result.get("threat_score")
            rec.risk_level       = _map_risk(score_result.get("risk_level", "CLEAN"))
            rec.threat_category  = score_result.get("threat_category")
            rec.recommendation   = score_result.get("recommendation")
            rec.status           = AnalysisStatus.COMPLETED
            rec.completed_at     = datetime.now(timezone.utc)
            await db.commit()

        logger.info(
            "[%s] Pipeline COMPLETED — score=%.1f, risk=%s",
            file_id, score_result.get("threat_score", 0), score_result.get("risk_level"),
        )

    except Exception as exc:
        logger.exception("[%s] Pipeline FAILED: %s", file_id, exc)
        async with AsyncSessionLocal() as db:
            rec = await db.get(FileRecord, file_id)
            if rec:
                rec.status        = AnalysisStatus.FAILED
                rec.error_message = str(exc)
                await db.commit()


def _map_risk(risk_str: str) -> RiskLevel:
    mapping = {
        "HIGH":   RiskLevel.HIGH,
        "MEDIUM": RiskLevel.MEDIUM,
        "LOW":    RiskLevel.LOW,
        "CLEAN":  RiskLevel.CLEAN,
    }
    return mapping.get(risk_str.upper(), RiskLevel.CLEAN)
