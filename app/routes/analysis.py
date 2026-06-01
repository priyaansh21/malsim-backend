"""
routes/analysis.py — Core analysis retrieval endpoints.

  GET /static-analysis/{id}   → file hashes, strings, signature matches
  GET /dynamic-analysis/{id}  → process tree, behavior log, fs/registry changes
  GET /threat-score/{id}      → composite score, YARA, network IOCs, verdict
  GET /status/{id}            → lightweight status poll

Returns 202 if analysis is still in progress, 200 when completed.
JSON shapes match the frontend UI data structures exactly.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.file_record import FileRecord, AnalysisStatus
from app.models.schemas import (
    StaticAnalysisResponse,
    DynamicAnalysisResponse,
    ThreatScoreResponse,
    QueueItem,
    ErrorResponse,
)
from app.utils.logger import get_logger

router = APIRouter(tags=["Analysis"])
logger = get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

async def _get_record_or_404(file_id: str, db: AsyncSession) -> FileRecord:
    record = await db.get(FileRecord, file_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"File '{file_id}' not found.")
    return record


def _assert_completed(record: FileRecord) -> None:
    if record.status == AnalysisStatus.FAILED:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {record.error_message or 'Unknown error'}",
        )
    if record.status != AnalysisStatus.COMPLETED:
        raise HTTPException(
            status_code=202,
            detail={
                "status":  record.status,
                "message": "Analysis is still in progress. Poll again shortly.",
            },
        )


# ═══════════════════════════════════════════════════════════════════════════════
# GET /status/{id}
# ═══════════════════════════════════════════════════════════════════════════════

@router.get(
    "/status/{file_id}",
    response_model=QueueItem,
    summary="Lightweight status poll for a single file",
)
async def get_status(file_id: str, db: AsyncSession = Depends(get_db)) -> QueueItem:
    record = await _get_record_or_404(file_id, db)
    return QueueItem(
        id            = record.id,
        original_name = record.original_name,
        file_size     = record.file_size,
        extension     = record.extension,
        status        = record.status,
        threat_score  = record.threat_score,
        risk_level    = record.risk_level,
        created_at    = record.created_at,
        updated_at    = record.updated_at,
        completed_at  = record.completed_at,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# GET /static-analysis/{id}
# ═══════════════════════════════════════════════════════════════════════════════

@router.get(
    "/static-analysis/{file_id}",
    response_model=StaticAnalysisResponse,
    summary="Retrieve static analysis results",
    description=(
        "Returns file hashes, entropy, suspicious string extraction, "
        "and signature database matches. Returns 202 if still processing."
    ),
    responses={
        202: {"description": "Analysis still in progress"},
        404: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
async def get_static_analysis(
    file_id: str,
    db: AsyncSession = Depends(get_db),
) -> StaticAnalysisResponse:

    record = await _get_record_or_404(file_id, db)
    _assert_completed(record)

    static = record.static_result or {}
    logger.debug("[%s] Serving static analysis result", file_id)

    return StaticAnalysisResponse(
        id       = record.id,
        status   = record.status,
        filename = record.original_name,
        hash_metadata      = static.get("hash_metadata"),
        suspicious_strings = static.get("suspicious_strings", []),
        signature_matches  = static.get("signature_matches", []),
        alert              = static.get("alert"),
    )


# ═══════════════════════════════════════════════════════════════════════════════
# GET /dynamic-analysis/{id}
# ═══════════════════════════════════════════════════════════════════════════════

@router.get(
    "/dynamic-analysis/{file_id}",
    response_model=DynamicAnalysisResponse,
    summary="Retrieve dynamic / sandbox simulation results",
    description=(
        "Returns the simulated process tree, behavior event log, "
        "file system mutations, and registry changes."
    ),
    responses={
        202: {"description": "Analysis still in progress"},
        404: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
async def get_dynamic_analysis(
    file_id: str,
    db: AsyncSession = Depends(get_db),
) -> DynamicAnalysisResponse:

    record = await _get_record_or_404(file_id, db)
    _assert_completed(record)

    dyn = record.dynamic_result or {}
    logger.debug("[%s] Serving dynamic analysis result", file_id)

    return DynamicAnalysisResponse(
        id       = record.id,
        status   = record.status,
        filename = record.original_name,
        process_tree        = dyn.get("process_tree", []),
        resource_usage      = dyn.get("resource_usage"),
        behavior_events     = dyn.get("behavior_events", []),
        filesystem_changes  = dyn.get("filesystem_changes", []),
        registry_changes    = dyn.get("registry_changes", []),
    )


# ═══════════════════════════════════════════════════════════════════════════════
# GET /threat-score/{id}
# ═══════════════════════════════════════════════════════════════════════════════

@router.get(
    "/threat-score/{file_id}",
    response_model=ThreatScoreResponse,
    summary="Retrieve composite threat score and verdict",
    description=(
        "Returns the final 0–100 threat score, risk classification, "
        "YARA rule results, network IOC reputation, and remediation recommendation."
    ),
    responses={
        202: {"description": "Analysis still in progress"},
        404: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
async def get_threat_score(
    file_id: str,
    db: AsyncSession = Depends(get_db),
) -> ThreatScoreResponse:

    record = await _get_record_or_404(file_id, db)
    _assert_completed(record)

    yara = record.yara_result or {}
    logger.debug("[%s] Serving threat score result", file_id)

    return ThreatScoreResponse(
        id               = record.id,
        status           = record.status,
        filename         = record.original_name,
        threat_score     = record.threat_score,
        risk_level       = record.risk_level,
        threat_category  = record.threat_category,
        recommendation   = record.recommendation,
        tags             = yara.get("tags", []),
        score_breakdown  = yara.get("score_breakdown"),
        yara_results     = yara.get("yara_results", []),
        network_iocs     = yara.get("network_iocs", []),
        algorithm_explanation = yara.get("algorithm_explanation"),
    )
