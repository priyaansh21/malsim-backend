"""
routes/queue.py — Analysis queue and dashboard statistics endpoints.

  GET /queue           → paginated list of all submissions with status
  GET /queue/active    → files currently queued or processing
  DELETE /queue/{id}   → soft-cancel / remove record
  GET /dashboard/stats → aggregated counts for the SOC dashboard
"""

from typing import Optional

from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy import select, func, case
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.file_record import FileRecord, AnalysisStatus, RiskLevel
from app.models.schemas import QueueListResponse, QueueItem, DashboardStats, CategoryCount, OKResponse
from app.utils.logger import get_logger

router = APIRouter(tags=["Queue & Dashboard"])
logger = get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# GET /queue
# ═══════════════════════════════════════════════════════════════════════════════

@router.get(
    "/queue",
    response_model=QueueListResponse,
    summary="List all submissions with their current analysis status",
)
async def list_queue(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    status: Optional[str] = Query(None, description="Filter by status: queued|processing|completed|failed"),
    db: AsyncSession = Depends(get_db),
) -> QueueListResponse:

    stmt = select(FileRecord).order_by(FileRecord.created_at.desc())

    if status:
        try:
            status_enum = AnalysisStatus(status.lower())
            stmt = stmt.where(FileRecord.status == status_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status filter: '{status}'")

    # Count total
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar_one()

    # Paginate
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)
    rows = (await db.execute(stmt)).scalars().all()

    items = [
        QueueItem(
            id            = r.id,
            original_name = r.original_name,
            file_size     = r.file_size,
            extension     = r.extension,
            status        = r.status,
            threat_score  = r.threat_score,
            risk_level    = r.risk_level,
            created_at    = r.created_at,
            updated_at    = r.updated_at,
            completed_at  = r.completed_at,
        )
        for r in rows
    ]

    logger.debug("Queue requested: page=%d, total=%d", page, total)
    return QueueListResponse(total=total, items=items)


# ═══════════════════════════════════════════════════════════════════════════════
# GET /queue/active
# ═══════════════════════════════════════════════════════════════════════════════

@router.get(
    "/queue/active",
    response_model=QueueListResponse,
    summary="Return only queued and currently-processing items",
)
async def list_active(db: AsyncSession = Depends(get_db)) -> QueueListResponse:
    stmt = (
        select(FileRecord)
        .where(FileRecord.status.in_([AnalysisStatus.QUEUED, AnalysisStatus.PROCESSING]))
        .order_by(FileRecord.created_at.asc())
    )
    rows = (await db.execute(stmt)).scalars().all()

    items = [
        QueueItem(
            id            = r.id,
            original_name = r.original_name,
            file_size     = r.file_size,
            extension     = r.extension,
            status        = r.status,
            threat_score  = r.threat_score,
            risk_level    = r.risk_level,
            created_at    = r.created_at,
            updated_at    = r.updated_at,
            completed_at  = r.completed_at,
        )
        for r in rows
    ]
    return QueueListResponse(total=len(items), items=items)


# ═══════════════════════════════════════════════════════════════════════════════
# DELETE /queue/{id}
# ═══════════════════════════════════════════════════════════════════════════════

@router.delete(
    "/queue/{file_id}",
    response_model=OKResponse,
    summary="Remove a record from the queue (soft delete / purge)",
)
async def delete_record(
    file_id: str,
    db: AsyncSession = Depends(get_db),
) -> OKResponse:
    record = await db.get(FileRecord, file_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Record '{file_id}' not found.")

    await db.delete(record)
    await db.commit()
    logger.info("Record %s deleted from queue", file_id)
    return OKResponse(message=f"Record '{file_id}' removed.")


# ═══════════════════════════════════════════════════════════════════════════════
# GET /dashboard/stats
# ═══════════════════════════════════════════════════════════════════════════════

_CATEGORY_COLORS = {
    "Trojan.Dropper":           "#ff4560",
    "Trojan.Generic.Dropper":   "#ff4560",
    "Ransomware.FileEncryptor": "#f5a623",
    "Spyware.Keylogger":        "#c864ff",
    "Spyware.MacroEmbedded":    "#c864ff",
    "Malware.Persistence":      "#3b8eff",
    "Backdoor.ReverseTCP":      "#00d4ff",
    "Clean":                    "#00e5a0",
}

@router.get(
    "/dashboard/stats",
    response_model=DashboardStats,
    summary="Aggregated statistics for the SOC dashboard",
)
async def dashboard_stats(db: AsyncSession = Depends(get_db)) -> DashboardStats:

    # ── Total scanned (completed only) ─────────────────────────────────────────
    total_stmt = select(func.count()).where(FileRecord.status == AnalysisStatus.COMPLETED)
    total_scanned = (await db.execute(total_stmt)).scalar_one() or 0

    # ── Risk breakdown ─────────────────────────────────────────────────────────
    high_stmt = select(func.count()).where(
        FileRecord.status == AnalysisStatus.COMPLETED,
        FileRecord.risk_level == RiskLevel.HIGH,
    )
    high_risk = (await db.execute(high_stmt)).scalar_one() or 0

    med_stmt = select(func.count()).where(
        FileRecord.status == AnalysisStatus.COMPLETED,
        FileRecord.risk_level == RiskLevel.MEDIUM,
    )
    medium_risk = (await db.execute(med_stmt)).scalar_one() or 0

    clean_stmt = select(func.count()).where(
        FileRecord.status == AnalysisStatus.COMPLETED,
        FileRecord.risk_level.in_([RiskLevel.CLEAN, RiskLevel.LOW]),
    )
    clean_files = (await db.execute(clean_stmt)).scalar_one() or 0

    # ── Active pipeline ────────────────────────────────────────────────────────
    proc_stmt = select(func.count()).where(FileRecord.status == AnalysisStatus.PROCESSING)
    processing = (await db.execute(proc_stmt)).scalar_one() or 0

    queue_stmt = select(func.count()).where(FileRecord.status == AnalysisStatus.QUEUED)
    queued = (await db.execute(queue_stmt)).scalar_one() or 0

    # ── YARA / sig rules matched (files with threat_score > 0) ─────────────────
    rules_stmt = select(func.count()).where(
        FileRecord.status == AnalysisStatus.COMPLETED,
        FileRecord.threat_score > 0,
    )
    rules_matched = (await db.execute(rules_stmt)).scalar_one() or 0

    # ── Category breakdown ─────────────────────────────────────────────────────
    cat_stmt = (
        select(FileRecord.threat_category, func.count().label("cnt"))
        .where(FileRecord.status == AnalysisStatus.COMPLETED)
        .where(FileRecord.threat_category.is_not(None))
        .group_by(FileRecord.threat_category)
        .order_by(func.count().desc())
    )
    cat_rows = (await db.execute(cat_stmt)).all()
    categories = [
        CategoryCount(
            label=row.threat_category,
            count=row.cnt,
            color=_CATEGORY_COLORS.get(row.threat_category, "#6a8099"),
        )
        for row in cat_rows
    ]

    logger.debug("Dashboard stats: total=%d, high=%d", total_scanned, high_risk)

    return DashboardStats(
        total_scanned = total_scanned,
        high_risk     = high_risk,
        medium_risk   = medium_risk,
        clean_files   = clean_files,
        rules_matched = rules_matched,
        processing    = processing,
        queued        = queued,
        categories    = categories,
    )
