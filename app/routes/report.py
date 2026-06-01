"""
routes/report.py — Full Threat Report generation endpoint.

Produces a consolidated JSON report incorporating static, dynamic, and scoring data.
Suitable for exporting or integrating with SIEMs.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.file_record import FileRecord, AnalysisStatus
from app.utils.logger import get_logger
from app.utils.response import success, error

router = APIRouter(tags=["Report"])
logger = get_logger(__name__)


@router.get(
    "/report/{file_id}",
    summary="Generate full consolidated threat report (JSON)",
)
async def get_report(file_id: str, db: AsyncSession = Depends(get_db)):
    record = await db.get(FileRecord, file_id)
    if not record:
        return error("File record not found", status_code=404)

    if record.status != AnalysisStatus.COMPLETED:
        return error(
            f"Analysis not ready. Current status: {record.status}",
            status_code=400,
        )

    logger.info("Generating full report for %s", file_id)

    report_data = {
        "metadata": {
            "id": record.id,
            "filename": record.original_name,
            "file_size": record.file_size,
            "extension": record.extension,
            "md5": record.md5,
            "sha1": record.sha1,
            "sha256": record.sha256,
            "submitted_at": record.created_at.isoformat(),
            "completed_at": record.completed_at.isoformat() if record.completed_at else None,
        },
        "verdict": {
            "threat_score": record.threat_score,
            "risk_level": record.risk_level,
            "category": record.threat_category,
            "recommendation": record.recommendation,
        },
        "static_analysis": record.static_result,
        "dynamic_analysis": record.dynamic_result,
        "yara_and_network": record.yara_result,
    }

    return success(report_data, message="Report generated successfully")
