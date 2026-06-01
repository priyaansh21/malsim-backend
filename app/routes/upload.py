"""
routes/upload.py — POST /upload

Accepts multipart file upload, validates, persists, computes hashes,
creates a DB record (status=queued) and fires the background analysis pipeline.
Returns immediately with file ID so the client can poll.
"""

import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, File, UploadFile, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends

from app.database import get_db
from app.models.file_record import FileRecord, AnalysisStatus
from app.models.schemas import UploadResponse, ErrorResponse
from app.services.analysis_pipeline import execute_analysis_pipeline
from app.utils.file_handler import (
    validate_extension,
    validate_file_size,
    save_upload,
    compute_hashes,
    FileValidationError,
)
from app.utils.logger import get_logger

router = APIRouter(prefix="/upload", tags=["Upload"])
logger = get_logger(__name__)


@router.post(
    "",
    response_model=UploadResponse,
    status_code=202,
    summary="Upload a file for malware analysis",
    description=(
        "Accepts a binary file (max 50 MB). "
        "Returns a file ID you can use to poll the analysis endpoints. "
        "Analysis runs asynchronously in the background."
    ),
    responses={
        422: {"model": ErrorResponse, "description": "Validation error"},
        413: {"model": ErrorResponse, "description": "File too large"},
    },
)
async def upload_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Binary file to analyse"),
    db: AsyncSession = Depends(get_db),
) -> UploadResponse:

    # ── Read raw bytes ─────────────────────────────────────────────────────────
    file_bytes = await file.read()
    original_name = file.filename or "unknown_file"
    logger.info("Received upload: '%s' (%d bytes)", original_name, len(file_bytes))

    # ── Validate ───────────────────────────────────────────────────────────────
    try:
        extension = validate_extension(original_name)
        validate_file_size(len(file_bytes))
    except FileValidationError as exc:
        logger.warning("Validation failed for '%s': %s", original_name, exc)
        raise HTTPException(status_code=422, detail=str(exc))

    # ── Compute hashes ─────────────────────────────────────────────────────────
    hashes = compute_hashes(file_bytes)

    # ── Generate ID & persist file ─────────────────────────────────────────────
    file_id  = str(uuid.uuid4())
    storage_path = await save_upload(file_bytes, original_name, file_id)

    # ── Create DB record ───────────────────────────────────────────────────────
    record = FileRecord(
        id            = file_id,
        filename      = storage_path.name,
        original_name = original_name,
        file_size     = len(file_bytes),
        mime_type     = file.content_type,
        extension     = extension,
        md5           = hashes["md5"],
        sha1          = hashes["sha1"],
        sha256        = hashes["sha256"],
        status        = AnalysisStatus.QUEUED,
        storage_path  = str(storage_path),
        created_at    = datetime.now(timezone.utc),
        updated_at    = datetime.now(timezone.utc),
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    logger.info("[%s] DB record created — status=QUEUED", file_id)

    # ── Kick off background pipeline ───────────────────────────────────────────
    background_tasks.add_task(
        execute_analysis_pipeline,
        file_id=file_id,
        file_bytes=file_bytes,
        original_name=original_name,
        extension=extension,
        md5=hashes["md5"],
        sha1=hashes["sha1"],
        sha256=hashes["sha256"],
    )
    logger.info("[%s] Background analysis pipeline enqueued", file_id)

    return UploadResponse(
        id          = file_id,
        filename    = original_name,
        file_size   = len(file_bytes),
        extension   = extension,
        status      = "queued",
        created_at  = record.created_at,
    )
