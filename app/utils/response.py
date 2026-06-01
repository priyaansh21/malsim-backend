"""
utils/response.py — Consistent API response envelope helpers.

All endpoints wrap their payload in a standard JSON envelope:
  {
    "ok": true,
    "data": { ... },          # on success
    "error": "...",           # on failure
    "meta": { ... }           # optional pagination / timing
  }

Using these helpers ensures every route stays consistent without boilerplate.
"""

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import status
from fastapi.responses import JSONResponse


def success(
    data: Any,
    *,
    status_code: int = status.HTTP_200_OK,
    meta: Optional[dict] = None,
    message: Optional[str] = None,
) -> JSONResponse:
    """Return a successful JSON envelope."""
    body: dict[str, Any] = {"ok": True, "data": data}
    if message:
        body["message"] = message
    if meta:
        body["meta"] = meta
    body["timestamp"] = datetime.now(timezone.utc).isoformat()
    return JSONResponse(content=body, status_code=status_code)


def error(
    message: str,
    *,
    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
    detail: Optional[Any] = None,
) -> JSONResponse:
    """Return a failure JSON envelope."""
    body: dict[str, Any] = {"ok": False, "error": message}
    if detail:
        body["detail"] = detail
    body["timestamp"] = datetime.now(timezone.utc).isoformat()
    return JSONResponse(content=body, status_code=status_code)


def paginated(
    items: list,
    *,
    total: int,
    page: int,
    page_size: int,
    status_code: int = status.HTTP_200_OK,
) -> JSONResponse:
    """Return a paginated list response."""
    body = {
        "ok": True,
        "data": items,
        "meta": {
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": max(1, (total + page_size - 1) // page_size),
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    return JSONResponse(content=body, status_code=status_code)
