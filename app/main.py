"""
main.py — FastAPI application factory & lifespan manager.

Registers:
  - Application lifespan (DB init on startup)
  - CORS middleware (permissive for local file:// frontend)
  - Rate limiting middleware (60 req/min per IP)
  - Global exception handlers
  - All route modules under their prefixes
  - OpenAPI metadata

Run with:
  uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
  # or:
  python run.py --reload
"""

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import settings
from app.database import init_db
from app.routes import upload, analysis, queue, report
from app.middleware.rate_limit import RateLimitMiddleware
from app.utils.logger import get_logger

logger = get_logger("malsim.main")


# ═══════════════════════════════════════════════════════════════════════════════
# LIFESPAN  (startup / shutdown)
# ═══════════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("══════════════════════════════════════════")
    logger.info("  MalSim API v%s  |  STARTUP", settings.APP_VERSION)
    logger.info("══════════════════════════════════════════")
    await init_db()
    logger.info("Ready — listening on http://%s:%d", settings.HOST, settings.PORT)
    yield
    logger.info("MalSim API — SHUTDOWN")


# ═══════════════════════════════════════════════════════════════════════════════
# APPLICATION FACTORY
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title       = settings.APP_NAME,
    version     = settings.APP_VERSION,
    description = (
        "**MalSim** — Malware Analysis Simulation REST API.\n\n"
        "Industry-grade sandboxed analysis pipeline with real-time state tracking.\n\n"
        "> ⚠️ **Simulation only** — no real code is ever executed.\n\n"
        "### Endpoints\n"
        "- `POST /api/v1/upload` — Submit file for analysis\n"
        "- `GET /api/v1/static-analysis/{id}` — Static analysis results\n"
        "- `GET /api/v1/dynamic-analysis/{id}` — Dynamic sandbox results\n"
        "- `GET /api/v1/threat-score/{id}` — Composite threat score & verdict\n"
        "- `GET /api/v1/status/{id}` — Lightweight polling endpoint\n"
        "- `GET /api/v1/queue` — Analysis queue with pagination\n"
        "- `GET /api/v1/dashboard/stats` — SOC dashboard aggregates\n"
        "- `GET /api/v1/report/{id}` — Full consolidated threat report\n"
    ),
    docs_url    = "/docs",
    redoc_url   = "/redoc",
    openapi_url = "/openapi.json",
    lifespan    = lifespan,
)


# ═══════════════════════════════════════════════════════════════════════════════
# MIDDLEWARE  (order matters — outermost wraps everything)
# ═══════════════════════════════════════════════════════════════════════════════

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins     = settings.ALLOWED_ORIGINS,
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# ── Rate Limiter ──────────────────────────────────────────────────────────────
app.add_middleware(RateLimitMiddleware)

# ── Request timing logger ─────────────────────────────────────────────────────
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    elapsed = (time.perf_counter() - start) * 1000
    logger.info(
        "%s %s → %d  (%.1f ms)",
        request.method, request.url.path, response.status_code, elapsed,
    )
    return response


# ═══════════════════════════════════════════════════════════════════════════════
# GLOBAL EXCEPTION HANDLERS
# ═══════════════════════════════════════════════════════════════════════════════

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    logger.warning("HTTP %d: %s at %s", exc.status_code, exc.detail, request.url.path)
    return JSONResponse(
        status_code = exc.status_code,
        content     = {"ok": False, "error": str(exc.detail)},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning("Validation error at %s: %s", request.url.path, exc.errors())
    return JSONResponse(
        status_code = status.HTTP_422_UNPROCESSABLE_ENTITY,
        content     = {
            "ok":     False,
            "error":  "Request validation failed",
            "detail": exc.errors(),
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception at %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
        content     = {"ok": False, "error": "Internal server error"},
    )


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

API_PREFIX = "/api/v1"

app.include_router(upload.router,   prefix=API_PREFIX)
app.include_router(analysis.router, prefix=API_PREFIX)
app.include_router(queue.router,    prefix=API_PREFIX)
app.include_router(report.router,   prefix=API_PREFIX)


# ── Health / root ──────────────────────────────────────────────────────────────
@app.get("/", tags=["Health"], summary="Root health check")
async def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status":  "operational",
        "docs":    "/docs",
        "api":     API_PREFIX,
    }


@app.get("/health", tags=["Health"], summary="Health probe (for load balancers)")
async def health():
    return {"status": "ok", "version": settings.APP_VERSION}
