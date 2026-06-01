"""
middleware/rate_limit.py — In-memory sliding-window rate limiter.

Limits upload requests to MAX_REQUESTS_PER_MINUTE per client IP.
Uses a simple deque-based sliding window — no Redis required for dev.

Production note: Replace with redis-py + token bucket for multi-process setups.
"""

import time
from collections import defaultdict, deque
from typing import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.utils.logger import get_logger

logger = get_logger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
MAX_REQUESTS_PER_MINUTE: int = 60     # per IP
WINDOW_SECONDS: int = 60

# ── State (per-process — swap for Redis in production) ────────────────────────
_ip_windows: dict[str, deque] = defaultdict(deque)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Sliding-window rate limiter applied to all routes.
    Returns 429 JSON when limit is exceeded.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = _get_client_ip(request)
        now = time.monotonic()

        window = _ip_windows[client_ip]

        # Evict timestamps older than the window
        while window and now - window[0] > WINDOW_SECONDS:
            window.popleft()

        if len(window) >= MAX_REQUESTS_PER_MINUTE:
            logger.warning("Rate limit exceeded for IP: %s", client_ip)
            return JSONResponse(
                status_code=429,
                content={
                    "ok": False,
                    "error": "Rate limit exceeded. Maximum 60 requests/minute per IP.",
                },
                headers={"Retry-After": str(WINDOW_SECONDS)},
            )

        window.append(now)
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(MAX_REQUESTS_PER_MINUTE)
        response.headers["X-RateLimit-Remaining"] = str(
            MAX_REQUESTS_PER_MINUTE - len(window)
        )
        return response


def _get_client_ip(request: Request) -> str:
    """Extract real client IP, respecting X-Forwarded-For for reverse proxies."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"
