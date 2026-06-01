"""
run.py — Convenience server launcher.

Usage:
    python run.py
    python run.py --port 9000 --reload
"""

import argparse
import uvicorn

from app.config import settings


def parse_args():
    parser = argparse.ArgumentParser(description="MalSim API Server")
    parser.add_argument("--host",   default=settings.HOST,  help="Bind host")
    parser.add_argument("--port",   default=settings.PORT,  type=int, help="Bind port")
    parser.add_argument("--reload", action="store_true",    help="Hot-reload (dev mode)")
    parser.add_argument("--debug",  action="store_true",    help="Enable DEBUG logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.debug:
        import os; os.environ["DEBUG"] = "true"

    uvicorn.run(
        "app.main:app",
        host        = args.host,
        port        = args.port,
        reload      = args.reload,
        log_level   = "debug" if args.debug else "info",
        access_log  = False,   # we have our own middleware logger
    )
