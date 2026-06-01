"""
config.py — Centralized application configuration.
Reads from environment variables with sane defaults.
"""

from pydantic_settings import BaseSettings
from pathlib import Path


class Settings(BaseSettings):
    # ── Application ──────────────────────────────────────────────────────────
    APP_NAME: str = "MalSim API"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # ── Server ───────────────────────────────────────────────────────────────
    HOST: str = "0.0.0.0"
    PORT: int = 8500

    # ── CORS ─────────────────────────────────────────────────────────────────
    ALLOWED_ORIGINS: list[str] = [
        "http://localhost",
        "http://127.0.0.1",
        "http://localhost:8500",
        "null",          # file:// origin for the HTML frontend
    ]

    # ── Storage ──────────────────────────────────────────────────────────────
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    UPLOAD_DIR: Path = BASE_DIR / "uploads"
    DB_PATH: Path = BASE_DIR / "malsim.db"
    LOG_DIR: Path = BASE_DIR / "logs"

    # ── Upload Constraints ───────────────────────────────────────────────────
    MAX_FILE_SIZE_BYTES: int = 50 * 1024 * 1024   # 50 MB
    ALLOWED_EXTENSIONS: set[str] = {
        ".exe", ".dll", ".pdf", ".doc", ".docx",
        ".ps1", ".js", ".bat", ".zip", ".bin",
        ".sh", ".py", ".vbs", ".msi", ".apk",
    }

    # ── Analysis Engine ──────────────────────────────────────────────────────
    ANALYSIS_TIMEOUT_SECONDS: int = 30
    SANDBOX_SIMULATION_DELAY: float = 0.8   # seconds per analysis step

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()

# Ensure required directories exist
settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
settings.LOG_DIR.mkdir(parents=True, exist_ok=True)
