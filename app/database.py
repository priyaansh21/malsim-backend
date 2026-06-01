"""
database.py — Async SQLite engine setup using SQLAlchemy 2.x + aiosqlite.

Provides:
  - Async engine & session factory
  - Base declarative class for all ORM models
  - init_db() coroutine called at application startup
"""

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)

DATABASE_URL = f"sqlite+aiosqlite:///{settings.DB_PATH}"

# ── Engine ────────────────────────────────────────────────────────────────────
engine = create_async_engine(
    DATABASE_URL,
    echo=settings.DEBUG,          # SQL statement logging in debug mode
    connect_args={"check_same_thread": False},
)

# ── Session Factory ───────────────────────────────────────────────────────────
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


# ── Declarative Base ──────────────────────────────────────────────────────────
class Base(DeclarativeBase):
    pass


# ── Dependency Injection Helper ───────────────────────────────────────────────
async def get_db() -> AsyncSession:
    """FastAPI dependency that yields an async DB session per request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ── Database Initialisation ───────────────────────────────────────────────────
async def init_db() -> None:
    """
    Create all tables defined via ORM models.
    Called once during application lifespan startup.
    """
    # Import models here so their metadata is registered before DDL
    from app.models import file_record  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database initialised at %s", settings.DB_PATH)
