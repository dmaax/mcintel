"""
mcintel.db.session
~~~~~~~~~~~~~~~~~~
Async SQLAlchemy engine and session factory.

Supports both SQLite (development) and PostgreSQL (production) via the
``DATABASE_URL`` environment variable / ``settings.database_url``.

Usage
-----
    # Application startup (called once)
    from mcintel.db.session import init_db, close_db
    await init_db()

    # Inside a request handler or task
    from mcintel.db.session import get_session
    async with get_session() as session:
        result = await session.execute(select(Server))
        servers = result.scalars().all()

    # FastAPI dependency injection
    from mcintel.db.session import db_session
    async def my_route(session: AsyncSession = Depends(db_session)):
        ...
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncGenerator
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool, StaticPool

from mcintel.config import settings
from mcintel.logging import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level singletons (initialised by init_db / closed by close_db)
# ---------------------------------------------------------------------------

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


# ---------------------------------------------------------------------------
# Engine factory helpers
# ---------------------------------------------------------------------------


def _engine_kwargs() -> dict[str, Any]:
    """
    Return keyword arguments for ``create_async_engine`` tuned for the
    current database backend.
    """
    url = settings.database_url

    if url.startswith("sqlite"):
        # SQLite needs special pool settings for async use.
        # ``StaticPool`` keeps a single in-process connection — fine for dev/test.
        return {
            "connect_args": {"check_same_thread": False},
            "poolclass": StaticPool,
            "echo": settings.app_debug,
        }

    # PostgreSQL / other backends
    return {
        # NullPool works well with async; avoids background threads.
        # For high-throughput production you may want AsyncAdaptedQueuePool.
        "poolclass": NullPool,
        "echo": settings.app_debug,
        # Connection pool health-check — reconnect on stale connections.
        "pool_pre_ping": True,
    }


# ---------------------------------------------------------------------------
# Public initialisation / teardown
# ---------------------------------------------------------------------------


async def init_db() -> None:
    """
    Create the async engine and session factory.

    Call this **once** at application startup (CLI main or FastAPI lifespan).
    Also creates all tables that don't yet exist (idempotent for dev/test;
    use Alembic migrations in production instead).
    """
    global _engine, _session_factory

    if _engine is not None:
        log.debug("Database already initialised — skipping")
        return

    log.info("Initialising database", url=_redact_url(settings.database_url))

    _engine = create_async_engine(settings.database_url, **_engine_kwargs())

    _session_factory = async_sessionmaker(
        bind=_engine,
        class_=AsyncSession,
        expire_on_commit=False,  # avoids lazy-load errors after commit
        autoflush=False,
        autocommit=False,
    )

    # Auto-create tables in dev/test mode.
    # In production, rely on Alembic migrations instead.
    if not settings.is_production:
        async with _engine.begin() as conn:
            await _create_tables(conn)

    log.info("Database ready")


async def close_db() -> None:
    """
    Dispose of the engine and release all connections.

    Call this at application shutdown.
    """
    global _engine, _session_factory

    if _engine is None:
        return

    log.info("Closing database connections")
    await _engine.dispose()
    _engine = None
    _session_factory = None


# ---------------------------------------------------------------------------
# Session context manager
# ---------------------------------------------------------------------------


@contextlib.asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Async context manager that yields a transactional ``AsyncSession``.

    Commits on success, rolls back on exception.

    Example::

        async with get_session() as session:
            session.add(some_model_instance)
            # commit happens automatically on exit
    """
    if _session_factory is None:
        raise RuntimeError("Database has not been initialised. Call `await init_db()` first.")

    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------


async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that yields an ``AsyncSession``.

    Usage::

        from fastapi import Depends
        from sqlalchemy.ext.asyncio import AsyncSession
        from mcintel.db.session import db_session

        @router.get("/servers")
        async def list_servers(session: AsyncSession = Depends(db_session)):
            ...
    """
    async with get_session() as session:
        yield session


# ---------------------------------------------------------------------------
# Engine accessor (for migrations / raw connections)
# ---------------------------------------------------------------------------


def get_engine() -> AsyncEngine:
    """Return the module-level engine. Raises if not yet initialised."""
    if _engine is None:
        raise RuntimeError("Database has not been initialised. Call `await init_db()` first.")
    return _engine


# ---------------------------------------------------------------------------
# Table creation helper (dev / test only)
# ---------------------------------------------------------------------------


async def _create_tables(conn: AsyncConnection) -> None:
    """
    Import all models so their metadata is registered, then create tables.

    This is intentionally lazy-imported to avoid circular imports during
    module load.
    """
    # Import models here to ensure they are registered on Base.metadata
    from mcintel.db import models  # noqa: F401 — side-effect import
    from mcintel.db.models import Base

    await conn.run_sync(Base.metadata.create_all)
    log.debug("Database tables created / verified")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _redact_url(url: str) -> str:
    """Replace the password in a database URL with ``***`` for safe logging."""
    try:
        from urllib.parse import urlparse, urlunparse

        parsed = urlparse(url)
        if parsed.password:
            netloc = parsed.netloc.replace(parsed.password, "***")
            return urlunparse(parsed._replace(netloc=netloc))
    except Exception:  # noqa: BLE001
        pass
    return url
