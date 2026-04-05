"""
mcintel.config
~~~~~~~~~~~~~~
Central configuration system.

Settings are loaded from (in priority order):
  1. Environment variables
  2. A .env file in the working directory
  3. Hard-coded defaults below

Usage
-----
    from mcintel.config import settings

    print(settings.database_url)
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic import AnyUrl, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AppEnv(str, Enum):
    development = "development"
    production = "production"
    test = "test"


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogFormat(str, Enum):
    text = "text"
    json = "json"


# ---------------------------------------------------------------------------
# Settings model
# ---------------------------------------------------------------------------


class Settings(BaseSettings):
    """
    All runtime configuration for mcintel.

    Every field maps directly to an environment variable (case-insensitive).
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ─────────────────────────────────────────────────────────
    app_env: AppEnv = AppEnv.development
    app_debug: bool = False
    app_log_level: LogLevel = LogLevel.INFO
    app_log_format: LogFormat = LogFormat.text

    # ── Database ────────────────────────────────────────────────────────────
    database_url: str = Field(
        default="sqlite+aiosqlite:///./data/mcintel.db",
        description="SQLAlchemy async database URL",
    )

    # ── Redis ────────────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── API Server ───────────────────────────────────────────────────────────
    api_host: str = "0.0.0.0"
    api_port: int = Field(default=8000, ge=1, le=65535)
    api_reload: bool = True
    api_secret_key: str = "change-me-to-a-long-random-string"
    api_allowed_origins: list[str] = ["http://localhost:3000", "https://mcin.tel"]

    # ── Rate Limiting / Politeness ───────────────────────────────────────────
    scan_ping_interval: int = Field(
        default=300,
        ge=1,
        description="Minimum seconds between successive pings to the same server",
    )
    scan_max_concurrency: int = Field(
        default=50,
        ge=1,
        le=1000,
        description="Max concurrent scanner coroutines",
    )
    scan_timeout: float = Field(
        default=5.0,
        gt=0,
        description="TCP connect/read timeout in seconds",
    )

    # ── Scheduler ────────────────────────────────────────────────────────────
    scheduler_enabled: bool = True
    scheduler_ping_cron: str = "*/15 * * * *"

    # ── External APIs ────────────────────────────────────────────────────────
    ipinfo_token: str = ""
    shodan_api_key: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""

    # ── Mojang API ───────────────────────────────────────────────────────────
    mojang_rate_limit: int = Field(
        default=600,
        ge=1,
        description="Max Mojang API requests per 10 minutes",
    )

    # ── NameMC ───────────────────────────────────────────────────────────────
    namemc_user_agent: str = "mcintel/0.1 (https://mcin.tel; research)"

    # ── Data Retention ───────────────────────────────────────────────────────
    retention_ping_days: int = Field(
        default=90,
        description="Days to keep raw ping records (-1 = forever)",
    )
    retention_dns_days: int = Field(
        default=365,
        description="Days to keep DNS history records (-1 = forever)",
    )

    # ── Opt-out ──────────────────────────────────────────────────────────────
    optout_list_path: Path = Path("./data/optout.txt")

    # ── Derived helpers ──────────────────────────────────────────────────────

    @property
    def is_development(self) -> bool:
        return self.app_env == AppEnv.development

    @property
    def is_production(self) -> bool:
        return self.app_env == AppEnv.production

    @property
    def is_test(self) -> bool:
        return self.app_env == AppEnv.test

    @property
    def using_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def using_postgres(self) -> bool:
        return self.database_url.startswith("postgresql")

    @field_validator("api_allowed_origins", mode="before")
    @classmethod
    def parse_origins(cls, v: object) -> list[str]:
        """Allow a comma-separated string or a proper list."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v  # type: ignore[return-value]

    @field_validator("optout_list_path", mode="before")
    @classmethod
    def expand_path(cls, v: object) -> Path:
        return Path(str(v)).expanduser()


# ---------------------------------------------------------------------------
# Singleton — import this everywhere
# ---------------------------------------------------------------------------

settings = Settings()
