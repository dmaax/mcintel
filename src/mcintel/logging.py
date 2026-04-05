"""
mcintel.logging
~~~~~~~~~~~~~~~
Structured logging setup for mcintel.

Supports two output formats controlled by ``settings.app_log_format``:
  - ``text`` — human-readable coloured output via ``rich``
  - ``json`` — machine-readable JSON lines, ideal for log aggregators

Usage
-----
    from mcintel.logging import get_logger

    log = get_logger(__name__)
    log.info("Server pinged", host="play.example.com", port=25565, latency_ms=42)
"""

from __future__ import annotations

import json
import logging
import sys
import time
import traceback
from datetime import UTC, datetime
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_LOGGER_NAME = "mcintel"

# ANSI colour helpers (used only in text mode)
_RESET = "\033[0m"
_BOLD = "\033[1m"
_COLOURS: dict[int, str] = {
    logging.DEBUG: "\033[36m",  # cyan
    logging.INFO: "\033[32m",  # green
    logging.WARNING: "\033[33m",  # yellow
    logging.ERROR: "\033[31m",  # red
    logging.CRITICAL: "\033[35m",  # magenta
}

_LEVEL_LABELS: dict[int, str] = {
    logging.DEBUG: "DEBUG",
    logging.INFO: "INFO ",
    logging.WARNING: "WARN ",
    logging.ERROR: "ERROR",
    logging.CRITICAL: "CRIT ",
}

# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------


class _TextFormatter(logging.Formatter):
    """Coloured, human-readable single-line log formatter."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: ANN201
        colour = _COLOURS.get(record.levelno, "")
        level_label = _LEVEL_LABELS.get(record.levelno, record.levelname[:5])
        ts = datetime.now(UTC).strftime("%H:%M:%S.%f")[:-3]  # HH:MM:SS.mmm

        # Core message
        msg = record.getMessage()

        # Extra structured fields attached via log.info("…", key=value)
        extras = _extract_extras(record)
        extras_str = ""
        if extras:
            parts = [f"{k}={v!r}" for k, v in extras.items()]
            extras_str = "  " + "  ".join(parts)

        # Exception info
        exc_str = ""
        if record.exc_info:
            exc_str = "\n" + "".join(traceback.format_exception(*record.exc_info)).rstrip()

        name_short = record.name.replace(_LOGGER_NAME + ".", "")

        line = (
            f"{colour}{_BOLD}{ts}{_RESET} "
            f"{colour}{level_label}{_RESET} "
            f"\033[2m{name_short:<20}{_RESET} "
            f"{msg}"
            f"{extras_str}"
            f"{exc_str}"
        )
        return line


class _JsonFormatter(logging.Formatter):
    """JSON Lines formatter — one JSON object per log record."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: ANN201
        payload: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }

        extras = _extract_extras(record)
        if extras:
            payload.update(extras)

        if record.exc_info:
            payload["exc"] = "".join(traceback.format_exception(*record.exc_info)).rstrip()

        return json.dumps(payload, default=str, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Structured adapter — lets callers pass keyword extras
# ---------------------------------------------------------------------------


class _StructuredAdapter(logging.LoggerAdapter):
    """
    Wraps a standard Logger so callers can attach arbitrary key-value data:

        log = get_logger(__name__)
        log.info("Ping complete", host="play.example.com", latency_ms=12)
    """

    def process(self, msg: str, kwargs: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        # Pull out any non-standard kwargs and stash them as ``extra``
        std_keys = {
            "exc_info",
            "stack_info",
            "stacklevel",
            "extra",
            "args",
        }
        extra: dict[str, Any] = kwargs.pop("extra", {}) or {}

        for key in list(kwargs.keys()):
            if key not in std_keys:
                extra[key] = kwargs.pop(key)

        if extra:
            kwargs["extra"] = {**getattr(self, "extra", {}), **extra}

        return msg, kwargs


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_extras(record: logging.LogRecord) -> dict[str, Any]:
    """Return fields that were injected via ``extra=`` and aren't stdlib attrs."""
    stdlib_attrs = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()) | {
        "message",
        "asctime",
        "taskName",
    }
    return {
        k: v for k, v in record.__dict__.items() if k not in stdlib_attrs and not k.startswith("_")
    }


# ---------------------------------------------------------------------------
# Public initialiser
# ---------------------------------------------------------------------------


def setup_logging(
    *,
    level: str = "INFO",
    fmt: str = "text",
    force: bool = False,
) -> None:
    """
    Configure the root ``mcintel`` logger.

    Call this once at application startup (CLI entry-point or API ``lifespan``).

    Parameters
    ----------
    level:
        Logging level string — ``"DEBUG"``, ``"INFO"``, ``"WARNING"``, etc.
    fmt:
        ``"text"`` for human-readable output, ``"json"`` for JSON lines.
    force:
        If *True*, reconfigure even if handlers are already set up.
        Useful in tests.
    """
    root = logging.getLogger(_LOGGER_NAME)

    if root.handlers and not force:
        return  # already configured

    # Clear any existing handlers
    root.handlers.clear()

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root.setLevel(numeric_level)

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(numeric_level)

    if fmt == "json":
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(_TextFormatter())

    root.addHandler(handler)
    root.propagate = False  # don't bubble up to the root Python logger


# ---------------------------------------------------------------------------
# Factory — the only function most callers need
# ---------------------------------------------------------------------------


def get_logger(name: str) -> _StructuredAdapter:
    """
    Return a structured logger for *name*.

    Typically called with ``__name__`` so log records include the module path:

        log = get_logger(__name__)

    The returned adapter supports keyword extras:

        log.debug("Resolved SRV", domain="play.example.com", target="mc.host.net", port=25565)
    """
    # Ensure the name is scoped under the mcintel namespace
    if not name.startswith(_LOGGER_NAME):
        full_name = f"{_LOGGER_NAME}.{name}" if name else _LOGGER_NAME
    else:
        full_name = name

    logger = logging.getLogger(full_name)
    return _StructuredAdapter(logger, {})
