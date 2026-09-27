import logging
import os
from datetime import UTC, datetime
from logging.handlers import TimedRotatingFileHandler

from pythonjsonlogger.json import JsonFormatter

logger = logging.getLogger(__name__)

_AUDIT_LOG_RETENTION_DAYS = 30
_ROOT_LOG_RETENTION_DAYS = 14


def setup_audit_logger(
    log_dir: str = "/logs",
    log_level: str = "INFO",
) -> logging.Logger:
    """Configure and return a structured JSON audit logger.

    Writes to daily rotated files (audit-YYYY-MM-DD.jsonl) and console.
    """
    logger = logging.getLogger("sentinel.audit")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Avoid adding duplicate handlers on repeated calls
    if logger.handlers:
        return logger

    formatter = JsonFormatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
        rename_fields={"asctime": "timestamp", "levelname": "level"},
    )

    # Console handler
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)

    # File handler — only if the log directory exists or can be created
    try:
        os.makedirs(log_dir, exist_ok=True)
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        file_path = os.path.join(log_dir, f"audit-{today}.jsonl")
        file_handler = TimedRotatingFileHandler(
            file_path,
            when="midnight",
            interval=1,
            backupCount=_AUDIT_LOG_RETENTION_DAYS,
            utc=True,
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError:
        logger.warning(
            "Could not create log directory %s; file logging disabled",
            log_dir,
            extra={"event": "audit.log_dir_create_failed"},
            exc_info=True,
        )

    # Configure the sentinel parent logger so all sentinel.* child loggers
    # (planner, executor, scanner, etc.) inherit the correct level. This is
    # required for the LogSSEWriter (UI log stream) which attaches to "sentinel".
    sentinel_parent = logging.getLogger("sentinel")
    sentinel_parent.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Persist ALL Python logging (uvicorn, tracebacks, library warnings)
    # to a separate file. These are lost on container restart without this
    # because podman captures stdout/stderr only for the container's lifetime.
    # The audit logger above covers sentinel.audit; this covers everything else.
    root = logging.getLogger()
    root.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    already_has_file = any(isinstance(h, logging.FileHandler) for h in root.handlers)
    if not already_has_file:
        try:
            today = datetime.now(UTC).strftime("%Y-%m-%d")
            root_file = os.path.join(log_dir, f"sentinel-{today}.log")
            root_handler = TimedRotatingFileHandler(
                root_file,
                when="midnight",
                interval=1,
                backupCount=_ROOT_LOG_RETENTION_DAYS,
                utc=True,
            )
            root_handler.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
            )
            root_handler.setLevel(getattr(logging, log_level.upper(), logging.INFO))
            root.addHandler(root_handler)
        except OSError:
            logger.warning(
                "setup_audit_logger: OSError suppressed",
                extra={"event": "audit.root_log_create_failed"},
                exc_info=True,
            )

    # Suppress DEBUG noise from third-party HTTP/polling libraries
    for name in ("httpcore", "httpx", "telegram", "urllib3", "hpack", "sse_starlette"):
        logging.getLogger(name).setLevel(logging.WARNING)

    return logger
