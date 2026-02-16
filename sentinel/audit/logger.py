import logging
import os
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler

from pythonjsonlogger.json import JsonFormatter


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
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        file_path = os.path.join(log_dir, f"audit-{today}.jsonl")
        file_handler = TimedRotatingFileHandler(
            file_path,
            when="midnight",
            interval=1,
            backupCount=30,
            utc=True,
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError:
        logger.warning("Could not create log directory %s; file logging disabled", log_dir)

    return logger
