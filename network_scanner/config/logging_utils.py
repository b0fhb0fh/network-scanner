from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
import sys
from pathlib import Path

from .settings import Settings


def get_app_logger(settings: Settings) -> logging.Logger:
    """Return the application logger configured to write into data/activity.log.

    Ensures idempotent configuration (no duplicate handlers on repeated calls).
    """
    logger = logging.getLogger("network_scanner")
    logger.setLevel(logging.INFO)

    log_file: Path = settings.data_dir / "activity.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)

    # Only add a file handler once per process
    handler_key = str(log_file.resolve())
    for h in logger.handlers:
        if isinstance(h, RotatingFileHandler):
            # Compare by filename to avoid duplicates
            try:
                if Path(h.baseFilename).resolve() == log_file.resolve():
                    return logger
            except Exception:
                continue

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    try:
        file_handler = RotatingFileHandler(
            filename=str(log_file),
            maxBytes=5 * 1024 * 1024,  # 5 MB
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception:
        # Fallback to stderr logging if file is not writable
        if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
            stream_handler = logging.StreamHandler(stream=sys.stderr)
            stream_handler.setFormatter(formatter)
            logger.addHandler(stream_handler)

    return logger


