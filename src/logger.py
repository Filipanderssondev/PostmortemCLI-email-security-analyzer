# src/logger.py
# Centralized logging for PostmortemCLI
# Usage: from src.logger import get_logger
#        logger = get_logger(__name__)

import logging
import os
from datetime import datetime


def get_logger(name: str) -> logging.Logger:
    """Returns a configured logger for the given module."""

    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # ── Console handler ──────────────────────────────────
    # Use UTF-8 encoding to support Unicode characters on all platforms
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)s  ->  %(message)s",
        datefmt="%H:%M:%S"
    ))
    if hasattr(console.stream, 'reconfigure'):
        try:
            console.stream.reconfigure(encoding='utf-8')
        except Exception:
            pass
    logger.addHandler(console)

    # ── File handler ─────────────────────────────────────
    # Use tempfile.gettempdir() for cross-platform temp directory
    # Linux/Mac: /tmp/postmortem   Windows: C:\Users\...\AppData\Local\Temp\postmortem
    import tempfile
    log_dir = os.path.join(tempfile.gettempdir(), "postmortem")
    os.makedirs(log_dir, exist_ok=True)

    timestamp    = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file     = os.path.join(log_dir, f"session_{timestamp}.log")
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)s  ->  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(file_handler)

    logger.debug(f"Logger initialized - session log: {log_file}")

    return logger