"""Lightweight logging utility.

Usage:
    from snyk_ai.utils.log import log, set_verbose

    set_verbose(True)  # Enable logging
    log("tag", "message")  # Prints: HH:MM:SS.mmm [       tag] message
    log(None, "message")   # Auto-detects tag from caller's filename
"""

import inspect
from datetime import datetime
from pathlib import Path

_verbose = False


def set_verbose(enabled: bool) -> None:
    """Enable or disable verbose logging."""
    global _verbose
    _verbose = enabled


def log(message: str, tag: str | None = None) -> None:
    """Log a message if verbose mode is enabled.

    Args:
        tag: Source identifier. If None, uses caller's filename (without extension).
        message: The message to log.
    """
    if not _verbose:
        return
    if tag is None:
        frame = inspect.currentframe()
        caller_frame = frame.f_back
        tag = Path(caller_frame.f_code.co_filename).stem
    now = datetime.now()
    timestamp = now.strftime("%H:%M:%S") + f".{now.microsecond // 1000:03d}"
    print(f"{timestamp} [ {tag:>10} ] {message}")
