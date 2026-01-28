"""Lightweight logging utility.

Usage:
    from snyk_ai.utils.log import log, set_verbose

    set_verbose(True)  # Enable logging
    log("tag", "message")  # Prints: HH:MM:SS.mmm [tag] message
"""

from datetime import datetime

_verbose = False


def set_verbose(enabled: bool) -> None:
    """Enable or disable verbose logging."""
    global _verbose
    _verbose = enabled


def log(tag: str, message: str) -> None:
    """Log a message if verbose mode is enabled.

    Args:
        tag: Source identifier (typically the module name).
        message: The message to log.
    """
    if not _verbose:
        return
    now = datetime.now()
    timestamp = now.strftime("%H:%M:%S") + f".{now.microsecond // 1000:03d}"
    print(f"{timestamp} [{tag}] {message}")
