"""
Custom logging configuration for Certipy.

This module provides specialized logging formatters and initialization functions
for consistent log output across the Certipy application.
"""

import logging as _logging
import sys
from typing import Dict

# from impacket.examples import logger as _impacket_logger

_IS_VERBOSE = False  # Flag to control verbosity of logging output


def set_verbose(is_verbose: bool) -> None:
    """
    Set the verbosity level for logging.

    Args:
        is_verbose: Boolean indicating whether to enable verbose logging
    """
    global _IS_VERBOSE
    _IS_VERBOSE = is_verbose  # type: ignore


def is_verbose() -> bool:
    """
    Check if verbose logging is enabled.

    Returns:
        Boolean indicating whether verbose logging is enabled
    """
    return _IS_VERBOSE


# Bullet point mapping for different log levels
BULLET_POINTS: Dict[int, str] = {
    _logging.INFO: "[*]",
    _logging.DEBUG: "[+]",
    _logging.WARNING: "[!]",
    _logging.ERROR: "[-]",
    _logging.CRITICAL: "[-]",
}


class Formatter(_logging.Formatter):
    """
    Custom formatter that adds bullet-point indicators based on log level.

    Formats log messages with the following bullet points:
    - INFO:    [*] - Informational messages about normal operation
    - DEBUG:   [+] - Detailed debugging information
    - WARNING: [!] - Warning about potential issues
    - ERROR:   [-] - Error conditions preventing normal operation
    - CRITICAL:[-] - Critical failure requiring immediate attention
    """

    def __init__(self) -> None:
        """
        Initialize the formatter with a simple format string.

        The format uses a custom 'bullet' attribute added during formatting.
        """
        super().__init__("%(bullet)s %(message)s")

    def format(self, record: _logging.LogRecord) -> str:
        """
        Format the log record by adding an appropriate bullet point.

        Args:
            record: The log record to format

        Returns:
            Formatted log message with bullet point prefix
        """
        # Add bullet point based on log level, defaulting to "[-]" for unknown levels
        record.bullet = BULLET_POINTS.get(record.levelno, "[-]")

        # Call parent formatter to apply the format string
        return super().format(record)


def init(
    level: int = _logging.INFO, logger_name: str = "certipy", propagate: bool = False
) -> None:
    """
    Initialize the Certipy logger with the appropriate formatter.

    Args:
        level: Log level to set (default: INFO)
        logger_name: Name of the logger to configure (default: "certipy")
        propagate: Whether to propagate logs to parent loggers (default: False)

    Note:
        This function configures a logger that:
        - Outputs to stdout with bullet-point prefixed messages
        - Has the specified log level (INFO by default)
        - Can be isolated from parent loggers (default behavior)

    Example:
        # Standard initialization
        init()

        # Initialize with debug level
        init(level=logging.DEBUG)
    """
    # Create stdout handler
    handler = _logging.StreamHandler(sys.stdout)

    # Apply the custom formatter
    handler.setFormatter(Formatter())

    # Configure the logger
    logger = _logging.getLogger(logger_name)

    # Remove existing handlers if any (to avoid duplicates on re-initialization)
    if logger.handlers:
        logger.handlers.clear()

    # Add the new handler
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = propagate


# Create and export the logger instance for direct import
logging = _logging.getLogger("certipy")
