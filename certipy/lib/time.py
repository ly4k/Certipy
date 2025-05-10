"""
Time Conversion Utilities

This module provides functions for handling Microsoft Windows FILETIME format
and converting time spans to human-readable strings.
"""

import struct

# Constants for time calculations (in seconds)
SECONDS_PER_HOUR = 3600
SECONDS_PER_DAY = 86400
SECONDS_PER_WEEK = 604800
SECONDS_PER_MONTH = 2592000  # 30-day month approximation
SECONDS_PER_YEAR = 31536000  # 365-day year approximation

# FILETIME conversion factor
# Windows FILETIME is in 100-nanosecond intervals
# Negative because FILETIME represents time remaining
FILETIME_CONVERSION_FACTOR = -0.0000001


def filetime_to_span(filetime: bytes) -> int:
    """
    Convert Windows FILETIME to time span in seconds.

    Windows FILETIME is a 64-bit value representing the number of
    100-nanosecond intervals since January 1, 1601 UTC.
    When used for validity periods, negative values represent time remaining.

    Args:
        filetime: Windows FILETIME as 8 bytes

    Returns:
        Time span in seconds (absolute value)

    Raises:
        struct.error: If the input bytes cannot be unpacked as a 64-bit integer
    """
    # Unpack the 8-byte FILETIME as a 64-bit integer (little-endian)
    (span,) = struct.unpack("<q", filetime)

    # Convert from 100-nanosecond intervals to seconds
    span *= FILETIME_CONVERSION_FACTOR

    return int(span)


def span_to_filetime(span: int) -> bytes:
    """
    Convert a time span in seconds to Windows FILETIME format.

    This function converts the time span to a 64-bit integer representing
    the number of 100-nanosecond intervals since January 1, 1601 UTC.

    Args:
        span: Time span in seconds (positive integer)

    Returns:
        Windows FILETIME as 8 bytes

    Raises:
        ValueError: If the input span is negative
    """
    if span < 0:
        raise ValueError("Span must be a positive integer")

    # Convert seconds to 100-nanosecond intervals
    filetime = int(span / FILETIME_CONVERSION_FACTOR)

    # Pack as little-endian 64-bit integer
    return struct.pack("<q", filetime)


def span_to_str(span: int) -> str:
    """
    Convert a time span in seconds to a human-readable string.

    The function converts the span to the largest appropriate unit
    (years, months, weeks, days, or hours) for readability.

    Args:
        span: Time span in seconds (positive integer)

    Returns:
        Human-readable time span (e.g., "1 year", "2 months", "3 weeks")
        Empty string if span is negative or zero
    """
    if span <= 0:
        return ""

    # Time unit conversion table
    # (seconds_per_unit, singular_name, plural_name)
    time_units = [
        (SECONDS_PER_YEAR, "year", "years"),
        (SECONDS_PER_MONTH, "month", "months"),
        (SECONDS_PER_WEEK, "week", "weeks"),
        (SECONDS_PER_DAY, "day", "days"),
        (SECONDS_PER_HOUR, "hour", "hours"),
    ]

    # Find the largest unit that divides span evenly
    for seconds_per_unit, singular, plural in time_units:
        if span % seconds_per_unit == 0 and span // seconds_per_unit >= 1:
            unit_count = span // seconds_per_unit
            return f"{unit_count} {singular if unit_count == 1 else plural}"

    # If no exact match, return in seconds
    return f"{span} seconds"


def filetime_to_str(filetime: bytes) -> str:
    """
    Convert Windows FILETIME to a human-readable time span string.

    This is a convenience function that combines filetime_to_span()
    and span_to_str() operations.

    Args:
        filetime: Windows FILETIME as bytes

    Returns:
        Human-readable time span string

    Example:
        >>> filetime_bytes = struct.pack("<q", -315360000000000)  # 1 year in FILETIME format
        >>> filetime_to_str(filetime_bytes)
        '1 year'
    """
    try:
        span = filetime_to_span(filetime)
        return span_to_str(span)
    except (struct.error, TypeError, ValueError) as e:
        # Handle potential errors in the FILETIME format
        return f"Invalid FILETIME format: {str(e)}"
