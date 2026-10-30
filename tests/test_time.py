import struct

import pytest

from certipy.lib.time import (
    filetime_to_span,
    filetime_to_str,
    span_to_filetime,
    span_to_str,
)

ONE_YEAR = 31536000


def test_filetime_to_span_reads_negative_100ns_intervals():
    filetime = struct.pack("<q", -ONE_YEAR * 10_000_000)
    assert filetime_to_span(filetime) == ONE_YEAR


@pytest.mark.parametrize("span", [0, 3600, 86400, ONE_YEAR, 2 * ONE_YEAR])
def test_span_filetime_round_trip(span: int):
    assert filetime_to_span(span_to_filetime(span)) == span


def test_span_to_filetime_rejects_negative():
    with pytest.raises(ValueError):
        span_to_filetime(-1)


@pytest.mark.parametrize(
    ("span", "expected"),
    [
        (ONE_YEAR, "1 year"),
        (2 * ONE_YEAR, "2 years"),
        (2592000, "1 month"),
        (6 * 604800, "6 weeks"),
        (86400, "1 day"),
        (3 * 86400, "3 days"),
        (3600, "1 hour"),
        (90, "90 seconds"),
        (0, ""),
        (-5, ""),
    ],
)
def test_span_to_str(span: int, expected: str):
    assert span_to_str(span) == expected


def test_filetime_to_str_formats_validity_period():
    assert filetime_to_str(span_to_filetime(ONE_YEAR)) == "1 year"


def test_filetime_to_str_reports_bad_input():
    assert filetime_to_str(b"\x00").startswith("Invalid FILETIME format")
