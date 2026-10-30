import datetime
from typing import Any

import pytest

from certipy.lib.formatting import pretty_print, to_pascal_case


@pytest.mark.parametrize(
    ("snake", "pascal"),
    [
        ("hello_world", "HelloWorld"),
        ("enrollee_supplies_subject", "EnrolleeSuppliesSubject"),
        ("single", "Single"),
        ("", ""),
    ],
)
def test_to_pascal_case(snake: str, pascal: str):
    assert to_pascal_case(snake) == pascal


def _lines(data: dict[str, Any], **kwargs: Any) -> list[str]:
    out: list[str] = []
    pretty_print(data, print_func=out.append, **kwargs)
    return out


def test_pretty_print_scalars_are_padded():
    assert _lines({"Name": "CA", "Port": 443}, padding=10) == [
        "Name      : CA",
        "Port      : 443",
    ]


def test_pretty_print_remaps_known_keys():
    assert _lines({"channel_binding": True}, padding=0) == [
        "Channel Binding (EPA): True"
    ]


def test_pretty_print_nested_dict_indents():
    assert _lines({"CA": {"Name": "X"}}, padding=10) == ["CA", "  Name    : X"]


def test_pretty_print_list_of_scalars_wraps():
    assert _lines({"Users": ["a", "b"]}, padding=8) == [
        "Users   : a",
        "          b",
    ]


def test_pretty_print_empty_list():
    assert _lines({"Users": []}, padding=8) == ["Users   :"]


def test_pretty_print_skips_none():
    assert _lines({"Gone": None, "Kept": 1}, padding=6) == ["Kept  : 1"]


def test_pretty_print_datetime_is_iso():
    when = datetime.datetime(2026, 1, 2, 3, 4, 5)
    assert _lines({"When": when}, padding=6) == ["When  : 2026-01-02T03:04:05"]


def test_pretty_print_rejects_unsupported_type():
    with pytest.raises(TypeError):
        _lines({"Bad": object()})
