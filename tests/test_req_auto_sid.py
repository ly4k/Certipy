import argparse
from typing import Any, Dict, List

import pytest

from certipy.commands import req
from certipy.commands.parsers import req as req_parser


class StopAfterRequestError(Exception):
    pass


def _options(**overrides: Any) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    req_parser.add_subparser(subparsers)
    argv = [
        "req",
        "-u",
        "lowpriv@corp.local",
        "-p",
        "Passw0rd!",
        "-dc-ip",
        "10.0.0.10",
        "-target-ip",
        "10.0.0.20",
        "-target",
        "ca.corp.local",
        "-ca",
        "CORP-CA",
        "-template",
        "ESC1",
    ]
    options = parser.parse_args(argv)
    for key, value in overrides.items():
        setattr(options, key, value)
    return options


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch) -> Dict[str, Any]:
    seen: Dict[str, Any] = {"calls": []}

    def fake_resolve(target: Any, upn: Any, dns: Any, sid: Any) -> Any:
        seen["calls"].append((target, upn, dns, sid))
        return "S-1-5-21-1-2-3-500"

    class FakeRequest:
        def __init__(self, **kwargs: Any) -> None:
            seen["request_kwargs"] = kwargs
            raise StopAfterRequestError

    monkeypatch.setattr(req, "resolve_alt_sid", fake_resolve)
    monkeypatch.setattr(req, "Request", FakeRequest)
    return seen


def test_req_passes_looked_up_sid_to_request(captured: Dict[str, Any]) -> None:
    with pytest.raises(StopAfterRequestError):
        req.entry(_options(upn="administrator@corp.local"))
    target, upn, dns, sid = captured["calls"][0]
    assert (upn, dns, sid) == ("administrator@corp.local", None, None)
    assert target.username == "LOWPRIV"
    assert captured["request_kwargs"]["sid"] == "S-1-5-21-1-2-3-500"


@pytest.mark.parametrize("override", [{"retrieve": 7}, {"cax_cert": True}])
def test_req_skips_lookup_when_not_requesting(
    captured: Dict[str, Any], override: Dict[str, Any]
) -> None:
    with pytest.raises(StopAfterRequestError):
        req.entry(_options(upn="administrator@corp.local", **override))
    calls: List[Any] = captured["calls"]
    assert calls == []
