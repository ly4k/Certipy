import argparse
import base64
from types import SimpleNamespace
from typing import Any
from xml.etree import ElementTree

import httpx
import pytest

from certipy.commands import req as req_command
from certipy.commands.parsers import req as req_parser
from certipy.lib import req as req_module
from certipy.lib.certificate import generate_rsa_key
from certipy.lib.ces import ADDR_NS, AUTHZ_NS, WST_NS
from certipy.lib.constants import USER_AGENT
from certipy.lib.kerberos import HttpxKerberosAuth
from certipy.lib.ntlm import HttpxNtlmAuth
from certipy.lib.req import (
    CESRequestInterface,
    Request,
    ces_request,
    create_http_session,
)
from tests.test_ces import _fault, _rstr, _self_signed_der

PATH = "/ESSOS-CA_CES_Kerberos/service.svc/CES"
TO_URL = f"https://braavos.essos.local{PATH}"


def _session(handler: Any) -> httpx.Client:
    return httpx.Client(
        base_url="https://10.0.0.5:443", transport=httpx.MockTransport(handler)
    )


def _call(session: httpx.Client) -> Any:
    return ces_request(
        session,
        PATH,
        TO_URL,
        "missandei",
        b"\x30\x03\x02\x01\x00",
        ["CertificateTemplate:User"],
        "User",
        generate_rsa_key(2048),
    )


def _xml_response(status: int, body: bytes) -> httpx.Response:
    return httpx.Response(
        status, content=body, headers={"Content-Type": "application/soap+xml"}
    )


@pytest.fixture
def pending_saves(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    saved: list[int] = []
    monkeypatch.setattr(
        req_module,
        "handle_pending_key_save",
        lambda request_id, key, out=None: saved.append(request_id),
    )
    return saved


def test_ces_request_posts_wstep_envelope():
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["path"] = request.url.path
        seen["content_type"] = request.headers["Content-Type"]
        seen["body"] = request.content
        return _xml_response(
            200, _rstr(cert_token=base64.b64encode(_self_signed_der()).decode())
        )

    assert _call(_session(handler)) is not None
    assert seen["method"] == "POST"
    assert seen["path"] == PATH
    assert seen["content_type"].startswith("application/soap+xml")
    root = ElementTree.fromstring(seen["body"])
    assert root.findtext(f".//{{{ADDR_NS}}}To") == TO_URL
    assert root.find(f".//{{{WST_NS}}}RequestSecurityToken") is not None
    item = root.find(f".//{{{AUTHZ_NS}}}ContextItem")
    assert item is not None and item.get("Name") == "CertificateTemplate"


def test_ces_request_pending_offers_key_save(pending_saves: list[int]):
    session = _session(
        lambda r: _xml_response(
            200, _rstr(request_id="19", disposition="Taken Under Submission")
        )
    )
    assert _call(session) is None
    assert pending_saves == [19]


def test_ces_request_issued_without_certificate_is_not_pending(
    pending_saves: list[int],
):
    session = _session(lambda r: _xml_response(200, _rstr(request_id="21")))
    assert _call(session) is None
    assert pending_saves == []


def test_ces_request_fault_returns_none(pending_saves: list[int]):
    body = _fault("Denied by Policy Module", "-2146877422", "18")
    assert _call(_session(lambda r: _xml_response(500, body))) is None
    assert pending_saves == []


def test_ces_request_non_xml_error_returns_none():
    session = _session(lambda r: httpx.Response(404, text="Not Found"))
    assert _call(session) is None


def test_ces_request_unauthorized_returns_none():
    session = _session(lambda r: httpx.Response(401, text="Unauthorized"))
    assert _call(session) is None


def _parent(**overrides: Any) -> SimpleNamespace:
    values: dict[str, Any] = dict(
        target=SimpleNamespace(
            target_ip="10.0.0.5",
            remote_name="braavos.essos.local",
            do_kerberos=False,
            timeout=5,
        ),
        no_channel_binding=False,
        ca="ESSOS-CA",
        ces_path=None,
        http_scheme="https",
        http_port=443,
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def test_interface_default_urls():
    interface = CESRequestInterface(_parent())  # type: ignore[arg-type]
    assert interface.path == PATH
    assert interface.base_url == "https://10.0.0.5:443"
    assert interface.endpoint_url == TO_URL
    assert interface.session.headers["Host"] == "braavos.essos.local"


def test_interface_non_default_port_and_custom_path():
    interface = CESRequestInterface(
        _parent(http_port=8443, ces_path="/Custom_CES_Kerberos/service.svc/CES")  # type: ignore[arg-type]
    )
    assert interface.base_url == "https://10.0.0.5:8443"
    assert (
        interface.endpoint_url
        == "https://braavos.essos.local:8443/Custom_CES_Kerberos/service.svc/CES"
    )
    assert interface.session.headers["Host"] == "braavos.essos.local:8443"


def test_interface_relative_ces_path_is_normalized():
    interface = CESRequestInterface(
        _parent(ces_path="Custom_CES_Kerberos/service.svc/CES")  # type: ignore[arg-type]
    )
    assert interface.path == "/Custom_CES_Kerberos/service.svc/CES"
    assert (
        interface.endpoint_url
        == "https://braavos.essos.local/Custom_CES_Kerberos/service.svc/CES"
    )


def test_interface_falls_back_to_ip_without_hostname():
    parent = _parent(
        target=SimpleNamespace(
            target_ip="10.0.0.5", remote_name="", do_kerberos=False, timeout=5
        )
    )
    interface = CESRequestInterface(parent)  # type: ignore[arg-type]
    assert interface.endpoint_url == f"https://10.0.0.5{PATH}"
    assert "Host" not in interface.session.headers


def test_interface_requires_ca_or_path():
    interface = CESRequestInterface(_parent(ca=None))  # type: ignore[arg-type]
    with pytest.raises(Exception, match="-ca"):
        _ = interface.path


def test_interface_request_requires_key():
    interface = CESRequestInterface(_parent(key=None))  # type: ignore[arg-type]
    with pytest.raises(Exception, match="private key"):
        interface.request(b"csr", [])


def test_interface_request_calls_ces_request(monkeypatch: pytest.MonkeyPatch):
    key = generate_rsa_key(2048)
    parent = _parent(key=key, template="User", out="out")
    parent.target.username = "missandei"
    interface = CESRequestInterface(parent)  # type: ignore[arg-type]
    calls: list[tuple[Any, ...]] = []
    monkeypatch.setattr(req_module, "ces_request", lambda *a: calls.append(a) or "ok")
    assert interface.request(b"csr", ["CertificateTemplate:User"]) == "ok"
    assert calls == [
        (
            interface.session,
            PATH,
            TO_URL,
            "missandei",
            b"csr",
            ["CertificateTemplate:User"],
            "User",
            key,
            "out",
        )
    ]


def test_interface_retrieve_not_supported():
    interface = CESRequestInterface(_parent())  # type: ignore[arg-type]
    assert interface.retrieve(1) is None


def test_create_http_session_auth_selection():
    ntlm = create_http_session(
        SimpleNamespace(do_kerberos=False, timeout=5),  # type: ignore[arg-type]
        "https://10.0.0.5:443",
        channel_binding=True,
    )
    kerberos = create_http_session(
        SimpleNamespace(do_kerberos=True, timeout=5),  # type: ignore[arg-type]
        "https://10.0.0.5:443",
        channel_binding=True,
    )
    assert isinstance(ntlm.auth, HttpxNtlmAuth)
    assert isinstance(kerberos.auth, HttpxKerberosAuth)
    assert ntlm.headers["User-Agent"] == USER_AGENT


@pytest.mark.parametrize(
    "kwargs, scheme, port",
    [
        ({"ces": True}, "https", 443),
        ({"web": True}, "http", 80),
        ({"ces": True, "http_scheme": "http"}, "http", 80),
        ({}, None, None),
    ],
)
def test_request_scheme_defaults(kwargs: dict[str, Any], scheme: Any, port: Any):
    request = Request(target=SimpleNamespace(), **kwargs)  # type: ignore[arg-type]
    assert request.http_scheme == scheme
    assert request.http_port == port


def test_request_selects_ces_interface():
    request = Request(target=SimpleNamespace(), ces=True, ca="ESSOS-CA")  # type: ignore[arg-type]
    assert isinstance(request.interface, CESRequestInterface)


def _parse(*argv: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    req_parser.add_subparser(parser.add_subparsers(dest="action"))
    return parser.parse_args(["req", *argv])


def test_parser_ces_flags():
    options = _parse("-ces", "-ces-path", "/X_CES_Kerberos/service.svc/CES")
    assert options.ces is True
    assert options.ces_path == "/X_CES_Kerberos/service.svc/CES"


def test_parser_defaults():
    options = _parse()
    assert options.ces is False
    assert options.ces_path is None
    assert options.http_scheme is None


@pytest.mark.parametrize("other", ["-web", "-dcom"])
def test_entry_rejects_ces_with_web(monkeypatch: pytest.MonkeyPatch, other: str):
    built: list[Any] = []
    monkeypatch.setattr(req_command, "Request", lambda **kw: built.append(kw))
    monkeypatch.setattr(
        req_command.Target, "from_options", staticmethod(lambda options: object())
    )
    req_command.entry(_parse("-ces", other))
    assert built == []
