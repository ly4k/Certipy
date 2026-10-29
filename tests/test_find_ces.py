from types import SimpleNamespace
from typing import Any, Callable

import httpx

from certipy.commands.find import Find
from certipy.lib.ldap import LDAPEntry

CES_URI = "https://braavos.essos.local/ESSOS-CA_CES_Kerberos/service.svc/CES"


def _find() -> Find:
    f = Find.__new__(Find)  # bypass __init__; we only test pure helpers
    target: Any = SimpleNamespace(
        timeout=5, resolver=SimpleNamespace(resolve=lambda n: "10.0.0.5")
    )
    f.target = target
    return f


def _factory(
    handler: Callable[[httpx.Request], httpx.Response],
) -> Callable[[], httpx.Client]:
    return lambda: httpx.Client(transport=httpx.MockTransport(handler))


def test_probe_enrollment_server_reachable():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/service.svc/CES")
        assert request.headers["Host"] == "braavos.essos.local"
        return httpx.Response(401, headers={"WWW-Authenticate": "Negotiate"})

    f = _find()
    f.check_enrollment_channel_binding = lambda parsed, ip: True  # type: ignore
    reachable, cb = f.probe_enrollment_server(
        CES_URI, session_factory=_factory(handler)
    )
    assert reachable is True
    assert cb is True


def test_probe_enrollment_server_http_skips_channel_binding():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401)

    reachable, cb = _find().probe_enrollment_server(
        "http://x/y_CES_Kerberos/service.svc/CES", session_factory=_factory(handler)
    )
    assert reachable is True
    assert cb is None


def test_probe_enrollment_server_unreachable():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    reachable, cb = _find().probe_enrollment_server(
        CES_URI, session_factory=_factory(handler)
    )
    assert reachable is False
    assert cb is None


def test_probe_enrollment_server_channel_binding_error_is_none():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401)

    f = _find()

    def boom(parsed: httpx.URL, ip: str):
        raise RuntimeError("x")

    f.check_enrollment_channel_binding = boom  # type: ignore
    reachable, cb = f.probe_enrollment_server(
        CES_URI, session_factory=_factory(handler)
    )
    assert reachable is True
    assert cb is None


def _ep(**kw: Any) -> dict[str, Any]:
    base = {
        "uri": "https://h/ca_CES_Kerberos/service.svc/CES",
        "auth": ["Kerberos"],
        "scheme": "https",
        "reachable": True,
        "channel_binding": None,
        "priority": 1,
        "renewals_only": False,
    }
    base.update(kw)
    return base


def test_esc8_ces_relayable_http():
    ep = [_ep(uri="http://h/ca_CES_Kerberos/service.svc/CES", scheme="http")]
    assert "CES" in (Find.evaluate_esc8_ces(ep, True) or "")


def test_esc8_ces_https_epa_not_relayable():
    assert Find.evaluate_esc8_ces([_ep(channel_binding=True)], True) is None


def test_esc8_ces_usernamepassword_not_relayable():
    ep = [_ep(auth=["UsernameAndPassword"], channel_binding=False)]
    assert Find.evaluate_esc8_ces(ep, True) is None


def test_esc8_ces_https_epa_disabled_relayable():
    assert Find.evaluate_esc8_ces([_ep(channel_binding=False)], True)


def test_esc8_ces_https_epa_unknown_is_not_hard_finding():
    ep = [_ep(channel_binding="Unknown")]
    assert Find.evaluate_esc8_ces(ep, True) is None
    assert Find.evaluate_esc8_ces_remark(ep, True)


def test_esc8_ces_unreachable_or_not_issuing():
    assert Find.evaluate_esc8_ces([_ep(scheme="http", reachable=False)], True) is None
    assert Find.evaluate_esc8_ces([_ep(scheme="http")], False) is None


def test_check_enrollment_web_service_populates_list():
    f = _find()
    f.probe_enrollment_server = lambda uri: (True, False)  # type: ignore
    ca = LDAPEntry(
        attributes={
            "msPKI-Enrollment-Servers": [
                b"1\n2\n0\nhttps://ca/ESSOS-CA_CES_Kerberos/service.svc/CES\n0"
            ]
        }
    )
    result = f._check_enrollment_web_service(ca)
    assert len(result) == 1
    ep = result[0]
    assert set(ep) == {
        "uri",
        "auth",
        "priority",
        "renewals_only",
        "scheme",
        "reachable",
        "channel_binding",
    }
    assert ep["uri"] == "https://ca/ESSOS-CA_CES_Kerberos/service.svc/CES"
    assert ep["scheme"] == "https"
    assert ep["reachable"] is True
    assert ep["channel_binding"] is False
    assert "Kerberos" in ep["auth"]


def test_check_enrollment_web_service_absent():
    assert _find()._check_enrollment_web_service(LDAPEntry(attributes={})) == []


def test_probe_enrollment_server_malformed_uri():
    assert _find().probe_enrollment_server("http://h:abc/") == (False, None)


def test_format_enrollment_web_service():
    out = Find.format_enrollment_web_service(
        [_ep(channel_binding=False, auth=["Kerberos"])]
    )
    assert out == [
        "https://h/ca_CES_Kerberos/service.svc/CES [Kerberos] reachable=True EPA=Disabled"
    ]


def test_csv_output_includes_ces_endpoint_column():
    f = _find()
    line = "https://h/CES [Kerberos] reachable=True EPA=Disabled"
    out = f.get_ca_output_for_csv(
        {
            "Certificate Authorities": {
                0: {"CA Name": "CA", "Enrollment Web Service": [line]}
            }
        }
    )
    header, body = out.splitlines()[0], out.split("\n", 1)[1]
    assert '"CES Endpoint"' in header
    assert line in body


def test_ces_remark_emitted_alongside_web_enrollment_esc8():
    f = _find()
    f.can_user_enroll_in_ca = lambda ca: (True, [])  # type: ignore
    f.format_principals = lambda sids: []  # type: ignore
    f.ca_has_vulnerable_acl = lambda ca: (False, [])  # type: ignore
    ca = LDAPEntry(
        attributes={
            "request_disposition": "Issue",
            "web_enrollment": {
                "http": {"enabled": True},
                "https": {"enabled": False, "channel_binding": None},
            },
            "enrollment_web_service": [_ep(channel_binding="Unknown")],
        }
    )
    vulns, remarks, _, _ = f.get_ca_vulnerabilities(ca)
    assert "ESC8" in vulns
    assert "EPA couldn't be verified" in remarks["ESC8"]


CES_SERVER = b"1\n2\n0\nhttps://ca/ESSOS-CA_CES_Kerberos/service.svc/CES\n0"


def test_dc_only_lists_ces_endpoints_without_probing():
    f = _find()
    f.dc_only = True

    def boom(uri: str):
        raise AssertionError("probe must not run in dc-only mode")

    f.probe_enrollment_server = boom  # type: ignore
    ca = LDAPEntry(attributes={"msPKI-Enrollment-Servers": [CES_SERVER]})
    f._process_ca_properties([ca])
    endpoints = ca.get("enrollment_web_service")
    assert len(endpoints) == 1
    assert endpoints[0]["uri"] == "https://ca/ESSOS-CA_CES_Kerberos/service.svc/CES"
    assert endpoints[0]["scheme"] == "https"
    assert endpoints[0]["reachable"] == "Unknown"
    assert endpoints[0]["channel_binding"] == "Unknown"


def test_dc_only_ces_endpoints_are_not_a_hard_esc8():
    eps = [_ep(reachable="Unknown", channel_binding="Unknown")]
    assert Find.evaluate_esc8_ces(eps, True) is None
    eps = [_ep(scheme="http", reachable="Unknown", channel_binding="Unknown")]
    assert Find.evaluate_esc8_ces(eps, True) is None
    remark = Find.evaluate_esc8_ces_remark(eps, True)
    assert remark and "not probed" in remark


def test_check_enrollment_web_service_no_probe():
    f = _find()
    ca = LDAPEntry(attributes={"msPKI-Enrollment-Servers": [CES_SERVER]})
    result = f._check_enrollment_web_service(ca, probe=False)
    assert result[0]["reachable"] == "Unknown"


def test_ca_properties_keep_structured_ces_for_json():
    f = _find()
    ca = LDAPEntry(attributes={"enrollment_web_service": [_ep(channel_binding=False)]})
    props = f.get_ca_properties(ca)
    eps = props["Enrollment Web Service"]
    assert isinstance(eps[0], dict)
    assert eps[0]["reachable"] is True
    assert eps[0]["channel_binding"] is False
    assert eps[0]["auth"] == ["Kerberos"]


def test_text_output_formats_ces_endpoints():
    f = _find()
    ca = LDAPEntry(attributes={"enrollment_web_service": [_ep(channel_binding=False)]})
    output = {
        "Certificate Authorities": {0: f.get_ca_properties(ca)},
        "Certificate Templates": {},
    }
    text = f._format_ces_for_text(output)
    lines = text["Certificate Authorities"][0]["Enrollment Web Service"]
    assert lines == [
        "https://h/ca_CES_Kerberos/service.svc/CES [Kerberos] reachable=True EPA=Disabled"
    ]
    # the structured output is left untouched
    assert isinstance(
        output["Certificate Authorities"][0]["Enrollment Web Service"][0], dict
    )


def test_csv_output_formats_structured_ces_endpoints():
    f = _find()
    out = f.get_ca_output_for_csv(
        {
            "Certificate Authorities": {
                0: {
                    "CA Name": "CA",
                    "Enrollment Web Service": [_ep(channel_binding=False)],
                }
            }
        }
    )
    assert "reachable=True EPA=Disabled" in out


def test_format_enrollment_web_service_http_epa_not_applicable():
    out = Find.format_enrollment_web_service(
        [_ep(scheme="http", uri="http://h/ca_CES_Kerberos/service.svc/CES")]
    )
    assert out[0].endswith("reachable=True EPA=N/A")


def test_esc8_messages_join_cleanly():
    f = _find()
    f.can_user_enroll_in_ca = lambda ca: (True, [])  # type: ignore
    f.format_principals = lambda sids: []  # type: ignore
    f.ca_has_vulnerable_acl = lambda ca: (False, [])  # type: ignore
    ca = LDAPEntry(
        attributes={
            "request_disposition": "Issue",
            "web_enrollment": {
                "http": {"enabled": True},
                "https": {"enabled": False, "channel_binding": None},
            },
            "enrollment_web_service": [
                _ep(scheme="http", uri="http://h/ca_CES_Kerberos/service.svc/CES")
            ],
        }
    )
    vulns, _, _, _ = f.get_ca_vulnerabilities(ca)
    assert ".;" not in vulns["ESC8"]
    assert vulns["ESC8"].endswith(
        "Certificate Enrollment Web Service (CES) is relayable: "
        "http://h/ca_CES_Kerberos/service.svc/CES (http)."
    )
