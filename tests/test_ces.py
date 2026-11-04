import base64
import datetime
from xml.etree import ElementTree

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from certipy.lib.ces import (
    ADDR_NS,
    AUTHZ_NS,
    ENCODING_TYPE_BASE64,
    ENROLL_NS,
    MAX_RESPONSE_SIZE,
    REQUEST_TYPE_ISSUE,
    SOAP_NS,
    TOKEN_TYPE_X509V3,
    VALUE_TYPE_PKCS10,
    WSS_NS,
    WST_NS,
    WSTEP_ACTION,
    CESError,
    EnrollmentServer,
    build_wstep_request,
    decode_enrollment_auth,
    default_ces_path,
    parse_enrollment_servers,
    parse_wstep_response,
)

CES_URL = "https://braavos.essos.local/ESSOS-CA_CES_Kerberos/service.svc/CES"
CSR = b"\x30\x03\x02\x01\x00"


def _context_items(root: ElementTree.Element) -> list[tuple[str | None, str | None]]:
    items = root.findall(f".//{{{AUTHZ_NS}}}ContextItem")
    return [(i.get("Name"), i.findtext(f"{{{AUTHZ_NS}}}Value")) for i in items]


def test_default_ces_path():
    assert default_ces_path("ESSOS-CA") == "/ESSOS-CA_CES_Kerberos/service.svc/CES"


def test_default_ces_path_escapes_slash():
    assert default_ces_path("A/B") == "/A%2FB_CES_Kerberos/service.svc/CES"


def test_default_ces_path_quotes_ca_name():
    assert default_ces_path("My CA") == "/My%20CA_CES_Kerberos/service.svc/CES"


def test_build_wstep_request_headers():
    root = ElementTree.fromstring(
        build_wstep_request(
            CES_URL, CSR, ["CertificateTemplate:User"], message_id="urn:uuid:1"
        )
    )
    header = root.find(f"{{{SOAP_NS}}}Header")
    assert header is not None
    assert header.findtext(f"{{{ADDR_NS}}}Action") == WSTEP_ACTION
    assert header.findtext(f"{{{ADDR_NS}}}MessageID") == "urn:uuid:1"
    assert header.findtext(f"{{{ADDR_NS}}}To") == CES_URL


def test_build_wstep_request_body():
    root = ElementTree.fromstring(
        build_wstep_request(CES_URL, CSR, ["CertificateTemplate:User"])
    )
    rst = root.find(f"{{{SOAP_NS}}}Body/{{{WST_NS}}}RequestSecurityToken")
    assert rst is not None
    assert rst.findtext(f"{{{WST_NS}}}TokenType") == TOKEN_TYPE_X509V3
    assert rst.findtext(f"{{{WST_NS}}}RequestType") == REQUEST_TYPE_ISSUE
    token = rst.find(f"{{{WSS_NS}}}BinarySecurityToken")
    assert token is not None
    assert token.get("ValueType") == VALUE_TYPE_PKCS10
    assert token.get("EncodingType") == ENCODING_TYPE_BASE64
    assert base64.b64decode(token.text or "") == CSR


def test_build_wstep_request_generates_message_id():
    root = ElementTree.fromstring(
        build_wstep_request(CES_URL, CSR, ["CertificateTemplate:User"])
    )
    message_id = root.findtext(f".//{{{ADDR_NS}}}MessageID") or ""
    assert message_id.startswith("urn:uuid:")


def test_build_wstep_request_context_items():
    root = ElementTree.fromstring(
        build_wstep_request(
            CES_URL,
            CSR,
            [
                "CertificateTemplate:User",
                "SAN:upn=administrator@essos.local&dns=braavos.essos.local",
            ],
        )
    )
    assert _context_items(root) == [
        ("CertificateTemplate", "User"),
        ("SAN", "upn=administrator@essos.local&dns=braavos.essos.local"),
    ]


def test_build_wstep_request_escapes_values():
    root = ElementTree.fromstring(
        build_wstep_request(CES_URL + "?a=1&b=2", CSR, ['Certificate"Template:<A&B>'])
    )
    assert root.findtext(f".//{{{ADDR_NS}}}To") == CES_URL + "?a=1&b=2"
    assert _context_items(root) == [('Certificate"Template', "<A&B>")]


def test_build_wstep_request_rejects_malformed_attribute():
    with pytest.raises(ValueError):
        build_wstep_request(CES_URL, CSR, ["NoColonHere"])


def _self_signed_der() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ces-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _chain() -> tuple[x509.Certificate, x509.Certificate]:
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ces-test-ca")])
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ces-test-leaf")])

    def build(
        subject: x509.Name, issuer: x509.Name, pub: rsa.RSAPublicKey, serial: int
    ) -> x509.Certificate:
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(pub)
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(ca_key, hashes.SHA256())
        )

    return (
        build(ca_name, ca_name, ca_key.public_key(), 1),
        build(leaf_name, ca_name, leaf_key.public_key(), 2),
    )


def _rstr(
    cert_token: str = "", request_id: str = "17", disposition: str = "Issued"
) -> bytes:
    issued = (
        f"<RequestedSecurityToken><BinarySecurityToken "
        f'ValueType="{TOKEN_TYPE_X509V3}" EncodingType="{ENCODING_TYPE_BASE64}" '
        f'xmlns="{WSS_NS}">{cert_token}</BinarySecurityToken></RequestedSecurityToken>'
        if cert_token
        else ""
    )
    return (
        f'<s:Envelope xmlns:s="{SOAP_NS}" xmlns:a="{ADDR_NS}"><s:Body>'
        f'<RequestSecurityTokenResponseCollection xmlns="{WST_NS}">'
        "<RequestSecurityTokenResponse>"
        f"<TokenType>{TOKEN_TYPE_X509V3}</TokenType>"
        f'<DispositionMessage xml:lang="en-US" xmlns="{ENROLL_NS}">{disposition}</DispositionMessage>'
        f'<BinarySecurityToken ValueType="{ENROLL_NS}#PKCS7" '
        f'EncodingType="{ENCODING_TYPE_BASE64}" xmlns="{WSS_NS}">MIIB</BinarySecurityToken>'
        f"{issued}"
        f'<RequestID xmlns="{ENROLL_NS}">{request_id}</RequestID>'
        "</RequestSecurityTokenResponse>"
        "</RequestSecurityTokenResponseCollection>"
        "</s:Body></s:Envelope>"
    ).encode()


def _fault(reason: str, error_code: str | None, request_id: str | None) -> bytes:
    detail = ""
    if error_code is not None or request_id is not None:
        detail = f'<s:Detail><CertificateEnrollmentWSDetail xmlns="{ENROLL_NS}">'
        if error_code is not None:
            detail += f"<ErrorCode>{error_code}</ErrorCode>"
        if request_id is not None:
            detail += f"<RequestID>{request_id}</RequestID>"
        detail += "</CertificateEnrollmentWSDetail></s:Detail>"
    return (
        f'<s:Envelope xmlns:s="{SOAP_NS}"><s:Body><s:Fault>'
        "<s:Code><s:Value>s:Receiver</s:Value></s:Code>"
        f'<s:Reason><s:Text xml:lang="en-US">{reason}</s:Text></s:Reason>'
        f"{detail}</s:Fault></s:Body></s:Envelope>"
    ).encode()


def test_parse_issued_certificate():
    der = _self_signed_der()
    b64 = base64.b64encode(der).decode()
    # CES wraps base64 across lines; whitespace must be ignored
    wrapped = "\r\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    response = parse_wstep_response(_rstr(cert_token=wrapped, request_id="17"))
    assert response.certificate is not None
    assert response.certificate.public_bytes(serialization.Encoding.DER) == der
    assert response.request_id == 17
    assert response.disposition_message == "Issued"


def test_parse_pkcs7_issuance_returns_leaf():
    ca_cert, leaf_cert = _chain()
    # CA listed first so that picking the first cert would be wrong
    bundle = pkcs7.serialize_certificates(
        [ca_cert, leaf_cert], serialization.Encoding.DER
    )
    response = parse_wstep_response(_rstr(cert_token=base64.b64encode(bundle).decode()))
    assert response.certificate is not None
    assert response.certificate.subject == leaf_cert.subject


def test_parse_prefers_requested_security_token():
    stray = base64.b64encode(_self_signed_der()).decode()
    wanted_der = _self_signed_der()
    stray_token = (
        f'<BinarySecurityToken ValueType="{TOKEN_TYPE_X509V3}" '
        f'EncodingType="{ENCODING_TYPE_BASE64}" xmlns="{WSS_NS}">{stray}'
        "</BinarySecurityToken>"
    ).encode()
    body = _rstr(cert_token=base64.b64encode(wanted_der).decode()).replace(
        b"<RequestSecurityTokenResponse>",
        b"<RequestSecurityTokenResponse>" + stray_token,
        1,
    )
    # a stray token after it must not win either
    body = body.replace(
        b"</RequestSecurityTokenResponse>",
        stray_token + b"</RequestSecurityTokenResponse>",
        1,
    )
    response = parse_wstep_response(body)
    assert response.certificate is not None
    assert response.certificate.public_bytes(serialization.Encoding.DER) == wanted_der


def test_parse_pending():
    response = parse_wstep_response(
        _rstr(request_id="19", disposition="Taken Under Submission")
    )
    assert response.certificate is None
    assert response.request_id == 19
    assert response.disposition_message == "Taken Under Submission"


def test_parse_fault_with_detail():
    # 0x80094012 CERTSRV_E_TEMPLATE_DENIED, sent as a signed decimal
    with pytest.raises(CESError) as excinfo:
        parse_wstep_response(_fault("Denied by Policy Module", "-2146877422", "18"))
    assert str(excinfo.value) == "Denied by Policy Module"
    assert excinfo.value.error_code == 0x80094012
    assert excinfo.value.request_id == 18


def test_parse_fault_without_detail():
    with pytest.raises(CESError) as excinfo:
        parse_wstep_response(_fault("Access is denied.", None, None))
    assert str(excinfo.value) == "Access is denied."
    assert excinfo.value.error_code is None
    assert excinfo.value.request_id is None


def test_parse_invalid_certificate_token():
    with pytest.raises(CESError):
        parse_wstep_response(_rstr(cert_token="bm90IGEgY2VydA=="))


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"<not-xml",
        b"x" * (MAX_RESPONSE_SIZE + 1),
        b'<?xml version="1.0" encoding="bogus-enc"?><a/>',
    ],
    ids=["empty", "malformed", "oversized", "unknown-encoding"],
)
def test_parse_rejects_bad_bodies(data: bytes):
    with pytest.raises(CESError):
        parse_wstep_response(data)


GOAD_VALUE = (
    "1\n2\n0\nhttps://braavos.essos.local/ESSOS-CA_CES_Kerberos/service.svc/CES\n0"
)


def test_decode_enrollment_auth_single():
    assert decode_enrollment_auth(2) == ["Kerberos"]


def test_decode_enrollment_auth_combined():
    assert decode_enrollment_auth(2 | 4) == ["Kerberos", "UsernameAndPassword"]


def test_decode_enrollment_auth_unknown_bit():
    assert decode_enrollment_auth(2 | 16) == ["Kerberos", "Unknown(0x10)"]


def test_parse_enrollment_servers_goad():
    servers = parse_enrollment_servers([GOAD_VALUE])
    assert servers == [
        EnrollmentServer(
            priority=1,
            authentication=2,
            auth_names=["Kerberos"],
            renewals_only=False,
            uri="https://braavos.essos.local/ESSOS-CA_CES_Kerberos/service.svc/CES",
            key_based_renewal=False,
        )
    ]


def test_parse_enrollment_servers_sorts_by_priority_and_skips_malformed():
    high = "10\n2\n0\nhttps://a/ca_CES_Kerberos/service.svc/CES\n0"
    low = "1\n4\n1\nhttps://b/ca_CES_UsernamePassword/service.svc/CES\n0"
    servers = parse_enrollment_servers([high, low, "garbage", "", "1\n2"])
    assert [s.uri for s in servers] == [
        "https://b/ca_CES_UsernamePassword/service.svc/CES",
        "https://a/ca_CES_Kerberos/service.svc/CES",
    ]
    assert servers[0].auth_names == ["UsernameAndPassword"]
    assert servers[0].renewals_only is True


def test_parse_enrollment_servers_empty():
    assert parse_enrollment_servers([]) == []
    assert parse_enrollment_servers(None) == []
