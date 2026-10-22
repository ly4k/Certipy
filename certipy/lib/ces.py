"""Microsoft Certificate Enrollment Services (CES/WSTEP) helpers."""

import base64
import binascii
import re
import uuid
from html import escape
from typing import Optional
from xml.etree import ElementTree

from cryptography import x509

SOAP_NS = "http://www.w3.org/2003/05/soap-envelope"
ADDRESSING_NS = "http://www.w3.org/2005/08/addressing"
TRUST_NS = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
SECURITY_NS = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-wssecurity-secext-1.0.xsd"
)
UTILITY_NS = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-wssecurity-utility-1.0.xsd"
)
AUTHORIZATION_NS = "http://schemas.xmlsoap.org/ws/2006/12/authorization"
ENROLLMENT_NS = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment"

ACTION = f"{ENROLLMENT_NS}/RST/wstep"
TOKEN_TYPE_X509V3 = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-x509-token-profile-1.0#X509v3"
)
REQUEST_TYPE_ISSUE = f"{TRUST_NS}/Issue"
VALUE_TYPE_PKCS10 = f"{ENROLLMENT_NS}#PKCS10"
ENCODING_BASE64 = f"{SECURITY_NS}#base64binary"
MAX_RESPONSE_SIZE = 10 * 1024 * 1024

_WHITESPACE_RE = re.compile(r"\s+")


class CESResponseError(RuntimeError):
    """Raised when a CES endpoint returns an invalid response or SOAP fault."""


def build_ces_request(
    endpoint: str,
    csr: bytes,
    template: str,
    message_id: Optional[str] = None,
) -> bytes:
    """Build a CES/WSTEP RequestSecurityToken containing a DER PKCS#10 CSR."""
    if not endpoint:
        raise ValueError("CES endpoint is required")
    if not csr:
        raise ValueError("CSR data is required")
    if not template:
        raise ValueError("Certificate template is required")

    csr_b64 = base64.b64encode(csr).decode("ascii")
    request_id = message_id or f"urn:uuid:{uuid.uuid4()}"
    context = (
        f'<AdditionalContext xmlns="{AUTHORIZATION_NS}">'
        '<ContextItem Name="CertificateTemplate">'
        f"<Value>{escape(template, quote=True)}</Value>"
        "</ContextItem></AdditionalContext>"
    )

    request = f"""<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:a="{ADDRESSING_NS}" xmlns:s="{SOAP_NS}">
  <s:Header>
    <a:Action s:mustUnderstand="1">{escape(ACTION)}</a:Action>
    <a:MessageID>{escape(request_id)}</a:MessageID>
    <a:To s:mustUnderstand="1">{escape(endpoint)}</a:To>
  </s:Header>
  <s:Body>
    <RequestSecurityToken PreferredLanguage="en-US" xmlns="{TRUST_NS}">
      <TokenType>{escape(TOKEN_TYPE_X509V3)}</TokenType>
      <RequestType>{escape(REQUEST_TYPE_ISSUE)}</RequestType>
      <BinarySecurityToken ValueType="{escape(VALUE_TYPE_PKCS10)}" EncodingType="{escape(ENCODING_BASE64)}" a:Id="" xmlns:a="{UTILITY_NS}" xmlns="{SECURITY_NS}">{csr_b64}</BinarySecurityToken>
      {context}
    </RequestSecurityToken>
  </s:Body>
</s:Envelope>
"""
    return request.encode("utf-8")


def parse_ces_response(response: bytes) -> x509.Certificate:
    """Extract and validate the issued X.509 certificate from a CES response."""
    if not response:
        raise CESResponseError("CES returned an empty response")
    if len(response) > MAX_RESPONSE_SIZE:
        raise CESResponseError(
            f"CES response exceeds the {MAX_RESPONSE_SIZE}-byte limit"
        )

    try:
        root = ElementTree.fromstring(response)
    except ElementTree.ParseError as e:
        raise CESResponseError(f"CES returned malformed XML: {e}") from e

    fault = root.find(f".//{{{SOAP_NS}}}Fault")
    if fault is not None:
        reason = fault.find(f".//{{{SOAP_NS}}}Text")
        reason_text = (
            (reason.text or "").strip() if reason is not None else "unspecified fault"
        )
        error_code = _find_local_text(fault, "ErrorCode")
        request_id = _find_local_text(fault, "RequestID")
        details = []
        if error_code:
            details.append(f"error code {error_code}")
        if request_id:
            details.append(f"request ID {request_id}")
        suffix = f" ({', '.join(details)})" if details else ""
        raise CESResponseError(f"CES SOAP fault: {reason_text}{suffix}")

    certificate_tokens = []
    for node in root.findall(f".//{{{SECURITY_NS}}}BinarySecurityToken"):
        if "X509v3" not in node.attrib.get("ValueType", ""):
            continue
        token = _WHITESPACE_RE.sub("", node.text or "")
        if token:
            certificate_tokens.append(token)

    if not certificate_tokens:
        raise CESResponseError("CES response did not contain an X509v3 certificate")

    try:
        certificate_der = base64.b64decode(certificate_tokens[-1], validate=True)
        return x509.load_der_x509_certificate(certificate_der)
    except (binascii.Error, ValueError) as e:
        raise CESResponseError("CES returned an invalid X509v3 certificate") from e


def _find_local_text(element: ElementTree.Element, local_name: str) -> Optional[str]:
    for node in element.iter():
        if node.tag.rsplit("}", 1)[-1] == local_name and node.text:
            return node.text.strip()
    return None
