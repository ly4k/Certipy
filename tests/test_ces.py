import base64
import unittest
from datetime import UTC, datetime, timedelta
from xml.etree import ElementTree

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from certipy.lib.ces import (
    ADDRESSING_NS,
    SECURITY_NS,
    SOAP_NS,
    CESResponseError,
    build_ces_request,
    parse_ces_response,
)


class CESTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
        now = datetime.now(UTC)
        cls.certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .sign(key, hashes.SHA256())
        )

    def test_build_ces_request(self) -> None:
        endpoint = "https://ca.test/CA_CES_Kerberos/service.svc/CES?mode=test"
        request = build_ces_request(
            endpoint,
            b"test-csr",
            "Template<&>",
            message_id="urn:uuid:test",
        )
        root = ElementTree.fromstring(request)

        self.assertEqual(
            root.findtext(f".//{{{ADDRESSING_NS}}}To"),
            endpoint,
        )
        self.assertEqual(
            root.findtext(f".//{{{SECURITY_NS}}}BinarySecurityToken"),
            base64.b64encode(b"test-csr").decode(),
        )
        self.assertIn(b"Template&lt;&amp;&gt;", request)

    def test_parse_certificate_response(self) -> None:
        certificate_der = self.certificate.public_bytes(Encoding.DER)
        response = f"""<s:Envelope xmlns:s="{SOAP_NS}" xmlns:o="{SECURITY_NS}">
<s:Body><o:BinarySecurityToken ValueType="profile#X509v3">
{base64.b64encode(certificate_der).decode()}
</o:BinarySecurityToken></s:Body></s:Envelope>""".encode()

        parsed = parse_ces_response(response)
        self.assertEqual(
            parsed.fingerprint(hashes.SHA256()),
            self.certificate.fingerprint(hashes.SHA256()),
        )

    def test_parse_fault_response(self) -> None:
        response = f"""<s:Envelope xmlns:s="{SOAP_NS}" xmlns:e="urn:test">
<s:Body><s:Fault><s:Reason><s:Text>Denied</s:Text></s:Reason>
<s:Detail><e:ErrorCode>0x80094012</e:ErrorCode><e:RequestID>7</e:RequestID></s:Detail>
</s:Fault></s:Body></s:Envelope>""".encode()

        with self.assertRaisesRegex(
            CESResponseError,
            "Denied.*0x80094012.*request ID 7",
        ):
            parse_ces_response(response)

    def test_rejects_missing_certificate(self) -> None:
        response = f'<s:Envelope xmlns:s="{SOAP_NS}" />'.encode()
        with self.assertRaisesRegex(CESResponseError, "did not contain"):
            parse_ces_response(response)


if __name__ == "__main__":
    unittest.main()
