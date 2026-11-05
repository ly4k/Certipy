"""Regression tests for issue #372: empty relayed username breaks relay.

Some relayed NTLM AUTHENTICATE messages (e.g. PetitPotam-coerced machine
authentications) carry an empty ``user_name``/``domain_name``. Certipy used to
crash while building the CSR subject with:

    ValueError: Attribute's length must be >= 1 and <= 64, but it was 0

The relay must instead generate the CSR with an empty subject (RFC 2986 allows
an empty subject; templates such as DomainController fill the subject in on the
CA side), submit the request, and save the issued certificate - matching the
behavior of impacket's ``ntlmrelayx --adcs`` in the same environment.
"""

import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional, Union

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography.x509.oid import NameOID

from certipy.commands.relay import ADCSHTTPAttackClient
from certipy.lib.certificate import create_csr
from certipy.lib.req import _determine_output_filename


def make_csr(
    username: str, subject: Optional[str] = None
) -> x509.CertificateSigningRequest:
    """Build a CSR the way the relay does: no subject DN, no SAN, no policies."""
    csr, _key = create_csr(
        username,
        alt_dns=None,
        alt_upn=None,
        alt_sid=None,
        subject=subject,
        key_size=2048,
        application_policies=None,
        smime=None,
    )
    return csr


class TestCreateCsrEmptyRelayedUsername:
    """create_csr() must handle the empty relayed username case (issue #372)."""

    @pytest.mark.parametrize("username", ["", "   "])
    def test_empty_username_generates_csr_with_empty_subject(
        self, username: str
    ) -> None:
        # Regression: this raised ValueError before the fix (first from
        # cryptography's x509.NameAttribute, later re-raised explicitly).
        csr = make_csr(username)

        assert isinstance(csr, x509.CertificateSigningRequest)
        assert list(csr.subject.rdns) == []

    def test_empty_username_with_explicit_subject_uses_subject(self) -> None:
        csr = make_csr("", subject="CN=explicit.example.com")

        assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == (
            "explicit.example.com"
        )

    def test_normal_username_still_sets_common_name(self) -> None:
        csr = make_csr("bbrown")

        assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == (
            "bbrown".capitalize()
        )

    def test_truly_invalid_common_name_is_still_rejected(self) -> None:
        # 65 chars exceeds ub-common-name (RFC 5280) - must stay an error.
        with pytest.raises(ValueError):
            make_csr("x" * 65)

    def test_name_attribute_errors_are_surfaced(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Name validation errors from the underlying cryptography library
        # must propagate instead of being silently swallowed.
        def failing_name_attribute(
            oid: object, value: object, **kwargs: object
        ) -> None:
            raise ValueError("Attribute's length must be >= 1 and <= 64")

        monkeypatch.setattr(x509, "NameAttribute", failing_name_attribute)
        with pytest.raises(ValueError, match="invalid common name"):
            make_csr("bbrown")


class TestOutputFilenameFallback:
    """PFX naming must not produce an empty name for an empty identity."""

    def test_empty_username_falls_back_to_certificate(self) -> None:
        assert _determine_output_filename(None, [], "") == "certificate"

    def test_separator_only_username_falls_back_to_certificate(self) -> None:
        # The relay passes "DOMAIN\\user"; both parts empty gives "\\".
        assert _determine_output_filename(None, [], "\\") == "certificate"

    def test_normal_username_is_kept(self) -> None:
        assert _determine_output_filename(None, [], "Bbrown") == "bbrown"

    def test_certificate_identity_preferred(self) -> None:
        identities = [("DNS Host Name", "dc01.shadow.gate")]
        assert _determine_output_filename(None, identities, "") == "dc01"


class FakeResponse:
    def __init__(
        self,
        status_code: int = 200,
        text: str = "",
        content: bytes = b"",
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.status_code = status_code
        self.text = text
        self.content = content
        self.headers = headers if headers is not None else {}


class FakeSession:
    """Minimal stand-in for the httpx session used by the relay client."""

    def __init__(
        self,
        user: str,
        post_response: FakeResponse,
        get_response: Union[FakeResponse, Callable[[], FakeResponse]],
    ) -> None:
        self.user = user
        self.timeout = SimpleNamespace(read=5)
        self._post_response = post_response
        self._get_response = get_response
        self.posts: List[Dict[str, Any]] = []
        self.gets: List[Dict[str, Any]] = []

    def post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> FakeResponse:
        self.posts.append({"url": url, "data": data})
        return self._post_response

    def get(self, url: str, params: Optional[Dict[str, Any]] = None) -> FakeResponse:
        self.gets.append({"url": url, "params": params})
        response = self._get_response
        if callable(response):
            response = response()
        return response


def make_issued_certificate(public_key: CertificatePublicKeyTypes) -> bytes:
    """Cert shaped like a DomainController-issued certificate.

    Like a real CA, it embeds the CSR's public key so the certificate matches
    the private key generated during the attack.
    """
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DC01.shadow.gate")])
        )
        .issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "shadow-DC01-CA")])
        )
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("DC01.shadow.gate")]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def make_relay_stub() -> SimpleNamespace:
    return SimpleNamespace(
        attack_lock=threading.Lock(),
        no_skip=False,
        enum_templates=False,
        request_id=None,
        subject=None,
        alt_dns=None,
        alt_upn=None,
        alt_sid=None,
        key_size=2048,
        application_policies=None,
        smime=None,
        archive_key=None,
        out=None,
        pfx_password=None,
        attacked_targets=[],
        forever=True,
        shutdown=lambda: None,
    )


class TestRelayAttackEmptyRelayedUsername:
    """End-to-end relay path with the identity from the issue ("domain/user" = "/")."""

    def test_relay_requests_and_saves_certificate(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig

        monkeypatch.chdir(tmp_path)

        def issued_cert_response() -> FakeResponse:
            # A real CA signs the CSR's public key
            csr_pem = session.posts[0]["data"]["CertRequest"]
            csr = x509.load_pem_x509_csr(csr_pem.encode())
            return FakeResponse(content=make_issued_certificate(csr.public_key()))

        session = FakeSession(
            user="\\",  # set by the relay from an empty domain/user
            post_response=FakeResponse(
                text='<a href="certnew.cer?ReqID=4&">download</a>'
            ),
            get_response=issued_cert_response,
        )
        config = NTLMRelayxConfig()
        config.setADCSOptions("DomainController")

        # "/" is exactly what impacket's getUserString() yields for the
        # empty user/domain NTLM response seen in the issue.
        attack = ADCSHTTPAttackClient(
            make_relay_stub(),  # type: ignore[arg-type]
            config,
            session,
            "/",
        )
        attack.run()

        # The CSR must have been submitted instead of crashing
        assert len(session.posts) == 1
        assert session.posts[0]["url"] == "/certsrv/certfnsh.asp"
        csr_pem = session.posts[0]["data"]["CertRequest"]
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        assert list(csr.subject.rdns) == []

        # The issued certificate must have been downloaded and saved as PFX,
        # named after the certificate identity (like ntlmrelayx does).
        assert session.gets and session.gets[0]["params"] == {"ReqID": 4}
        saved = list(tmp_path.glob("*.pfx"))
        assert [p.name for p in saved] == ["dc01.pfx"]
