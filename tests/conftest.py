import datetime
from pathlib import Path
from typing import Any, Callable, Iterator, Optional, Union

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from certipy.lib.certificate import (
    NTDS_CA_SECURITY_EXT,
    NTDS_OBJECTSID,
    PRINCIPAL_NAME,
    SAN_URL_PREFIX,
)
from certipy.lib.ldap import LDAPEntry


def _der(tag: int, content: bytes) -> bytes:
    """Encode one DER TLV. Supports content up to 65535 bytes."""
    length = len(content)
    if length < 0x80:
        return bytes([tag, length]) + content
    if length < 0x100:
        return bytes([tag, 0x81, length]) + content
    return bytes([tag, 0x82]) + length.to_bytes(2, "big") + content


def _der_oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    body = bytes([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.insert(0, 0x80 | (arc & 0x7F))
            arc >>= 7
        body += bytes(chunk)
    return _der(0x06, body)


def encode_upn(upn: str) -> bytes:
    """DER UTF8String value for a UPN OtherName."""
    return _der(0x0C, upn.encode())


def encode_sid_extension(sid: str) -> bytes:
    """
    DER value of the szOID_NTDS_CA_SECURITY_EXT extension:
    SEQUENCE { [0] { OID szOID_NTDS_OBJECTSID, [0] { OCTET STRING sid } } }
    """
    inner = _der_oid(NTDS_OBJECTSID.dotted_string) + _der(
        0xA0, _der(0x04, sid.encode())
    )
    return _der(0x30, _der(0xA0, inner))


@pytest.fixture(scope="session")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


CertFactory = Callable[..., x509.Certificate]
SigningHash = Union[hashes.SHA256, hashes.SHA384, hashes.SHA512]


@pytest.fixture(scope="session")
def make_cert(rsa_key: rsa.RSAPrivateKey) -> CertFactory:
    def factory(
        subject_cn: str = "test",
        key: Optional[rsa.RSAPrivateKey] = None,
        issuer: Optional[x509.Certificate] = None,
        issuer_key: Optional[rsa.RSAPrivateKey] = None,
        san_upn: Optional[str] = None,
        san_dns: Optional[str] = None,
        san_url_sid: Optional[str] = None,
        sid: Optional[str] = None,
        ca: bool = False,
        hash_algorithm: Optional[SigningHash] = None,
    ) -> x509.Certificate:
        key = key or rsa_key
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer.subject if issuer else subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(
                x509.BasicConstraints(ca=ca, path_length=None), critical=True
            )
        )
        names: list[x509.GeneralName] = []
        if san_upn is not None:
            names.append(x509.OtherName(PRINCIPAL_NAME, encode_upn(san_upn)))
        if san_dns is not None:
            names.append(x509.DNSName(san_dns))
        if san_url_sid is not None:
            names.append(x509.UniformResourceIdentifier(SAN_URL_PREFIX + san_url_sid))
        if names:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(names), critical=False
            )
        if sid is not None:
            builder = builder.add_extension(
                x509.UnrecognizedExtension(
                    NTDS_CA_SECURITY_EXT, encode_sid_extension(sid)
                ),
                critical=False,
            )
        return builder.sign(issuer_key or key, hash_algorithm or hashes.SHA256())

    return factory


@pytest.fixture(scope="session")
def ca_chain(
    make_cert: CertFactory,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey, x509.Certificate, rsa.RSAPrivateKey]:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_cert = make_cert(subject_cn="Test CA", key=ca_key, ca=True)
    leaf_cert = make_cert(
        subject_cn="leaf", key=leaf_key, issuer=ca_cert, issuer_key=ca_key
    )
    return ca_cert, ca_key, leaf_cert, leaf_key


Handler = Callable[[httpx.Request], httpx.Response]


@pytest.fixture
def mock_http() -> Iterator[Callable[..., httpx.Client]]:
    clients: list[httpx.Client] = []

    def factory(handler: Handler, **client_kwargs: Any) -> httpx.Client:
        client = httpx.Client(transport=httpx.MockTransport(handler), **client_kwargs)
        clients.append(client)
        return client

    yield factory
    for client in clients:
        client.close()


@pytest.fixture
def make_ldap_entry() -> Callable[..., LDAPEntry]:
    def factory(
        attributes: Optional[dict[str, Any]] = None,
        raw_attributes: Optional[dict[str, Any]] = None,
        dn: str = "CN=test,DC=corp,DC=local",
    ) -> LDAPEntry:
        return LDAPEntry(
            dn=dn,
            attributes=dict(attributes or {}),
            raw_attributes=dict(raw_attributes or {}),
        )

    return factory


@pytest.fixture
def tmp_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    return tmp_path
