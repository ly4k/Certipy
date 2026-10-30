import struct
from typing import Callable, Optional

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from certipy.lib.certificate import (
    cert_id_to_parts,
    cert_to_der,
    cert_to_pem,
    create_pfx,
    der_to_cert,
    der_to_key,
    der_to_pem,
    get_identities_from_certificate,
    get_object_sid_from_certificate,
    get_object_sid_from_certificate_san_url,
    get_object_sid_from_certificate_sid_extension,
    hash_digest,
    key_to_der,
    key_to_pem,
    load_pfx,
    pem_to_cert,
    pem_to_key,
    private_key_to_ms_blob,
    rsa_pkcs1v15_sign,
)

SID = "S-1-5-21-1111-2222-3333-1104"


def test_cert_der_round_trip(make_cert: Callable[..., x509.Certificate]):
    cert = make_cert()
    assert der_to_cert(cert_to_der(cert)) == cert


def test_cert_pem_round_trip(make_cert: Callable[..., x509.Certificate]):
    cert = make_cert()
    assert pem_to_cert(cert_to_pem(cert)) == cert


@pytest.mark.parametrize(
    ("encode", "decode"), [(key_to_der, der_to_key), (key_to_pem, pem_to_key)]
)
def test_key_round_trip(
    rsa_key: rsa.RSAPrivateKey,
    encode: Callable[[rsa.RSAPrivateKey], bytes],
    decode: Callable[[bytes], PrivateKeyTypes],
):
    key = decode(encode(rsa_key))
    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.private_numbers() == rsa_key.private_numbers()


def test_der_to_pem_wraps_at_64_columns():
    pem = der_to_pem(b"\x00" * 100, "certificate")
    lines = pem.splitlines()
    assert lines[0] == "-----BEGIN CERTIFICATE-----"
    assert lines[-1] == "-----END CERTIFICATE-----"
    body = lines[1:-1]
    assert all(len(line) == 64 for line in body[:-1])
    assert 0 < len(body[-1]) <= 64


@pytest.mark.parametrize("password", [None, "Passw0rd!"])
def test_pfx_round_trip(
    make_cert: Callable[..., x509.Certificate],
    rsa_key: rsa.RSAPrivateKey,
    password: Optional[str],
):
    cert = make_cert()
    pfx = create_pfx(rsa_key, cert, password)
    key, loaded = load_pfx(pfx, password.encode() if password else None)
    assert loaded == cert
    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.private_numbers() == rsa_key.private_numbers()


def test_load_pfx_wrong_password_raises(
    make_cert: Callable[..., x509.Certificate], rsa_key: rsa.RSAPrivateKey
):
    pfx = create_pfx(rsa_key, make_cert(), "right")
    with pytest.raises(ValueError):
        load_pfx(pfx, b"wrong")


def test_identities_from_upn_and_dns(make_cert: Callable[..., x509.Certificate]):
    cert = make_cert(san_upn="administrator@corp.local", san_dns="dc01.corp.local")
    assert get_identities_from_certificate(cert) == [
        ("UPN", "administrator@corp.local"),
        ("DNS Host Name", "dc01.corp.local"),
    ]


def test_identities_empty_without_san(make_cert: Callable[..., x509.Certificate]):
    assert get_identities_from_certificate(make_cert()) == []


@pytest.mark.parametrize(
    ("identities", "expected"),
    [
        ([], (None, None)),
        ([("UPN", "administrator@corp.local")], ("administrator", "corp.local")),
        ([("UPN", "a@b@corp.local")], ("a@b", "corp.local")),
        ([("UPN", "administrator")], ("administrator", "")),
        ([("DNS Host Name", "dc01.corp.local")], ("dc01$", "corp.local")),
        ([("DNS Host Name", "dc01")], ("dc01", "")),
        (
            [("UPN", "a@corp.local"), ("DNS Host Name", "dc01.corp.local")],
            ("a_dc01$", "corp.local_corp.local"),
        ),
        ([("Email", "a@corp.local"), (None, None)], ("", "")),
    ],
)
def test_cert_id_to_parts(
    identities: list[tuple[Optional[str], Optional[str]]],
    expected: tuple[Optional[str], Optional[str]],
):
    assert cert_id_to_parts(identities) == expected


def test_sid_from_sid_extension(make_cert: Callable[..., x509.Certificate]):
    cert = make_cert(sid=SID)
    assert get_object_sid_from_certificate_sid_extension(cert) == SID


def test_sid_from_san_url(make_cert: Callable[..., x509.Certificate]):
    cert = make_cert(san_url_sid=SID)
    assert get_object_sid_from_certificate_san_url(cert) == SID


def test_sid_absent_returns_none(make_cert: Callable[..., x509.Certificate]):
    cert = make_cert(san_upn="a@corp.local")
    assert get_object_sid_from_certificate(cert) is None


def test_sid_prefers_extension_over_san_url(make_cert: Callable[..., x509.Certificate]):
    cert = make_cert(sid=SID, san_url_sid="S-1-5-21-9-9-9-500")
    assert get_object_sid_from_certificate(cert) == SID


def test_sid_falls_back_to_san_url(make_cert: Callable[..., x509.Certificate]):
    assert get_object_sid_from_certificate(make_cert(san_url_sid=SID)) == SID


def test_ms_blob_header_and_length(rsa_key: rsa.RSAPrivateKey):
    blob = private_key_to_ms_blob(rsa_key)
    blob_type, version, _, alg_id, magic, bitlen, exponent = struct.unpack(
        "<bbHI4sII", blob[:20]
    )
    assert (blob_type, version, alg_id, magic) == (7, 2, 41984, b"RSA2")
    assert bitlen == 2048
    assert exponent == 65537
    # header + n + p + q + dp + dq + qinv + d
    assert len(blob) == 20 + 256 + 5 * 128 + 256


def test_rsa_pkcs1v15_sign_verifies(rsa_key: rsa.RSAPrivateKey):
    signature = rsa_pkcs1v15_sign(b"data", rsa_key)
    rsa_key.public_key().verify(signature, b"data", padding.PKCS1v15(), hashes.SHA256())


def test_rsa_pkcs1v15_sign_rejects_non_rsa_key():
    with pytest.raises(TypeError):
        rsa_pkcs1v15_sign(b"data", ec.generate_private_key(ec.SECP256R1()))


def test_hash_digest_sha256():
    digest = hash_digest(b"abc", hashes.SHA256)
    assert digest.hex().startswith("ba7816bf")
