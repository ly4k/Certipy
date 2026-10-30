import hashlib
from typing import Callable, Union

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from certipy.lib.channel_binding import get_channel_binding_data


def _expected(cert_der: bytes, hash_name: str) -> bytes:
    app_data = b"tls-server-end-point:" + hashlib.new(hash_name, cert_der).digest()
    structure = b"\x00" * 16 + len(app_data).to_bytes(4, "little") + app_data
    return hashlib.md5(structure).digest()


@pytest.mark.parametrize(
    ("signature_hash", "binding_hash"),
    [
        (hashes.SHA256(), "sha256"),
        (hashes.SHA384(), "sha384"),
        (hashes.SHA512(), "sha512"),
    ],
)
def test_binding_hash_follows_rfc5929(
    make_cert: Callable[..., x509.Certificate],
    signature_hash: Union[hashes.SHA256, hashes.SHA384, hashes.SHA512],
    binding_hash: str,
):
    cert_der = make_cert(hash_algorithm=signature_hash).public_bytes(Encoding.DER)
    assert get_channel_binding_data(cert_der) == _expected(cert_der, binding_hash)


def test_binding_is_16_byte_md5(make_cert: Callable[..., x509.Certificate]):
    cert_der = make_cert().public_bytes(Encoding.DER)
    assert len(get_channel_binding_data(cert_der)) == 16


# DER OID TLVs for sha256WithRSAEncryption and sha1WithRSAEncryption.
SHA256_RSA_OID = bytes.fromhex("06092a864886f70d01010b")
SHA1_RSA_OID = bytes.fromhex("06092a864886f70d010105")


def test_sha1_signature_binds_with_sha256(make_cert: Callable[..., x509.Certificate]):
    # cryptography refuses to sign with SHA-1, so relabel a SHA-256 cert.
    # The signature no longer verifies, but binding only reads the algorithm.
    cert_der = make_cert().public_bytes(Encoding.DER)
    assert cert_der.count(SHA256_RSA_OID) == 2
    sha1_der = cert_der.replace(SHA256_RSA_OID, SHA1_RSA_OID)
    hash_algorithm = x509.load_der_x509_certificate(sha1_der).signature_hash_algorithm
    assert isinstance(hash_algorithm, hashes.SHA1)
    assert get_channel_binding_data(sha1_der) == _expected(sha1_der, "sha256")
