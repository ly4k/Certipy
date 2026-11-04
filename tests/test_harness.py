import os
from pathlib import Path
from typing import Callable

import httpx
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from certipy.lib.certificate import get_object_sid_from_certificate_sid_extension
from certipy.lib.ldap import LDAPEntry


def test_rsa_key_is_2048(rsa_key: rsa.RSAPrivateKey):
    assert rsa_key.key_size == 2048


def test_make_cert_self_signed(make_cert: Callable[..., x509.Certificate]):
    cert = make_cert(subject_cn="alice")
    assert cert.subject == cert.issuer


def test_ca_chain_leaf_issued_by_ca(
    ca_chain: tuple[
        x509.Certificate, rsa.RSAPrivateKey, x509.Certificate, rsa.RSAPrivateKey
    ],
):
    ca_cert, _, leaf_cert, _ = ca_chain
    leaf_cert.verify_directly_issued_by(ca_cert)


def test_make_cert_sid_extension_parses(make_cert: Callable[..., x509.Certificate]):
    cert = make_cert(sid="S-1-5-21-1-2-3-1104")
    assert get_object_sid_from_certificate_sid_extension(cert) == "S-1-5-21-1-2-3-1104"


def test_mock_http_routes_to_handler(
    mock_http: Callable[[Callable[[httpx.Request], httpx.Response]], httpx.Client],
):
    client = mock_http(lambda request: httpx.Response(200, text=request.url.path))
    assert client.get("http://ca.corp.local/certsrv/").text == "/certsrv/"


def test_mock_http_passes_client_options(
    mock_http: Callable[..., httpx.Client],
):
    client = mock_http(
        lambda request: httpx.Response(200, text=str(request.url)),
        base_url="http://ca.corp.local",
    )
    assert client.get("/certsrv/").text == "http://ca.corp.local/certsrv/"


def test_make_ldap_entry_get(make_ldap_entry: Callable[..., LDAPEntry]):
    entry = make_ldap_entry({"cn": "CA", "empty": []}, raw_attributes={"cn": [b"CA"]})
    assert entry.get("cn") == "CA"
    assert entry.get("empty", "default") == "default"
    assert entry.get("missing") is None
    assert entry.get_raw("cn") == [b"CA"]


def test_tmp_cwd_changes_directory(tmp_cwd: Path):
    assert os.getcwd() == str(tmp_cwd)
