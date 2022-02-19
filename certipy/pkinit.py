import datetime
import os
from random import getrandbits
from typing import Tuple, Union

from asn1crypto import algos as asn1algos
from asn1crypto import cms as asn1cms
from asn1crypto import core as asn1core
from asn1crypto import keys as asn1keys
from asn1crypto import x509 as asn1x509
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, seq_set, seq_set_iter
from impacket.krb5.types import KerberosTime, Principal
from pyasn1.codec.der import encoder
from pyasn1.type.univ import noValue

from certipy.certificate import (
    cert_to_der,
    hash_digest,
    hashes,
    rsa,
    rsa_pkcs1v15_sign,
    x509,
)

# https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py#L292
DH_PARAMS = {
    "p": int(
        (
            "00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea6"
            "3b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e4"
            "85b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b"
            "1fe649286651ece65381ffffffffffffffff"
        ),
        16,
    ),
    "g": 2,
}


class Enctype(object):
    DES_CRC = 1
    DES_MD4 = 2
    DES_MD5 = 3
    DES3 = 16
    AES128 = 17
    AES256 = 18
    RC4 = 23


class DHNonce(asn1core.OctetString):
    pass


class AlgorithmIdentifiers(asn1core.SequenceOf):
    _child_spec = asn1x509.AlgorithmIdentifier


class Asn1KerberosTime(asn1core.GeneralizedTime):
    """KerberosTime ::= GeneralizedTime"""


class ExternalPrincipalIdentifier(asn1core.Sequence):
    _fields = [
        (
            "subjectName",
            asn1core.OctetString,
            {"tag_type": "implicit", "tag": 0, "optional": True},
        ),
        (
            "issuerAndSerialNumber",
            asn1core.OctetString,
            {"tag_type": "implicit", "tag": 1, "optional": True},
        ),
        (
            "subjectKeyIdentifier",
            asn1core.OctetString,
            {"tag_type": "implicit", "tag": 2, "optional": True},
        ),
    ]


class KDCDHKeyInfo(asn1core.Sequence):
    _fields = [
        ("subjectPublicKey", asn1core.BitString, {"tag_type": "explicit", "tag": 0}),
        ("nonce", asn1core.Integer, {"tag_type": "explicit", "tag": 1}),
        (
            "dhKeyExpiration",
            Asn1KerberosTime,
            {"tag_type": "explicit", "tag": 2, "optional": True},
        ),
    ]


class ExternalPrincipalIdentifiers(asn1core.SequenceOf):
    _child_spec = ExternalPrincipalIdentifier


class DHRepInfo(asn1core.Sequence):
    _fields = [
        ("dhSignedData", asn1core.OctetString, {"tag_type": "implicit", "tag": 0}),
        (
            "serverDHNonce",
            DHNonce,
            {"tag_type": "explicit", "tag": 1, "optional": True},
        ),
    ]


class PA_PK_AS_REQ(asn1core.Sequence):
    _fields = [
        ("signedAuthPack", asn1core.OctetString, {"tag_type": "implicit", "tag": 0}),
        (
            "trustedCertifiers",
            ExternalPrincipalIdentifiers,
            {"tag_type": "explicit", "tag": 1, "optional": True},
        ),
        (
            "kdcPkId",
            asn1core.OctetString,
            {"tag_type": "implicit", "tag": 2, "optional": True},
        ),
    ]


class PA_PK_AS_REP(asn1core.Choice):
    _alternatives = [
        ("dhInfo", DHRepInfo, {"explicit": (2, 0)}),
        ("encKeyPack", asn1core.OctetString, {"implicit": (2, 1)}),
    ]


class DirtyDH:
    def __init__(self):
        self.p = None
        self.g = None
        self.shared_key = None
        self.shared_key_int = None
        self.private_key = os.urandom(32)
        self.private_key_int = int(self.private_key.hex(), 16)
        self.dh_nonce = os.urandom(32)

    @staticmethod
    def from_params(p, g):
        dd = DirtyDH()
        dd.p = p
        dd.g = g
        return dd

    @staticmethod
    def from_dict(dhp):
        dd = DirtyDH()
        dd.p = dhp["p"]
        dd.g = dhp["g"]
        return dd

    @staticmethod
    def from_asn1(asn1_bytes):
        dhp = asn1algos.DHParameters.load(asn1_bytes).native
        return DirtyDH.from_dict(dhp)

    def get_public_key(self):
        # y = g^x mod p
        return pow(self.g, self.private_key_int, self.p)

    def exchange(self, bob_int):
        self.shared_key_int = pow(bob_int, self.private_key_int, self.p)
        x = hex(self.shared_key_int)[2:]
        if len(x) % 2 != 0:
            x = "0" + x
        self.shared_key = bytes.fromhex(x)
        return self.shared_key


class PKAuthenticator(asn1core.Sequence):
    _fields = [
        ("cusec", asn1core.Integer, {"tag_type": "explicit", "tag": 0}),
        ("ctime", Asn1KerberosTime, {"tag_type": "explicit", "tag": 1}),
        ("nonce", asn1core.Integer, {"tag_type": "explicit", "tag": 2}),
        (
            "paChecksum",
            asn1core.OctetString,
            {"tag_type": "explicit", "tag": 3, "optional": True},
        ),
    ]


class AuthPack(asn1core.Sequence):
    _fields = [
        ("pkAuthenticator", PKAuthenticator, {"tag_type": "explicit", "tag": 0}),
        (
            "clientPublicValue",
            asn1keys.PublicKeyInfo,
            {"tag_type": "explicit", "tag": 1, "optional": True},
        ),
        (
            "supportedCMSTypes",
            AlgorithmIdentifiers,
            {"tag_type": "explicit", "tag": 2, "optional": True},
        ),
        (
            "clientDHNonce",
            DHNonce,
            {"tag_type": "explicit", "tag": 3, "optional": True},
        ),
    ]


def sign_authpack(
    data: bytes,
    key: rsa.RSAPrivateKey,
    cert: Union[x509.Certificate, asn1x509.Certificate],
) -> bytes:
    if isinstance(cert, x509.Certificate):
        cert = asn1x509.Certificate.load(cert_to_der(cert))

    digest_algorithm = {}
    digest_algorithm["algorithm"] = asn1algos.DigestAlgorithmId("sha1")

    signer_info = {}
    signer_info["version"] = "v1"
    signer_info["sid"] = asn1cms.IssuerAndSerialNumber(
        {
            "issuer": cert.issuer,
            "serial_number": cert.serial_number,
        }
    )

    signer_info["digest_algorithm"] = asn1algos.DigestAlgorithm(digest_algorithm)
    signer_info["signed_attrs"] = [
        asn1cms.CMSAttribute({"type": "content_type", "values": ["1.3.6.1.5.2.3.1"]}),
        asn1cms.CMSAttribute(
            {"type": "message_digest", "values": [hash_digest(data, hashes.SHA1)]}
        ),
    ]
    signer_info["signature_algorithm"] = asn1algos.SignedDigestAlgorithm(
        {"algorithm": "sha1_rsa"}
    )
    signer_info["signature"] = rsa_pkcs1v15_sign(
        asn1cms.CMSAttributes(signer_info["signed_attrs"]).dump(),
        key,
        hash=hashes.SHA1,
    )

    enscapsulated_content_info = {}
    enscapsulated_content_info["content_type"] = "1.3.6.1.5.2.3.1"
    enscapsulated_content_info["content"] = data

    signed_data = {}
    signed_data["version"] = "v3"
    signed_data["digest_algorithms"] = [asn1algos.DigestAlgorithm(digest_algorithm)]
    signed_data["encap_content_info"] = asn1cms.EncapsulatedContentInfo(
        enscapsulated_content_info
    )
    signed_data["certificates"] = [cert]
    signed_data["signer_infos"] = asn1cms.SignerInfos([asn1cms.SignerInfo(signer_info)])

    content_info = {}
    content_info["content_type"] = "1.2.840.113549.1.7.2"
    content_info["content"] = asn1cms.SignedData(signed_data)

    return asn1cms.ContentInfo(content_info).dump()


def build_pkinit_as_req(
    username: str, domain: str, key: rsa.RSAPrivateKey, cert: x509.Certificate
) -> Tuple[AS_REQ, DirtyDH]:
    as_req = AS_REQ()

    server_name = Principal(
        "krbtgt/%s" % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value
    )
    client_name = Principal(
        username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
    )

    pac_request = KERB_PA_PAC_REQUEST()
    pac_request["include-pac"] = True
    encoded_pac_request = encoder.encode(pac_request)

    as_req["pvno"] = 5
    as_req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)

    req_body = seq_set(as_req, "req-body")

    opts = []
    opts.append(constants.KDCOptions.forwardable.value)
    opts.append(constants.KDCOptions.renewable.value)
    opts.append(constants.KDCOptions.proxiable.value)
    req_body["kdc-options"] = constants.encodeFlags(opts)

    seq_set(req_body, "sname", server_name.components_to_asn1)
    seq_set(req_body, "cname", client_name.components_to_asn1)

    req_body["realm"] = domain

    now = datetime.datetime.now(datetime.timezone.utc)
    req_body["till"] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
    req_body["rtime"] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
    req_body["nonce"] = getrandbits(31)

    supported_ciphers = (
        int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
        int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
    )

    seq_set_iter(req_body, "etype", supported_ciphers)

    encoded_req_body = encoder.encode(req_body)

    checksum = hash_digest(encoded_req_body, hashes.SHA1)

    diffie = DirtyDH.from_dict(DH_PARAMS)

    authpack = AuthPack(
        {
            "pkAuthenticator": PKAuthenticator(
                {
                    "cusec": now.microsecond,
                    "ctime": now.replace(microsecond=0),
                    "nonce": getrandbits(31),
                    "paChecksum": checksum,
                }
            ),
            "clientPublicValue": asn1keys.PublicKeyInfo(
                {
                    "algorithm": asn1keys.PublicKeyAlgorithm(
                        {
                            "algorithm": "1.2.840.10046.2.1",
                            "parameters": asn1keys.DomainParameters(
                                {"p": diffie.p, "g": diffie.g, "q": 0}
                            ),
                        }
                    ),
                    "public_key": diffie.get_public_key(),
                }
            ),
            "clientDHNonce": diffie.dh_nonce,
        }
    )

    signed_authpack = sign_authpack(authpack.dump(), key, cert)

    pa_pk_as_req = PA_PK_AS_REQ()
    pa_pk_as_req["signedAuthPack"] = signed_authpack
    encoded_pa_pk_as_req = pa_pk_as_req.dump()

    as_req["padata"] = noValue

    as_req["padata"][0] = noValue
    as_req["padata"][0]["padata-type"] = int(
        constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value
    )
    as_req["padata"][0]["padata-value"] = encoded_pac_request

    as_req["padata"][1] = noValue
    as_req["padata"][1]["padata-type"] = int(
        constants.PreAuthenticationDataTypes.PA_PK_AS_REQ.value
    )
    as_req["padata"][1]["padata-value"] = encoded_pa_pk_as_req

    return as_req, diffie
