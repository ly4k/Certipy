# Certipy - Active Directory certificate abuse
#
# Description:
#   PKINIT structures and helpers
#
# Authors:
#   @ly4k (https://github.com/ly4k)
#
# References:
#   https://github.com/skelsec/minikerberos/blob/master/minikerberos/pkinit.py
#   https://github.com/skelsec/minikerberos/blob/0b81e763216873cd5748da92dc482ba9a31bd19d/minikerberos/protocol/rfc4556.py
#

import os

from asn1crypto import algos, core, keys, x509


def upn_from_certificate(certificate):
    for san in certificate.subject_alt_name_value:
        san = san.native
        if san["type_id"] == "1.3.6.1.4.1.311.20.2.3":
            return san["value"]
    return None


class Enctype(object):
    DES_CRC = 1
    DES_MD4 = 2
    DES_MD5 = 3
    DES3 = 16
    AES128 = 17
    AES256 = 18
    RC4 = 23


class DHNonce(core.OctetString):
    pass


class AlgorithmIdentifiers(core.SequenceOf):
    _child_spec = x509.AlgorithmIdentifier


class KerberosTime(core.GeneralizedTime):
    """KerberosTime ::= GeneralizedTime"""


class ExternalPrincipalIdentifier(core.Sequence):
    _fields = [
        (
            "subjectName",
            core.OctetString,
            {"tag_type": "implicit", "tag": 0, "optional": True},
        ),
        (
            "issuerAndSerialNumber",
            core.OctetString,
            {"tag_type": "implicit", "tag": 1, "optional": True},
        ),
        (
            "subjectKeyIdentifier",
            core.OctetString,
            {"tag_type": "implicit", "tag": 2, "optional": True},
        ),
    ]


class KDCDHKeyInfo(core.Sequence):
    _fields = [
        ("subjectPublicKey", core.BitString, {"tag_type": "explicit", "tag": 0}),
        ("nonce", core.Integer, {"tag_type": "explicit", "tag": 1}),
        (
            "dhKeyExpiration",
            KerberosTime,
            {"tag_type": "explicit", "tag": 2, "optional": True},
        ),
    ]


class ExternalPrincipalIdentifiers(core.SequenceOf):
    _child_spec = ExternalPrincipalIdentifier


class DHRepInfo(core.Sequence):
    _fields = [
        ("dhSignedData", core.OctetString, {"tag_type": "implicit", "tag": 0}),
        (
            "serverDHNonce",
            DHNonce,
            {"tag_type": "explicit", "tag": 1, "optional": True},
        ),
    ]


class PA_PK_AS_REQ(core.Sequence):
    _fields = [
        ("signedAuthPack", core.OctetString, {"tag_type": "implicit", "tag": 0}),
        (
            "trustedCertifiers",
            ExternalPrincipalIdentifiers,
            {"tag_type": "explicit", "tag": 1, "optional": True},
        ),
        (
            "kdcPkId",
            core.OctetString,
            {"tag_type": "implicit", "tag": 2, "optional": True},
        ),
    ]


class PA_PK_AS_REP(core.Choice):
    _alternatives = [
        ("dhInfo", DHRepInfo, {"explicit": (2, 0)}),
        ("encKeyPack", core.OctetString, {"implicit": (2, 1)}),
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
        dhp = algos.DHParameters.load(asn1_bytes).native
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


class PKAuthenticator(core.Sequence):
    _fields = [
        ("cusec", core.Integer, {"tag_type": "explicit", "tag": 0}),
        ("ctime", KerberosTime, {"tag_type": "explicit", "tag": 1}),
        ("nonce", core.Integer, {"tag_type": "explicit", "tag": 2}),
        (
            "paChecksum",
            core.OctetString,
            {"tag_type": "explicit", "tag": 3, "optional": True},
        ),
    ]


class AuthPack(core.Sequence):
    _fields = [
        ("pkAuthenticator", PKAuthenticator, {"tag_type": "explicit", "tag": 0}),
        (
            "clientPublicValue",
            keys.PublicKeyInfo,
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
