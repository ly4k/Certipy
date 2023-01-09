import datetime
import enum
import os
from random import getrandbits
from typing import Tuple, Union

from asn1crypto import algos as asn1algos
from asn1crypto import cms as asn1cms
from asn1crypto import core as asn1core
from asn1crypto import keys as asn1keys
from asn1crypto import x509 as asn1x509
from impacket.krb5 import constants

from certipy.lib.certificate import (
    cert_to_der,
    hash_digest,
    hashes,
    rsa,
    rsa_pkcs1v15_sign,
    x509,
)
from certipy.lib.structs import KDC_REQ_BODY, PrincipalName, KDCOptions, AS_REQ, PA_PAC_REQUEST

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

class NAME_TYPE(enum.Enum):
	UNKNOWN = 0     #(0),	-- Name type not known
	PRINCIPAL = 1     #(1),	-- Just the name of the principal as in
	SRV_INST = 2     #(2),	-- Service and other unique instance (krbtgt)
	SRV_HST = 3     #(3),	-- Service with host name as instance
	SRV_XHST = 4     # (4),	-- Service with host as remaining components
	UID = 5     # (5),		-- Unique ID
	X500_PRINCIPAL = 6     #(6), -- PKINIT
	SMTP_NAME = 7     #(7),	-- Name in form of SMTP email name
	ENTERPRISE_PRINCIPAL = 10    #(10), -- Windows 2000 UPN
	WELLKNOWN  = 11    #(11),	-- Wellknown
	ENT_PRINCIPAL_AND_ID  = -130  #(-130), -- Windows 2000 UPN and SID
	MS_PRINCIPAL = -128  #(-128), -- NT 4 style name
	MS_PRINCIPAL_AND_ID = -129  #(-129), -- NT style name and SID
	NTLM = -1200 #(-1200) -- NTLM name, realm is domain

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
    now = datetime.datetime.now(datetime.timezone.utc)

    kdc_req_body_data = {}
    kdc_req_body_data['kdc-options'] = KDCOptions({'forwardable','renewable','renewable-ok'})
    kdc_req_body_data['cname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': [username]})
    kdc_req_body_data['realm'] = domain.upper()
    kdc_req_body_data['sname'] = PrincipalName({'name-type': NAME_TYPE.SRV_INST.value, 'name-string': ['krbtgt', domain.upper()]})
    kdc_req_body_data['till']  = (now + datetime.timedelta(days=1)).replace(microsecond=0)
    kdc_req_body_data['rtime'] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
    kdc_req_body_data['nonce'] = getrandbits(31)
    kdc_req_body_data['etype'] = [18,17]

    kdc_req_body = KDC_REQ_BODY(kdc_req_body_data)

    checksum = hash_digest(kdc_req_body.dump(), hashes.SHA1)

    authenticator = {}
    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = now.replace(microsecond=0)
    authenticator['nonce'] = getrandbits(31)
    authenticator['paChecksum'] = checksum

    diffie = DirtyDH.from_dict(DH_PARAMS)

    dp = {}
    dp['p'] = diffie.p
    dp['g'] = diffie.g
    dp['q'] = 0

    pka = {}
    pka['algorithm'] = '1.2.840.10046.2.1'
    pka['parameters'] = asn1keys.DomainParameters(dp)

    spki = {}
    spki['algorithm'] = asn1keys.PublicKeyAlgorithm(pka)
    spki['public_key'] = diffie.get_public_key()

    authpack = {}
    authpack['pkAuthenticator'] = PKAuthenticator(authenticator)
    authpack['clientPublicValue'] = asn1keys.PublicKeyInfo(spki)
    authpack['clientDHNonce'] = diffie.dh_nonce

    authpack = AuthPack(authpack)
    signed_authpack = sign_authpack(authpack.dump(), key, cert)

    payload = PA_PK_AS_REQ()
    payload['signedAuthPack'] = signed_authpack

    pa_data_1 = {}
    pa_data_1['padata-type'] = constants.PreAuthenticationDataTypes.PA_PK_AS_REQ.value
    pa_data_1['padata-value'] = payload.dump()

    pa_data_0 = {}
    pa_data_0['padata-type'] = constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value
    pa_data_0['padata-value'] = PA_PAC_REQUEST({'include-pac': True}).dump()

    asreq = {}
    asreq['pvno'] = 5
    asreq['msg-type'] = 10
    asreq['padata'] = [pa_data_0, pa_data_1]
    asreq['req-body'] = kdc_req_body

    return AS_REQ(asreq).dump(), diffie
