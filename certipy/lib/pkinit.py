"""
PKINIT implementation for Kerberos authentication.

This module provides functionality for Public Key Cryptography for Initial Authentication
in Kerberos (PKINIT), allowing certificate-based authentication to Kerberos services.
It implements:
- ASN.1 structures required for PKINIT
- Certificate signing and verification
- Diffie-Hellman key exchange
- Authentication request generation

References:
- RFC 4556: PKINIT specification
- MS-PKCA: Public Key Cryptography for Initial Authentication
"""

import datetime
import enum
import os
from random import getrandbits
from typing import Dict, Tuple, Union

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
from certipy.lib.structs import (
    AS_REQ,
    KDC_REQ_BODY,
    PA_PAC_REQUEST,
    KDCOptions,
    PrincipalName,
)

#
# Constants and Defaults
#

# Well-Known Group 2: A 1024-bit prime
# Source: https://datatracker.ietf.org/doc/html/rfc2412#appendix-E.2
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

# OIDs used in PKINIT
PKINIT_OID = "1.3.6.1.5.2.3.1"
CMS_SIGNED_DATA_OID = "1.2.840.113549.1.7.2"
DH_KEY_AGREEMENT_OID = "1.2.840.10046.2.1"


#
# Kerberos Types and Enumerations
#


class NAME_TYPE(enum.Enum):
    """Kerberos name types from RFC 4120."""

    UNKNOWN = 0  # Name type not known
    PRINCIPAL = 1  # Just the name of the principal
    SRV_INST = 2  # Service and other unique instance (krbtgt)
    SRV_HST = 3  # Service with host name as instance
    SRV_XHST = 4  # Service with host as remaining components
    UID = 5  # Unique ID
    X500_PRINCIPAL = 6  # PKINIT
    SMTP_NAME = 7  # Name in form of SMTP email name
    ENTERPRISE_PRINCIPAL = 10  # Windows 2000 UPN
    WELLKNOWN = 11  # Wellknown
    ENT_PRINCIPAL_AND_ID = -130  # Windows 2000 UPN and SID
    MS_PRINCIPAL = -128  # NT 4 style name
    MS_PRINCIPAL_AND_ID = -129  # NT style name and SID
    NTLM = -1200  # NTLM name, realm is domain


class Enctype(enum.IntEnum):
    """Kerberos encryption types."""

    DES_CRC = 1
    DES_MD4 = 2
    DES_MD5 = 3
    DES3 = 16
    AES128 = 17
    AES256 = 18
    RC4 = 23


#
# ASN.1 Structure Definitions
#


class DHNonce(asn1core.OctetString):
    """Diffie-Hellman nonce for PKINIT."""

    pass


class AlgorithmIdentifiers(asn1core.SequenceOf):
    """Sequence of algorithm identifiers."""

    _child_spec = asn1x509.AlgorithmIdentifier


class Asn1KerberosTime(asn1core.GeneralizedTime):
    """KerberosTime ::= GeneralizedTime"""

    pass


class ExternalPrincipalIdentifier(asn1core.Sequence):
    """External principal identifier for PKINIT."""

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
    """KDC-generated DH key information."""

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
    """Sequence of external principal identifiers."""

    _child_spec = ExternalPrincipalIdentifier


class DHRepInfo(asn1core.Sequence):
    """DH reply information."""

    _fields = [
        ("dhSignedData", asn1core.OctetString, {"tag_type": "implicit", "tag": 0}),
        (
            "serverDHNonce",
            DHNonce,
            {"tag_type": "explicit", "tag": 1, "optional": True},
        ),
    ]


class PA_PK_AS_REQ(asn1core.Sequence):
    """PKINIT request structure."""

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
    """PKINIT response structure."""

    _alternatives = [
        ("dhInfo", DHRepInfo, {"explicit": (2, 0)}),
        ("encKeyPack", asn1core.OctetString, {"implicit": (2, 1)}),
    ]


class PKAuthenticator(asn1core.Sequence):
    """PKINIT authenticator structure."""

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
    """PKINIT authentication pack."""

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


#
# Diffie-Hellman Implementation
#


class DirtyDH:
    """
    Lightweight Diffie-Hellman key exchange implementation.

    This class supports:
    - Creating DH parameters from various sources
    - Generating public keys
    - Computing shared secrets
    """

    def __init__(self, p: int, g: int):
        """Initialize a new DH instance with random private key."""
        self.p = p
        self.g = g
        self.private_key = os.urandom(32)
        self.private_key_int = int.from_bytes(self.private_key, byteorder="big")
        self.dh_nonce = os.urandom(32)

    @staticmethod
    def from_dict(dhp: Dict[str, int]) -> "DirtyDH":
        """
        Create a DH instance from a dictionary of parameters.

        Args:
            dhp: Dictionary containing 'p' and 'g' keys

        Returns:
            Configured DH instance
        """
        dd = DirtyDH(dhp["p"], dhp["g"])
        return dd

    def get_public_key(self) -> int:
        """
        Calculate the public key.

        Returns:
            Public key value (g^x mod p)

        Raises:
            ValueError: If p and g are not set
        """
        if self.p is None or self.g is None:
            raise ValueError("p and g must be set before getting the public key")
        # y = g^x mod p
        return pow(self.g, self.private_key_int, self.p)

    def exchange(self, peer_public_key: int) -> bytes:
        """
        Perform key exchange with peer's public key.

        Args:
            peer_public_key: Peer's public key value

        Returns:
            The shared secret as bytes
        """
        shared_key_int = pow(peer_public_key, self.private_key_int, self.p)
        # Convert to bytes, ensuring even length
        hex_key = hex(shared_key_int)[2:]
        if len(hex_key) % 2 != 0:
            hex_key = "0" + hex_key

        shared_key = bytes.fromhex(hex_key)
        return shared_key


#
# PKINIT Functions
#


def sign_authpack(
    data: bytes,
    key: rsa.RSAPrivateKey,
    cert: Union[x509.Certificate, asn1x509.Certificate],
) -> bytes:
    """
    Create a signed CMS structure containing the AuthPack.

    Args:
        data: The AuthPack data to sign
        key: RSA private key for signing
        cert: Certificate to include in the signed data

    Returns:
        ASN.1 DER encoded CMS signed data
    """
    # Convert certificate to asn1crypto format if needed
    if isinstance(cert, x509.Certificate):
        cert = asn1x509.Certificate.load(cert_to_der(cert))

    # Create digest algorithm identifier for SHA-1
    digest_algorithm = {"algorithm": asn1algos.DigestAlgorithmId("sha1")}

    # Create signer info
    signer_info = {
        "version": "v1",
        "sid": asn1cms.IssuerAndSerialNumber(
            {
                "issuer": cert.issuer,
                "serial_number": cert.serial_number,
            }
        ),
        "digest_algorithm": asn1algos.DigestAlgorithm(digest_algorithm),
        "signed_attrs": [
            asn1cms.CMSAttribute({"type": "content_type", "values": [PKINIT_OID]}),
            asn1cms.CMSAttribute(
                {"type": "message_digest", "values": [hash_digest(data, hashes.SHA1)]}
            ),
        ],
        "signature_algorithm": asn1algos.SignedDigestAlgorithm(
            {"algorithm": "sha1_rsa"}
        ),
    }

    # Create the signature
    signer_info["signature"] = rsa_pkcs1v15_sign(
        asn1cms.CMSAttributes(signer_info["signed_attrs"]).dump(),
        key,
        hash=hashes.SHA1,
    )

    # Create encapsulated content info
    encapsulated_content_info = {"content_type": PKINIT_OID, "content": data}

    # Create the signed data structure
    signed_data = {
        "version": "v3",
        "digest_algorithms": [asn1algos.DigestAlgorithm(digest_algorithm)],
        "encap_content_info": asn1cms.EncapsulatedContentInfo(
            encapsulated_content_info
        ),
        "certificates": [cert],
        "signer_infos": asn1cms.SignerInfos([asn1cms.SignerInfo(signer_info)]),
    }

    # Create the content info wrapper
    content_info = {
        "content_type": CMS_SIGNED_DATA_OID,
        "content": asn1cms.SignedData(signed_data),
    }

    # Return DER-encoded ContentInfo
    return asn1cms.ContentInfo(content_info).dump()


def build_pkinit_as_req(
    username: str, domain: str, key: rsa.RSAPrivateKey, cert: x509.Certificate
) -> Tuple[bytes, DirtyDH]:
    """
    Build a PKINIT AS-REQ message.

    Args:
        username: Client username
        domain: Domain/realm name
        key: RSA private key for signing
        cert: Client certificate

    Returns:
        A tuple containing:
        - The encoded AS-REQ message
        - The DirtyDH object for later key exchange
    """
    # Get current time
    now = datetime.datetime.now(datetime.timezone.utc)

    # Build KDC-REQ-BODY
    kdc_req_body_data = {
        "kdc-options": KDCOptions({"forwardable", "renewable", "renewable-ok"}),
        "cname": PrincipalName(
            {"name-type": NAME_TYPE.PRINCIPAL.value, "name-string": [username]}
        ),
        "realm": domain.upper(),
        "sname": PrincipalName(
            {
                "name-type": NAME_TYPE.SRV_INST.value,
                "name-string": ["krbtgt", domain.upper()],
            }
        ),
        "till": (now + datetime.timedelta(days=1)).replace(microsecond=0),
        "rtime": (now + datetime.timedelta(days=1)).replace(microsecond=0),
        "nonce": getrandbits(31),
        "etype": [Enctype.AES256, Enctype.AES128],  # Prefer stronger ciphers
    }

    kdc_req_body = KDC_REQ_BODY(kdc_req_body_data)

    # Calculate checksum of the KDC-REQ-BODY
    checksum = hash_digest(kdc_req_body.dump(), hashes.SHA1)

    # Build PKAuthenticator
    authenticator = {
        "cusec": now.microsecond,
        "ctime": now.replace(microsecond=0),
        "nonce": getrandbits(31),
        "paChecksum": checksum,
    }

    # Set up Diffie-Hellman
    diffie = DirtyDH.from_dict(DH_PARAMS)

    # Create DH domain parameters structure
    dh_params = {
        "p": diffie.p,
        "g": diffie.g,
        "q": 0,  # Not used but required by some implementations
    }

    # Create public key algorithm identifier for DH
    public_key_algorithm = {
        "algorithm": DH_KEY_AGREEMENT_OID,
        "parameters": asn1keys.DomainParameters(dh_params),
    }

    # Create subject public key info structure
    subject_public_key_info = {
        "algorithm": asn1keys.PublicKeyAlgorithm(public_key_algorithm),
        "public_key": diffie.get_public_key(),
    }

    # Build AuthPack
    authpack_data = {
        "pkAuthenticator": PKAuthenticator(authenticator),
        "clientPublicValue": asn1keys.PublicKeyInfo(subject_public_key_info),
        "clientDHNonce": diffie.dh_nonce,
    }

    # Encode and sign the AuthPack
    authpack = AuthPack(authpack_data)
    signed_authpack = sign_authpack(authpack.dump(), key, cert)

    # Build PA-PK-AS-REQ
    payload = PA_PK_AS_REQ()
    payload["signedAuthPack"] = signed_authpack

    # Prepare PA-DATA entries
    # PA-PAC-REQUEST to request a PAC
    pa_data_pac = {
        "padata-type": constants.PreAuthenticationDataTypes.PA_PAC_REQUEST,
        "padata-value": PA_PAC_REQUEST({"include-pac": True}).dump(),
    }

    # PA-PK-AS-REQ for PKINIT
    pa_data_pk = {
        "padata-type": constants.PreAuthenticationDataTypes.PA_PK_AS_REQ,
        "padata-value": payload.dump(),
    }

    # Build AS-REQ
    asreq = {
        "pvno": 5,  # Kerberos version 5
        "msg-type": 10,  # AS-REQ
        "padata": [pa_data_pac, pa_data_pk],
        "req-body": kdc_req_body,
    }

    # Return the encoded AS-REQ and the Diffie-Hellman object
    return AS_REQ(asreq).dump(), diffie
