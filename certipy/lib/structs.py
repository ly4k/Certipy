"""
Kerberos protocol ASN.1 structure definitions.

This module defines the ASN.1 structures used in Kerberos authentication
protocol and Microsoft extensions, implemented using the asn1crypto library.
It also provides enhanced Enum types with better string representation.
"""

import enum
from typing import List

from asn1crypto import cms, core, csr, keys, x509

from certipy.lib.formatting import to_pascal_case

# ASN.1 tag constants
TAG = "explicit"
APPLICATION = 1
CONTEXT = 2


class IntFlag(enum.IntFlag):
    """
    Enhanced IntFlag with smart string representation.
    """

    def to_list(self) -> List["IntFlag"]:
        """
        Decompose flag into list of individual flags.

        Returns:
            List of individual flag members
        """
        if not self._value_:
            return []

        # Get all individual flags that make up this value
        return [
            flag for flag in self.__class__ if flag.value and flag.value & self._value_
        ]

    def to_str_list(self) -> List[str]:
        """
        Return list of flag names.

        Returns:
            List of flag names
        """
        return [
            to_pascal_case(flag.name)
            for flag in self.to_list()
            if flag.name is not None
        ]

    def __str__(self) -> str:
        """
        Smart string representation that handles combinations gracefully.

        Returns:
            Human-readable string representation of the flag(s)
        """
        # Handle named values
        if self.name is not None:
            return to_pascal_case(self.name)

        # Handle empty flags
        if not self._value_:
            return ""

        # Get individual flags
        flags = self.to_list()

        # If no decomposition was possible, return the raw value
        if not flags:
            return repr(self._value_)

        # Return comma-separated list of flag names
        return ", ".join(
            to_pascal_case(flag.name) for flag in flags if flag.name is not None
        )

    def __repr__(self) -> str:
        return str(self)


class Flag(enum.Flag):
    """
    Enhanced Flag with smart string representation.
    """

    def to_list(self) -> List["Flag"]:
        """
        Decompose flag into list of individual flags.

        Returns:
            List of individual flag members
        """
        if not self._value_:
            return []

        # Get all individual flags that make up this value
        return [
            flag for flag in self.__class__ if flag.value and flag.value & self._value_
        ]

    def to_str_list(self) -> List[str]:
        """
        Return list of flag names.

        Returns:
            List of flag names
        """
        return [
            to_pascal_case(flag.name)
            for flag in self.to_list()
            if flag.name is not None
        ]

    def __str__(self) -> str:
        """
        Smart string representation that handles combinations gracefully.

        Returns:
            Human-readable string representation of the flag(s)
        """
        # Handle named values
        if self.name is not None:
            return to_pascal_case(self.name)

        # Handle empty flags
        if not self._value_:
            return ""

        # Get individual flags
        flags = self.to_list()

        # If no decomposition was possible, return the raw value
        if not flags:
            return repr(self._value_)

        # Return comma-separated list of flag names
        return ", ".join(
            to_pascal_case(flag.name) for flag in flags if flag.name is not None
        )

    def __repr__(self) -> str:
        return str(self)


# =========================================================================
# Basic ASN.1 structures
# =========================================================================


class SequenceOfEnctype(core.SequenceOf):
    """Sequence of Kerberos encryption types."""

    _child_spec = core.Integer


class SequenceOfKerberosString(core.SequenceOf):
    """Sequence of Kerberos strings."""

    _child_spec = core.GeneralString


class PrincipalName(core.Sequence):
    """
    Kerberos principal name structure.

    Represents a service or user principal in the format of name-type and name-string.
    """

    _fields = [
        ("name-type", core.Integer, {"tag_type": TAG, "tag": 0}),
        ("name-string", SequenceOfKerberosString, {"tag_type": TAG, "tag": 1}),
    ]


class HostAddress(core.Sequence):
    """
    Network host address structure.

    Contains address type and the actual address data.
    """

    _fields = [
        ("addr-type", core.Integer, {"tag_type": TAG, "tag": 0}),
        ("address", core.OctetString, {"tag_type": TAG, "tag": 1}),
    ]


class HostAddresses(core.SequenceOf):
    """Collection of host addresses."""

    _child_spec = HostAddress


class KDCOptions(core.BitString):
    """
    Kerberos KDC request options bitmap.

    This structure represents the various options that can be set in a Kerberos request.
    """

    _map = {
        0: "reserved",
        1: "forwardable",
        2: "forwarded",
        3: "proxiable",
        4: "proxy",
        5: "allow-postdate",
        6: "postdated",
        7: "unused7",
        8: "renewable",
        9: "unused9",
        10: "unused10",
        11: "opt-hardware-auth",
        12: "unused12",
        13: "unused13",
        14: "constrained-delegation",  # cname-in-addl-tkt (14)
        15: "canonicalize",
        16: "request-anonymous",
        17: "unused17",
        18: "unused18",
        19: "unused19",
        20: "unused20",
        21: "unused21",
        22: "unused22",
        23: "unused23",
        24: "unused24",
        25: "unused25",
        26: "disable-transited-check",
        27: "renewable-ok",
        28: "enc-tkt-in-skey",
        30: "renew",
        31: "validate",
    }


class EncryptedData(core.Sequence):
    """
    Generic encrypted data container for Kerberos.

    Contains encryption type, optional key version, and the encrypted content.
    """

    _fields = [
        ("etype", core.Integer, {"tag_type": TAG, "tag": 0}),  # EncryptionType
        (
            "kvno",
            core.Integer,
            {"tag_type": TAG, "tag": 1, "optional": True},
        ),  # Key version number
        ("cipher", core.OctetString, {"tag_type": TAG, "tag": 2}),  # Ciphertext
    ]


class Ticket(core.Sequence):
    """
    Kerberos ticket structure.

    Contains ticket version, realm, service name, and encrypted ticket part.
    """

    explicit = (APPLICATION, 1)

    _fields = [
        ("tkt-vno", core.Integer, {"tag_type": TAG, "tag": 0}),
        ("realm", core.GeneralString, {"tag_type": TAG, "tag": 1}),
        ("sname", PrincipalName, {"tag_type": TAG, "tag": 2}),
        ("enc-part", EncryptedData, {"tag_type": TAG, "tag": 3}),  # EncTicketPart
    ]


class SequenceOfTicket(core.SequenceOf):
    """Collection of Kerberos tickets."""

    _child_spec = Ticket


class PaData(core.Sequence):
    """
    Pre-authentication data structure.

    Used for various authentication mechanisms in Kerberos.
    """

    _fields = [
        ("padata-type", core.Integer, {"tag_type": TAG, "tag": 1}),
        ("padata-value", core.OctetString, {"tag_type": TAG, "tag": 2}),
    ]


class MethodData(core.SequenceOf):
    """Collection of pre-authentication data elements."""

    _child_spec = PaData


class KdcReqBody(core.Sequence):
    """
    KDC request body structure.

    Contains the core parameters for KDC requests like AS-REQ and TGS-REQ.
    """

    _fields = [
        ("kdc-options", KDCOptions, {"tag_type": TAG, "tag": 0}),
        ("cname", PrincipalName, {"tag_type": TAG, "tag": 1, "optional": True}),
        ("realm", core.GeneralString, {"tag_type": TAG, "tag": 2}),
        ("sname", PrincipalName, {"tag_type": TAG, "tag": 3, "optional": True}),
        ("from", core.GeneralizedTime, {"tag_type": TAG, "tag": 4, "optional": True}),
        ("till", core.GeneralizedTime, {"tag_type": TAG, "tag": 5, "optional": True}),
        ("rtime", core.GeneralizedTime, {"tag_type": TAG, "tag": 6, "optional": True}),
        ("nonce", core.Integer, {"tag_type": TAG, "tag": 7}),
        (
            "etype",
            SequenceOfEnctype,
            {"tag_type": TAG, "tag": 8},
        ),  # Encryption types in preference order
        ("addresses", HostAddresses, {"tag_type": TAG, "tag": 9, "optional": True}),
        (
            "enc-authorization-data",
            EncryptedData,
            {"tag_type": TAG, "tag": 10, "optional": True},
        ),
        (
            "additional-tickets",
            SequenceOfTicket,
            {"tag_type": TAG, "tag": 11, "optional": True},
        ),
    ]


class KdcReq(core.Sequence):
    """
    Base KDC request structure.

    Parent class for AS-REQ and TGS-REQ messages.
    """

    _fields = [
        ("pvno", core.Integer, {"tag_type": TAG, "tag": 1}),
        ("msg-type", core.Integer, {"tag_type": TAG, "tag": 2}),
        ("padata", MethodData, {"tag_type": TAG, "tag": 3, "optional": True}),
        ("req-body", KdcReqBody, {"tag_type": TAG, "tag": 4}),
    ]


class AsReq(KdcReq):
    """
    Authentication Service Request (AS-REQ).

    Initial request in Kerberos authentication to obtain a TGT.
    """

    explicit = (APPLICATION, 10)


class PaPacRequest(core.Sequence):
    """
    Microsoft PAC request pre-authentication data.

    Controls whether a Privilege Attribute Certificate should be included in the ticket.
    """

    _fields = [
        ("include-pac", core.Boolean, {"tag_type": TAG, "tag": 0}),
    ]


# =========================================================================
# Kerberos Types and Enumerations
# =========================================================================


class NameType:
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


class EncType(enum.IntEnum):
    """Kerberos encryption types."""

    DES_CRC = 1
    DES_MD4 = 2
    DES_MD5 = 3
    DES3 = 16
    AES128 = 17
    AES256 = 18
    RC4 = 23


class AlgorithmIdentifiers(core.SequenceOf):
    """Sequence of algorithm identifiers."""

    _child_spec = x509.AlgorithmIdentifier


class ExternalPrincipalIdentifier(core.Sequence):
    """External principal identifier for PKINIT."""

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
    """KDC-generated DH key information."""

    _fields = [
        ("subjectPublicKey", core.BitString, {"tag_type": "explicit", "tag": 0}),
        ("nonce", core.Integer, {"tag_type": "explicit", "tag": 1}),
        (
            "dhKeyExpiration",
            core.GeneralizedTime,
            {"tag_type": "explicit", "tag": 2, "optional": True},
        ),
    ]


class ExternalPrincipalIdentifiers(core.SequenceOf):
    """Sequence of external principal identifiers."""

    _child_spec = ExternalPrincipalIdentifier


class DHRepInfo(core.Sequence):
    """DH reply information."""

    _fields = [
        ("dhSignedData", core.OctetString, {"tag_type": "implicit", "tag": 0}),
        (
            "serverDHNonce",
            core.OctetString,
            {"tag_type": "explicit", "tag": 1, "optional": True},
        ),
    ]


class PaPkAsReq(core.Sequence):
    """PKINIT request structure."""

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


class PaPkAsRep(core.Choice):
    """PKINIT response structure."""

    _alternatives = [
        ("dhInfo", DHRepInfo, {"explicit": (2, 0)}),
        ("encKeyPack", core.OctetString, {"implicit": (2, 1)}),
    ]


class PKAuthenticator(core.Sequence):
    """PKINIT authenticator structure."""

    _fields = [
        ("cusec", core.Integer, {"tag_type": "explicit", "tag": 0}),
        ("ctime", core.GeneralizedTime, {"tag_type": "explicit", "tag": 1}),
        ("nonce", core.Integer, {"tag_type": "explicit", "tag": 2}),
        (
            "paChecksum",
            core.OctetString,
            {"tag_type": "explicit", "tag": 3, "optional": True},
        ),
    ]


class AuthPack(core.Sequence):
    """PKINIT authentication pack."""

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
            core.OctetString,
            {"tag_type": "explicit", "tag": 3, "optional": True},
        ),
    ]


# =========================================================================
# ASN.1 structures for Microsoft certificate operations
# =========================================================================


class TaggedCertificationRequest(core.Sequence):
    """ASN.1 structure for a tagged certification request."""

    _fields = [
        ("bodyPartID", core.Integer),
        ("certificationRequest", csr.CertificationRequest),
    ]


class TaggedRequest(core.Choice):
    """ASN.1 structure for PKI request types."""

    _alternatives = [
        ("tcr", TaggedCertificationRequest, {"implicit": 0}),
        ("crm", core.Any, {"implicit": 1}),
        ("orm", core.Any, {"implicit": 2}),
    ]


class TaggedAttribute(core.Sequence):
    """ASN.1 structure for a tagged attribute."""

    _fields = [
        ("bodyPartID", core.Integer),
        ("attrType", core.ObjectIdentifier),
        ("attrValues", cms.SetOfAny),
    ]


class TaggedAttributes(core.SequenceOf):
    """Sequence of TaggedAttribute objects."""

    _child_spec = TaggedAttribute


class TaggedRequests(core.SequenceOf):
    """Sequence of TaggedRequest objects."""

    _child_spec = TaggedRequest


class TaggedContentInfos(core.SequenceOf):
    """Sequence of ContentInfo objects."""

    _child_spec = core.Any  # not implemented


class OtherMsgs(core.SequenceOf):
    """Sequence of other message types."""

    _child_spec = core.Any  # not implemented


class PKIData(core.Sequence):
    """ASN.1 structure for PKI data container."""

    _fields = [
        ("controlSequence", TaggedAttributes),
        ("reqSequence", TaggedRequests),
        ("cmsSequence", TaggedContentInfos),
        ("otherMsgSequence", OtherMsgs),
    ]


class CertReference(core.SequenceOf):
    """Reference to certificates by ID."""

    _child_spec = core.Integer


class CMCAddAttributesInfo(core.Sequence):
    """ASN.1 structure for CMC AddAttributesInfo."""

    _fields = [
        ("data_reference", core.Integer),
        ("cert_reference", CertReference),
        ("attributes", csr.SetOfAttributes),
    ]


class EnrollmentNameValuePair(core.Sequence):
    """ASN.1 structure for name-value pairs in enrollment requests."""

    _fields = [
        ("name", core.BMPString),
        ("value", core.BMPString),
    ]


class EnrollmentNameValuePairs(core.SetOf):
    """Set of EnrollmentNameValuePair objects."""

    _child_spec = EnrollmentNameValuePair


def e2i(enum: int) -> int:
    """
    Convert an Impacket enum member to its integer value.

    Static type analysis is confused by the fact that Impacket enums are
    not standard Python enums. This function provides a workaround.

    Args:
        enum: The enum member to convert.

    Returns:
        The integer value of the enum member.
    """
    return enum.value  # type: ignore
