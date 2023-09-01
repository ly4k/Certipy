import enum
import io

from asn1crypto import core

from certipy.lib.formatting import to_pascal_case

def _high_bit(value):
    """returns index of highest bit, or -1 if value is zero or negative"""
    return value.bit_length() - 1

def _decompose(flag, value):
    """Extract all members from the value."""
    # _decompose is only called if the value is not named
    not_covered = value
    negative = value < 0
    members = []
    for member in flag:
        member_value = member.value
        if member_value and member_value & value == member_value:
            members.append(member)
            not_covered &= ~member_value
    if not negative:
        tmp = not_covered
        while tmp:
            flag_value = 2 ** _high_bit(tmp)
            if flag_value in flag._value2member_map_:
                members.append(flag._value2member_map_[flag_value])
                not_covered &= ~flag_value
            tmp &= ~flag_value
    if not members and value in flag._value2member_map_:
        members.append(flag._value2member_map_[value])
    members.sort(key=lambda m: m._value_, reverse=True)
    if len(members) > 1 and members[0].value == value:
        # we have the breakdown, don't need the value member itself
        members.pop(0)
    return members, not_covered



class IntFlag(enum.IntFlag):
    def to_list(self):
        cls = self.__class__
        members, _ = _decompose(cls, self._value_)
        return members

    def to_str_list(self):
        return list(map(lambda x: str(x), self.to_list()))

    def __str__(self):
        cls = self.__class__
        if self._name_ is not None:
            return "%s" % (to_pascal_case(self._name_))
        members, _ = _decompose(cls, self._value_)
        if len(members) == 1 and members[0]._name_ is None:
            return "%r" % (members[0]._value_)
        else:
            return "%s" % (
                ", ".join(
                    [to_pascal_case(str(m._name_ or m._value_)) for m in members]
                ),
            )

    def __repr__(self):
        return str(self)

class Flag(enum.Flag):
    def __str__(self):
        cls = self.__class__
        if self._name_ is not None:
            return "%s" % (to_pascal_case(self._name_))
        members, _ = _decompose(cls, self._value_)
        if len(members) == 1 and members[0]._name_ is None:
            return "%r" % (members[0]._value_)
        else:
            return "%s" % (
                ", ".join(
                    [to_pascal_case(str(m._name_ or m._value_)) for m in members]
                ),
            )

# KerberosV5Spec2 DEFINITIONS EXPLICIT TAGS ::=
TAG = "explicit"

# class
UNIVERSAL = 0
APPLICATION = 1
CONTEXT = 2
krb5_pvno = 5  # -- current Kerberos protocol version number


class PADATA_TYPE(core.Enumerated):
    _map = {
        0: "NONE",  # (0),
        1: "TGS-REQ",  # (1), #		1   : 'AP-REQ', #(1),
        2: "ENC-TIMESTAMP",  # (2),
        3: "PW-SALT",  # (3),
        5: "ENC-UNIX-TIME",  # (5),
        6: "SANDIA-SECUREID",  # (6),
        7: "SESAME",  # (7),
        8: "OSF-DCE",  # (8),
        9: "CYBERSAFE-SECUREID",  # (9),
        10: "AFS3-SALT",  # (10),
        11: "ETYPE-INFO",  # (11),
        12: "SAM-CHALLENGE",  # (12), -- ', #(sam/otp)
        13: "SAM-RESPONSE",  # (13), -- ', #(sam/otp)
        14: "PK-AS-REQ-19",  # (14), -- ', #(PKINIT-19)
        15: "PK-AS-REP-19",  # (15), -- ', #(PKINIT-19)
        15: "PK-AS-REQ-WIN",  # (15), -- ', #(PKINIT - old number)
        16: "PK-AS-REQ",  # (16), -- ', #(PKINIT-25)
        17: "PK-AS-REP",  # (17), -- ', #(PKINIT-25)
        18: "PA-PK-OCSP-RESPONSE",  # (18),
        19: "ETYPE-INFO2",  # (19),
        20: "USE-SPECIFIED-KVNO",  # (20),
        20: "SVR-REFERRAL-INFO",  # (20), --- old ms referral number
        21: "SAM-REDIRECT",  # (21), -- ', #(sam/otp)
        22: "GET-FROM-TYPED-DATA",  # (22),
        23: "SAM-ETYPE-INFO",  # (23),
        25: "SERVER-REFERRAL",  # (25),
        24: "ALT-PRINC",  # (24),		-- ', #(crawdad@fnal.gov)
        30: "SAM-CHALLENGE2",  # (30),		-- ', #(kenh@pobox.com)
        31: "SAM-RESPONSE2",  # (31),		-- ', #(kenh@pobox.com)
        41: "PA-EXTRA-TGT",  # (41),			-- Reserved extra TGT
        102: "TD-KRB-PRINCIPAL",  # (102),	-- PrincipalName
        104: "PK-TD-TRUSTED-CERTIFIERS",  # (104), -- PKINIT
        105: "PK-TD-CERTIFICATE-INDEX",  # (105), -- PKINIT
        106: "TD-APP-DEFINED-ERROR",  # (106),	-- application specific
        107: "TD-REQ-NONCE",  # (107),		-- INTEGER
        108: "TD-REQ-SEQ",  # (108),		-- INTEGER
        128: "PA-PAC-REQUEST",  # (128),	-- jbrezak@exchange.microsoft.com
        129: "PA-FOR-USER",  # (129),		-- MS-KILE
        130: "FOR-X509-USER",  # (130),		-- MS-KILE
        131: "FOR-CHECK-DUPS",  # (131),	-- MS-KILE
        132: "AS-CHECKSUM",  # (132),		-- MS-KILE
        132: "PK-AS-09-BINDING",  # (132),	-- client send this to -- tell KDC that is supports -- the asCheckSum in the --  PK-AS-REP
        133: "CLIENT-CANONICALIZED",  # (133),	-- referals
        133: "FX-COOKIE",  # (133),		-- krb-wg-preauth-framework
        134: "AUTHENTICATION-SET",  # (134),	-- krb-wg-preauth-framework
        135: "AUTH-SET-SELECTED",  # (135),	-- krb-wg-preauth-framework
        136: "FX-FAST",  # (136),		-- krb-wg-preauth-framework
        137: "FX-ERROR",  # (137),		-- krb-wg-preauth-framework
        138: "ENCRYPTED-CHALLENGE",  # (138),	-- krb-wg-preauth-framework
        141: "OTP-CHALLENGE",  # (141),		-- ', #(gareth.richards@rsa.com)
        142: "OTP-REQUEST",  # (142),		-- ', #(gareth.richards@rsa.com)
        143: "OTP-CONFIRM",  # (143),		-- ', #(gareth.richards@rsa.com)
        144: "OTP-PIN-CHANGE",  # (144),	-- ', #(gareth.richards@rsa.com)
        145: "EPAK-AS-REQ",  # (145),
        146: "EPAK-AS-REP",  # (146),
        147: "PKINIT-KX",  # (147),		-- krb-wg-anon
        148: "PKU2U-NAME",  # (148),		-- zhu-pku2u
        149: "REQ-ENC-PA-REP",  # (149),	--
        151: "SPAKE",  # (151),	https://datatracker.ietf.org/doc/draft-ietf-kitten-krb-spake-preauth/?include_text=1
        165: "SUPPORTED-ETYPES",  # (165)	-- MS-KILE
        167: "PA-PAC-OPTIONS",
    }


class AUTHDATA_TYPE(core.Enumerated):
    _map = {
        1: "IF-RELEVANT",  # 1),
        2: "INTENDED-FOR-SERVER",  # 2),
        3: "INTENDED-FOR-APPLICATION-CLASS",  # 3),
        4: "KDC-ISSUED",  # 4),
        5: "AND-OR",  # 5),
        6: "MANDATORY-TICKET-EXTENSIONS",  # 6),
        7: "IN-TICKET-EXTENSIONS",  # 7),
        8: "MANDATORY-FOR-KDC",  # 8),
        9: "INITIAL-VERIFIED-CAS",  # 9),
        64: "OSF-DCE",  # 64),
        65: "SESAME",  # 65),
        66: "OSF-DCE-PKI-CERTID",  # 66),
        70: "AD-authentication-strength",
        71: "AD-fx-fast-armor",
        72: "AD-fx-fast-used",
        128: "WIN2K-PAC",  # 128),
        129: "GSS-API-ETYPE-NEGOTIATION",  # 129), -- Authenticator only
        -17: "SIGNTICKET-OLDER",  # -17),
        142: "SIGNTICKET-OLD",  # 142),
        512: "SIGNTICKET",  # 512)
    }


class CKSUMTYPE(core.Enumerated):
    _map = {
        0: "NONE",  # 0),
        1: "CRC32",  # 1),
        2: "RSA_MD4",  # 2),
        3: "RSA_MD4_DES",  # 3),
        4: "DES_MAC",  # 4),
        5: "DES_MAC_K",  # 5),
        6: "RSA_MD4_DES_K",  # 6),
        7: "RSA_MD5",  # 7),
        8: "RSA_MD5_DES",  # 8),
        9: "RSA_MD5_DES3",  # 9),
        10: "SHA1_OTHER",  # 10),
        12: "HMAC_SHA1_DES3",  # 12),
        14: "SHA1",  # 14),
        15: "HMAC_SHA1_96_AES_128",  # 15),
        16: "HMAC_SHA1_96_AES_256",  # 16),
        0x8003: "GSSAPI",  # 0x8003),
        -138: "HMAC_MD5",  # -138),	-- unofficial microsoft number
        -1138: "HMAC_MD5_ENC",  # -1138)	-- even more unofficial
    }


# enctypes
class ENCTYPE(core.Enumerated):
    _map = {
        0: "NULL",  # 0),
        1: "DES_CBC_CRC",  # 1),
        2: "DES_CBC_MD4",  # 2),
        3: "DES_CBC_MD5",  # 3),
        5: "DES3_CBC_MD5",  # 5),
        7: "OLD_DES3_CBC_SHA1",  # 7),
        8: "SIGN_DSA_GENERATE",  # 8),
        9: "ENCRYPT_RSA_PRIV",  # 9),
        10: "ENCRYPT_RSA_PUB",  # 10),
        16: "DES3_CBC_SHA1",  # 16),	-- with key derivation
        17: "AES128_CTS_HMAC_SHA1_96",  # 17),
        18: "AES256_CTS_HMAC_SHA1_96",  # 18),
        23: "ARCFOUR_HMAC_MD5",  # 23),
        24: "ARCFOUR_HMAC_MD5_56",  # 24),
        48: "ENCTYPE_PK_CROSS",  # 48),
        # -- some "old" windows types
        -128: "ARCFOUR_MD4",  # -128),
        -133: "ARCFOUR_HMAC_OLD",  # -133),
        -135: "ARCFOUR_HMAC_OLD_EXP",  # -135),
        # -- these are for Heimdal internal use
        -0x1000: "DES_CBC_NONE",  # -0x1000),
        -0x1001: "DES3_CBC_NONE",  # -0x1001),
        -0x1002: "DES_CFB64_NONE",  # -0x1002),
        -0x1003: "DES_PCBC_NONE",  # -0x1003),
        -0x1004: "DIGEST_MD5_NONE",  # -0x1004),		-- private use, lukeh@padl.com
        -0x1005: "CRAM_MD5_NONE",  # -0x1005)		-- private use, lukeh@padl.com
    }


class SequenceOfEnctype(core.SequenceOf):
    _child_spec = core.Integer


class Microseconds(core.Integer):
    """::= INTEGER (0..999999)
    -- microseconds
    """


class krb5int32(core.Integer):
    """krb5int32  ::= INTEGER (-2147483648..2147483647)"""


class krb5uint32(core.Integer):
    """krb5uint32  ::= INTEGER (0..4294967295)"""


class KerberosString(core.GeneralString):
    """KerberosString ::= GeneralString (IA5String)
    For compatibility, implementations MAY choose to accept GeneralString
    values that contain characters other than those permitted by
    IA5String...
    """


class SequenceOfKerberosString(core.SequenceOf):
    _child_spec = KerberosString


# https://github.com/tiran/kkdcpasn1/blob/asn1crypto/pykkdcpasn1.py
class Realm(KerberosString):
    """Realm ::= KerberosString"""


# https://github.com/tiran/kkdcpasn1/blob/asn1crypto/pykkdcpasn1.py
class PrincipalName(core.Sequence):
    """PrincipalName for KDC-REQ-BODY and Ticket
    PrincipalName ::= SEQUENCE {
            name-type	[0] Int32,
            name-string  [1] SEQUENCE OF KerberosString
    }
    """

    _fields = [
        ("name-type", krb5int32, {"tag_type": TAG, "tag": 0}),
        ("name-string", SequenceOfKerberosString, {"tag_type": TAG, "tag": 1}),
    ]


class Principal(core.Sequence):
    _fields = [
        ("name", PrincipalName, {"tag_type": TAG, "tag": 0}),
        ("realm", Realm, {"tag_type": TAG, "tag": 1}),
    ]


class Principals(core.SequenceOf):
    _child_spec = Principal


class HostAddress(core.Sequence):
    """HostAddress for HostAddresses
    HostAddress ::= SEQUENCE {
        addr-type        [0] Int32,
        address  [1] OCTET STRING
    }
    """

    _fields = [
        ("addr-type", krb5int32, {"tag_type": TAG, "tag": 0}),
        ("address", core.OctetString, {"tag_type": TAG, "tag": 1}),
    ]


class HostAddresses(core.SequenceOf):
    """SEQUENCE OF HostAddress"""

    _child_spec = HostAddress


class KerberosTime(core.GeneralizedTime):
    """KerberosTime ::= GeneralizedTime"""


class AuthorizationDataElement(core.Sequence):
    _fields = [
        ("ad-type", krb5int32, {"tag_type": TAG, "tag": 0}),
        ("ad-data", core.OctetString, {"tag_type": TAG, "tag": 1}),
    ]


class AuthorizationData(core.SequenceOf):
    """SEQUENCE OF HostAddress"""

    _child_spec = AuthorizationDataElement


class APOptions(core.BitString):
    _map = {
        0: "reserved",  # (0),
        1: "use-session-key",  # (1),
        2: "mutual-required",  # (2)
    }


class TicketFlags(core.BitString):
    _map = {
        0: "reserved",
        1: "forwardable",
        2: "forwarded",
        3: "proxiable",
        4: "proxy",
        5: "may-postdate",
        6: "postdated",
        7: "invalid",
        8: "renewable",
        9: "initial",
        10: "pre-authent",
        11: "hw-authent",
        12: "transited-policy-checked",
        13: "ok-as-delegate",
        14: "anonymous",
        15: "enc-pa-rep",
    }


class KDCOptions(core.BitString):
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
        14: "constrained-delegation",  # -- cname-in-addl-tkt (14)
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


class LR_TYPE(core.Enumerated):
    _map = {
        0: "NONE",  # 0),		-- no information
        1: "INITIAL_TGT",  # 1),	-- last initial TGT request
        2: "INITIAL",  # 2),		-- last initial request
        3: "ISSUE_USE_TGT",  # 3),	-- time of newest TGT used
        4: "RENEWAL",  # 4),		-- time of last renewal
        5: "REQUEST",  # 5),		-- time of last request ', #of any type)
        6: "PW_EXPTIME",  # 6),	-- expiration time of password
        7: "ACCT_EXPTIME",  # 7)	-- expiration time of account
    }


class LastReqInner(core.Sequence):
    _fields = [
        ("lr-type", krb5int32, {"tag_type": TAG, "tag": 0}),  # LR_TYPE
        ("lr-value", KerberosTime, {"tag_type": TAG, "tag": 1}),
    ]


class LastReq(core.SequenceOf):
    _child_spec = LastReqInner


class EncryptedData(core.Sequence):
    _fields = [
        ("etype", krb5int32, {"tag_type": TAG, "tag": 0}),  # -- EncryptionType
        ("kvno", krb5uint32, {"tag_type": TAG, "tag": 1, "optional": True}),  #
        ("cipher", core.OctetString, {"tag_type": TAG, "tag": 2}),  # ciphertext
    ]


class EncryptionKey(core.Sequence):
    _fields = [
        ("keytype", krb5uint32, {"tag_type": TAG, "tag": 0}),  # -- EncryptionType
        ("keyvalue", core.OctetString, {"tag_type": TAG, "tag": 1}),  #
    ]


# -- encoded Transited field


class TransitedEncoding(core.Sequence):
    _fields = [
        ("tr-type", krb5uint32, {"tag_type": TAG, "tag": 0}),  # -- must be registered
        ("contents", core.OctetString, {"tag_type": TAG, "tag": 1}),  #
    ]


# https://github.com/tiran/kkdcpasn1/blob/asn1crypto/pykkdcpasn1.py
class Ticket(core.Sequence):
    explicit = (APPLICATION, 1)

    _fields = [
        ("tkt-vno", krb5int32, {"tag_type": TAG, "tag": 0}),
        ("realm", Realm, {"tag_type": TAG, "tag": 1}),
        ("sname", PrincipalName, {"tag_type": TAG, "tag": 2}),
        ("enc-part", EncryptedData, {"tag_type": TAG, "tag": 3}),  # EncTicketPart
    ]


class SequenceOfTicket(core.SequenceOf):
    """SEQUENCE OF Ticket for KDC-REQ-BODY"""

    _child_spec = Ticket


# -- Encrypted part of ticket
class EncTicketPart(core.Sequence):
    explicit = (APPLICATION, 3)

    _fields = [
        ("flags", TicketFlags, {"tag_type": TAG, "tag": 0}),
        ("key", EncryptionKey, {"tag_type": TAG, "tag": 1}),
        ("crealm", Realm, {"tag_type": TAG, "tag": 2}),
        ("cname", PrincipalName, {"tag_type": TAG, "tag": 3}),
        ("transited", TransitedEncoding, {"tag_type": TAG, "tag": 4}),
        ("authtime", KerberosTime, {"tag_type": TAG, "tag": 5}),
        ("starttime", KerberosTime, {"tag_type": TAG, "tag": 6, "optional": True}),
        ("endtime", KerberosTime, {"tag_type": TAG, "tag": 7}),
        ("renew-till", KerberosTime, {"tag_type": TAG, "tag": 8, "optional": True}),
        ("caddr", HostAddresses, {"tag_type": TAG, "tag": 9, "optional": True}),
        (
            "authorization-data",
            AuthorizationData,
            {"tag_type": TAG, "tag": 10, "optional": True},
        ),
    ]


class Checksum(core.Sequence):
    _fields = [
        ("cksumtype", krb5int32, {"tag_type": TAG, "tag": 0}),  # CKSUMTYPE
        ("checksum", core.OctetString, {"tag_type": TAG, "tag": 1}),
    ]


class Authenticator(core.Sequence):
    explicit = (APPLICATION, 2)

    _fields = [
        ("authenticator-vno", krb5int32, {"tag_type": TAG, "tag": 0}),
        ("crealm", Realm, {"tag_type": TAG, "tag": 1}),
        ("cname", PrincipalName, {"tag_type": TAG, "tag": 2}),
        ("cksum", Checksum, {"tag_type": TAG, "tag": 3, "optional": True}),
        ("cusec", krb5int32, {"tag_type": TAG, "tag": 4}),
        ("ctime", KerberosTime, {"tag_type": TAG, "tag": 5}),
        ("subkey", EncryptionKey, {"tag_type": TAG, "tag": 6, "optional": True}),
        ("seq-number", krb5uint32, {"tag_type": TAG, "tag": 7, "optional": True}),
        (
            "authorization-data",
            AuthorizationData,
            {"tag_type": TAG, "tag": 8, "optional": True},
        ),
    ]


class PA_DATA(core.Sequence):  #!!!! IT STARTS AT ONE!!!!
    _fields = [
        ("padata-type", core.Integer, {"tag_type": TAG, "tag": 1}),
        ("padata-value", core.OctetString, {"tag_type": TAG, "tag": 2}),
    ]


class ETYPE_INFO_ENTRY(core.Sequence):
    _fields = [
        ("etype", krb5int32, {"tag_type": TAG, "tag": 0}),
        ("salt", core.OctetString, {"tag_type": TAG, "tag": 1, "optional": True}),
        ("salttype", krb5int32, {"tag_type": TAG, "tag": 2, "optional": True}),
    ]


class ETYPE_INFO(core.SequenceOf):
    _child_spec = ETYPE_INFO_ENTRY


class ETYPE_INFO2_ENTRY(core.Sequence):
    _fields = [
        ("etype", krb5int32, {"tag_type": TAG, "tag": 0}),
        ("salt", KerberosString, {"tag_type": TAG, "tag": 1, "optional": True}),
        ("s2kparams", core.OctetString, {"tag_type": TAG, "tag": 2, "optional": True}),
    ]


class ETYPE_INFO2(core.SequenceOf):
    _child_spec = ETYPE_INFO2_ENTRY


class METHOD_DATA(core.SequenceOf):
    _child_spec = PA_DATA


class TypedData(core.Sequence):
    _fields = [
        ("data-type", krb5int32, {"tag_type": TAG, "tag": 0}),
        ("data-value", core.OctetString, {"tag_type": TAG, "tag": 1, "optional": True}),
    ]


"""
class TYPED-DATA ::= SEQUENCE SIZE (1..MAX) OF TypedData
"""


class KDC_REQ_BODY(core.Sequence):
    _fields = [
        ("kdc-options", KDCOptions, {"tag_type": TAG, "tag": 0}),
        ("cname", PrincipalName, {"tag_type": TAG, "tag": 1, "optional": True}),
        ("realm", Realm, {"tag_type": TAG, "tag": 2}),
        ("sname", PrincipalName, {"tag_type": TAG, "tag": 3, "optional": True}),
        ("from", KerberosTime, {"tag_type": TAG, "tag": 4, "optional": True}),
        ("till", KerberosTime, {"tag_type": TAG, "tag": 5, "optional": True}),
        ("rtime", KerberosTime, {"tag_type": TAG, "tag": 6, "optional": True}),
        ("nonce", krb5int32, {"tag_type": TAG, "tag": 7}),
        (
            "etype",
            SequenceOfEnctype,
            {"tag_type": TAG, "tag": 8},
        ),  # -- EncryptionType,preference order
        ("addresses", HostAddresses, {"tag_type": TAG, "tag": 9, "optional": True}),
        (
            "enc-authorization-data",
            EncryptedData,
            {"tag_type": TAG, "tag": 10, "optional": True},
        ),  # -- Encrypted AuthorizationData encoding
        (
            "additional-tickets",
            SequenceOfTicket,
            {"tag_type": TAG, "tag": 11, "optional": True},
        ),
    ]


class KDC_REQ(core.Sequence):
    _fields = [
        ("pvno", krb5int32, {"tag_type": TAG, "tag": 1}),
        ("msg-type", krb5int32, {"tag_type": TAG, "tag": 2}),  # MESSAGE_TYPE
        ("padata", METHOD_DATA, {"tag_type": TAG, "tag": 3, "optional": True}),
        ("req-body", KDC_REQ_BODY, {"tag_type": TAG, "tag": 4}),
    ]


class AS_REQ(KDC_REQ):
    explicit = (APPLICATION, 10)


class TGS_REQ(KDC_REQ):
    explicit = (APPLICATION, 12)


class FastOptions(core.BitString):
    _map = {
        0: "reserved",
        1: "hide-client-names",
        2: "critical_2",  # forwarded',
        3: "critical_3",  # proxiable',
        4: "critical_4",  # proxy',
        5: "critical_5",  # may-postdate',
        6: "critical_6",  # postdated',
        7: "critical_7",  # invalid',
        8: "critical_8",  # renewable',
        9: "critical_9",  # initial',
        10: "critical_10",  # pre-authent',
        11: "critical_11",  # hw-authent',
        12: "critical_12",  # transited-policy-checked',
        13: "critical_13",  # ok-as-delegate',
        14: "critical_14",  # anonymous',
        15: "critical_15",  # enc-pa-rep',
        16: "kdc-follow-referrals",
    }
    # error: KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS   93


# 5.4.1.  FAST Armors


class EncryptedChallenge(EncryptedData):
    pass


class AUTHENTICATION_SET_ELEM(core.SequenceOf):
    _fields = [
        ("pa-type", krb5int32, {"tag_type": TAG, "tag": 0}),
        ("pa-hint", core.OctetString, {"tag_type": TAG, "tag": 1, "optional": True}),
        ("pa-value", core.OctetString, {"tag_type": TAG, "tag": 1, "optional": True}),
    ]


class AUTHENTICATION_SET(core.SequenceOf):
    _child_spec = AUTHENTICATION_SET_ELEM


class KrbFastArmor(core.Sequence):
    _fields = [
        ("armor-type", krb5int32, {"tag_type": TAG, "tag": 0}),
        ("armor-value", core.OctetString, {"tag_type": TAG, "tag": 1}),
    ]


class KrbFastArmoredReq(core.Sequence):
    _fields = [
        ("armor", KrbFastArmor, {"tag_type": TAG, "tag": 0, "optional": True}),
        ("req-checksum", Checksum, {"tag_type": TAG, "tag": 1}),
        (
            "enc-fast-req",
            EncryptedData,
            {"tag_type": TAG, "tag": 2},
        ),  # KrbFastReq #KEY_USAGE_FAST_REQ_CHKSUM          50 #KEY_USAGE_FAST_ENC                 51
    ]


class KrbFastReq(core.Sequence):
    _fields = [
        ("fast-options", FastOptions, {"tag_type": TAG, "tag": 0}),
        ("padata", METHOD_DATA, {"tag_type": TAG, "tag": 1}),
        ("req-body", KDC_REQ_BODY, {"tag_type": TAG, "tag": 2}),
    ]


class KrbFastFinished(core.Sequence):
    _fields = [
        ("timestamp", KerberosTime, {"tag_type": TAG, "tag": 0}),
        ("usec", Microseconds, {"tag_type": TAG, "tag": 1}),
        ("crealm", Realm, {"tag_type": TAG, "tag": 2}),
        ("cname", PrincipalName, {"tag_type": TAG, "tag": 3}),
        (
            "ticket-checksum",
            Checksum,
            {"tag_type": TAG, "tag": 4},
        ),  # KEY_USAGE_FAST_FINISHED            53
    ]


class KrbFastArmoredRep(core.Sequence):
    _fields = [
        (
            "enc-fast-rep",
            EncryptedData,
            {"tag_type": TAG, "tag": 0},
        ),  # KrbFastResponse KEY_USAGE_FAST_REP                 52
    ]


class KrbFastResponse(core.Sequence):
    _fields = [
        ("padata", METHOD_DATA, {"tag_type": TAG, "tag": 0}),
        (
            "strengthen-key",
            EncryptionKey,
            {"tag_type": TAG, "tag": 1, "optional": True},
        ),
        (
            "finished",
            KrbFastFinished,
            {"tag_type": TAG, "tag": 2, "optional": True},
        ),  # KrbFastReq #KEY_USAGE_FAST_REQ_CHKSUM          50 #KEY_USAGE_FAST_ENC                 51
        ("nonce", krb5uint32, {"tag_type": TAG, "tag": 3}),
    ]


# -- padata-type ::= PA-ENC-TIMESTAMP
# -- padata-value ::= EncryptedData - PA-ENC-TS-ENC


class PA_PAC_OPTIONSTypes(core.BitString):
    _map = {
        0: "Claims",
        1: "Branch Aware",
        2: "Forward to Full DC",
        3: "resource-based constrained delegation",
    }


class PA_FX_FAST_REQUEST(core.Choice):
    _alternatives = [
        ("armored-data", KrbFastArmoredReq, {"explicit": (CONTEXT, 0)}),
    ]


class PA_FX_FAST_REPLY(core.Choice):
    _alternatives = [
        ("armored-data", KrbFastArmoredRep, {"explicit": (CONTEXT, 0)}),
    ]


class PA_PAC_OPTIONS(core.Sequence):
    _fields = [
        ("value", PA_PAC_OPTIONSTypes, {"tag_type": TAG, "tag": 0}),
    ]


class PA_ENC_TS_ENC(core.Sequence):
    _fields = [
        ("patimestamp", KerberosTime, {"tag_type": TAG, "tag": 0}),  # -- client's time
        ("pausec", krb5int32, {"tag_type": TAG, "tag": 1, "optional": True}),
    ]


# -- draft-brezak-win2k-krb-authz-01
class PA_PAC_REQUEST(core.Sequence):
    _fields = [
        (
            "include-pac",
            core.Boolean,
            {"tag_type": TAG, "tag": 0},
        ),  # -- Indicates whether a PAC should be included or not
    ]


# -- PacketCable provisioning server location, PKT-SP-SEC-I09-030728.pdf
class PROV_SRV_LOCATION(core.GeneralString):
    pass


class KDC_REP(core.Sequence):
    _fields = [
        ("pvno", core.Integer, {"tag_type": TAG, "tag": 0}),
        ("msg-type", krb5int32, {"tag_type": TAG, "tag": 1}),  # MESSAGE_TYPE
        ("padata", METHOD_DATA, {"tag_type": TAG, "tag": 2, "optional": True}),
        ("crealm", Realm, {"tag_type": TAG, "tag": 3}),
        ("cname", PrincipalName, {"tag_type": TAG, "tag": 4}),
        ("ticket", Ticket, {"tag_type": TAG, "tag": 5}),
        ("enc-part", EncryptedData, {"tag_type": TAG, "tag": 6}),  # EncKDCRepPart
    ]


class AS_REP(KDC_REP):
    #::= [APPLICATION 11] KDC-REP
    explicit = (APPLICATION, 11)


class TGS_REP(KDC_REP):  # ::= [APPLICATION 13] KDC-REP
    explicit = (APPLICATION, 13)


class EncKDCRepPart(core.Sequence):
    _fields = [
        ("key", EncryptionKey, {"tag_type": TAG, "tag": 0}),
        ("last-req", LastReq, {"tag_type": TAG, "tag": 1}),
        ("nonce", krb5int32, {"tag_type": TAG, "tag": 2}),
        ("key-expiration", KerberosTime, {"tag_type": TAG, "tag": 3, "optional": True}),
        ("flags", TicketFlags, {"tag_type": TAG, "tag": 4}),
        ("authtime", KerberosTime, {"tag_type": TAG, "tag": 5}),
        ("starttime", KerberosTime, {"tag_type": TAG, "tag": 6, "optional": True}),
        ("endtime", KerberosTime, {"tag_type": TAG, "tag": 7}),
        ("renew-till", KerberosTime, {"tag_type": TAG, "tag": 8, "optional": True}),
        ("srealm", Realm, {"tag_type": TAG, "tag": 9}),
        ("sname", PrincipalName, {"tag_type": TAG, "tag": 10}),
        ("caddr", HostAddresses, {"tag_type": TAG, "tag": 11, "optional": True}),
        (
            "encrypted-pa-data",
            METHOD_DATA,
            {"tag_type": TAG, "tag": 12, "optional": True},
        ),
    ]


class EncASRepPart(EncKDCRepPart):
    explicit = (APPLICATION, 25)


class EncTGSRepPart(EncKDCRepPart):
    explicit = (APPLICATION, 26)


class AP_REQ(core.Sequence):
    explicit = (APPLICATION, 14)
    _fields = [
        ("pvno", krb5int32, {"tag_type": TAG, "tag": 0}),
        ("msg-type", krb5int32, {"tag_type": TAG, "tag": 1}),  # MESSAGE_TYPE
        ("ap-options", APOptions, {"tag_type": TAG, "tag": 2}),
        ("ticket", Ticket, {"tag_type": TAG, "tag": 3}),
        ("authenticator", EncryptedData, {"tag_type": TAG, "tag": 4}),
    ]


class AP_REP(core.Sequence):
    explicit = (APPLICATION, 15)
    _fields = [
        ("pvno", krb5int32, {"tag_type": TAG, "tag": 0}),
        ("msg-type", krb5int32, {"tag_type": TAG, "tag": 1}),  # MESSAGE_TYPE
        ("enc-part", EncryptedData, {"tag_type": TAG, "tag": 2}),
    ]


class EncAPRepPart(core.Sequence):
    explicit = (APPLICATION, 27)
    _fields = [
        ("ctime", KerberosTime, {"tag_type": TAG, "tag": 0}),
        ("cusec", krb5int32, {"tag_type": TAG, "tag": 1}),
        ("subkey", EncryptionKey, {"tag_type": TAG, "tag": 2, "optional": True}),
        ("seq-number", krb5uint32, {"tag_type": TAG, "tag": 3, "optional": True}),
    ]


class KRB_SAFE_BODY(core.Sequence):
    _fields = [
        ("user-data", core.OctetString, {"tag_type": TAG, "tag": 0}),
        ("timestamp", KerberosTime, {"tag_type": TAG, "tag": 1, "optional": True}),
        ("usec", krb5int32, {"tag_type": TAG, "tag": 2, "optional": True}),
        ("seq-number", krb5uint32, {"tag_type": TAG, "tag": 3, "optional": True}),
        ("s-address", HostAddress, {"tag_type": TAG, "tag": 4, "optional": True}),
        ("r-address", HostAddress, {"tag_type": TAG, "tag": 5, "optional": True}),
    ]


class KRB_SAFE(core.Sequence):
    explicit = (APPLICATION, 20)
    _fields = [
        ("pvno", krb5int32, {"tag_type": TAG, "tag": 0}),
        ("msg-type", krb5int32, {"tag_type": TAG, "tag": 1}),  # MESSAGE_TYPE
        ("safe-body", KRB_SAFE_BODY, {"tag_type": TAG, "tag": 2}),
        ("cksum", Checksum, {"tag_type": TAG, "tag": 3}),
    ]


class KRB_PRIV(core.Sequence):
    explicit = (APPLICATION, 21)
    _fields = [
        ("pvno", krb5int32, {"tag_type": TAG, "tag": 0}),
        ("msg-type", krb5int32, {"tag_type": TAG, "tag": 1}),  # MESSAGE_TYPE
        ("enc-part", EncryptedData, {"tag_type": TAG, "tag": 2}),
    ]


class EncKrbPrivPart(core.Sequence):
    explicit = (APPLICATION, 28)
    _fields = [
        ("user-data", core.OctetString, {"tag_type": TAG, "tag": 0}),
        ("timestamp", KerberosTime, {"tag_type": TAG, "tag": 1, "optional": True}),
        ("usec", krb5int32, {"tag_type": TAG, "tag": 2, "optional": True}),
        ("seq-number", krb5uint32, {"tag_type": TAG, "tag": 3, "optional": True}),
        ("s-address", HostAddress, {"tag_type": TAG, "tag": 4, "optional": True}),
        ("r-address", HostAddress, {"tag_type": TAG, "tag": 5, "optional": True}),
    ]


class KRB_CRED(core.Sequence):
    explicit = (APPLICATION, 22)
    _fields = [
        ("pvno", core.Integer, {"tag_type": TAG, "tag": 0}),
        ("msg-type", core.Integer, {"tag_type": TAG, "tag": 1}),
        ("tickets", SequenceOfTicket, {"tag_type": TAG, "tag": 2}),
        ("enc-part", EncryptedData, {"tag_type": TAG, "tag": 3}),
    ]


# http://web.mit.edu/freebsd/head/crypto/heimdal/lib/asn1/krb5.asn1
class KrbCredInfo(core.Sequence):
    _fields = [
        ("key", EncryptionKey, {"tag_type": TAG, "tag": 0}),
        ("prealm", Realm, {"tag_type": TAG, "tag": 1, "optional": True}),
        ("pname", PrincipalName, {"tag_type": TAG, "tag": 2, "optional": True}),
        ("flags", TicketFlags, {"tag_type": TAG, "tag": 3, "optional": True}),
        ("authtime", KerberosTime, {"tag_type": TAG, "tag": 4, "optional": True}),
        ("starttime", KerberosTime, {"tag_type": TAG, "tag": 5, "optional": True}),
        ("endtime", KerberosTime, {"tag_type": TAG, "tag": 6, "optional": True}),
        ("renew-till", KerberosTime, {"tag_type": TAG, "tag": 7, "optional": True}),
        ("srealm", Realm, {"tag_type": TAG, "tag": 8, "optional": True}),
        ("sname", PrincipalName, {"tag_type": TAG, "tag": 9, "optional": True}),
        ("caddr", HostAddresses, {"tag_type": TAG, "tag": 10, "optional": True}),
    ]


class SequenceOfKrbCredInfo(core.SequenceOf):
    _child_spec = KrbCredInfo


class EncKrbCredPart(core.Sequence):
    explicit = (APPLICATION, 29)
    _fields = [
        ("ticket-info", SequenceOfKrbCredInfo, {"tag_type": TAG, "tag": 0}),
        ("nonce", krb5int32, {"tag_type": TAG, "tag": 1, "optional": True}),
        ("timestamp", KerberosTime, {"tag_type": TAG, "tag": 2, "optional": True}),
        ("usec", krb5int32, {"tag_type": TAG, "tag": 3, "optional": True}),
        ("s-address", HostAddress, {"tag_type": TAG, "tag": 4, "optional": True}),
        ("r-address", HostAddress, {"tag_type": TAG, "tag": 5, "optional": True}),
    ]


class KRB_ERROR(core.Sequence):
    explicit = (APPLICATION, 30)
    _fields = [
        ("pvno", krb5int32, {"tag_type": TAG, "tag": 0}),
        ("msg-type", krb5int32, {"tag_type": TAG, "tag": 1}),  # MESSAGE_TYPE
        ("ctime", KerberosTime, {"tag_type": TAG, "tag": 2, "optional": True}),
        ("cusec", krb5int32, {"tag_type": TAG, "tag": 3, "optional": True}),
        ("stime", KerberosTime, {"tag_type": TAG, "tag": 4}),
        ("susec", krb5int32, {"tag_type": TAG, "tag": 5}),
        ("error-code", krb5int32, {"tag_type": TAG, "tag": 6}),
        ("crealm", Realm, {"tag_type": TAG, "tag": 7, "optional": True}),
        ("cname", PrincipalName, {"tag_type": TAG, "tag": 8, "optional": True}),
        ("realm", Realm, {"tag_type": TAG, "tag": 9}),
        ("sname", PrincipalName, {"tag_type": TAG, "tag": 10}),
        ("e-text", core.GeneralString, {"tag_type": TAG, "tag": 11, "optional": True}),
        ("e-data", core.OctetString, {"tag_type": TAG, "tag": 12, "optional": True}),
    ]


class ChangePasswdDataMS(core.Sequence):
    _fields = [
        ("newpasswd", core.OctetString, {"tag_type": TAG, "tag": 0}),
        ("targname", PrincipalName, {"tag_type": TAG, "tag": 1, "optional": True}),
        ("targrealm", Realm, {"tag_type": TAG, "tag": 2, "optional": True}),
    ]


class EtypeList(core.SequenceOf):
    # -- the client's proposed enctype list in
    # -- decreasing preference order, favorite choice first
    _child_spec = ENCTYPE


class KerberosResponse(core.Choice):
    _alternatives = [
        ("AS_REP", AS_REP, {"implicit": (APPLICATION, 11)}),
        ("TGS_REP", TGS_REP, {"implicit": (APPLICATION, 13)}),
        ("KRB_ERROR", KRB_ERROR, {"implicit": (APPLICATION, 30)}),
    ]


class KRBCRED(core.Sequence):
    explicit = (APPLICATION, 22)

    _fields = [
        ("pvno", core.Integer, {"tag_type": TAG, "tag": 0}),
        ("msg-type", core.Integer, {"tag_type": TAG, "tag": 1}),
        ("tickets", SequenceOfTicket, {"tag_type": TAG, "tag": 2}),
        ("enc-part", EncryptedData, {"tag_type": TAG, "tag": 3}),
    ]


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/aceb70de-40f0-4409-87fa-df00ca145f5a
# other name: PA-S4U2Self
class PA_FOR_USER_ENC(core.Sequence):
    _fields = [
        ("userName", PrincipalName, {"tag_type": TAG, "tag": 0}),
        ("userRealm", Realm, {"tag_type": TAG, "tag": 1}),
        ("cksum", Checksum, {"tag_type": TAG, "tag": 2}),
        ("auth-package", KerberosString, {"tag_type": TAG, "tag": 3}),
    ]


class S4UUserIDOptions(core.BitString):
    _map = {
        0x40000000: "check-logon-hour",  # This option causes the KDC to check logon hour restrictions for the user.
        0x20000000: "signed-with-kun-27",  # In a request, asks the KDC to sign the reply with key usage number 27. In a reply, indicates that it was signed with key usage number 27.
    }


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/cd9d5ca7-ce20-4693-872b-2f5dd41cbff6
class S4UUserID(core.Sequence):
    _fields = [
        (
            "nonce",
            core.Integer,
            {"tag_type": TAG, "tag": 0},
        ),  # -- the nonce in KDC-REQ-BODY
        ("cname", PrincipalName, {"tag_type": TAG, "tag": 1, "optional": True}),
        # -- Certificate mapping hints
        ("crealm", Realm, {"tag_type": TAG, "tag": 2}),
        (
            "subject-certificate",
            core.OctetString,
            {"tag_type": TAG, "tag": 3, "optional": True},
        ),
        ("options", S4UUserIDOptions, {"tag_type": TAG, "tag": 4, "optional": True}),
    ]


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/cd9d5ca7-ce20-4693-872b-2f5dd41cbff6
class PA_S4U_X509_USER(core.Sequence):
    _fields = [
        ("user-id", S4UUserID, {"tag_type": TAG, "tag": 0}),
        ("checksum", Checksum, {"tag_type": TAG, "tag": 1}),
    ]


class AD_IF_RELEVANT(AuthorizationData):
    pass


class GSSAPIOID(core.ObjectIdentifier):
    _map = {
        "1.2.840.113554.1.2.2": "krb5",
    }

    _reverse_map = {
        "krb5": "1.2.840.113554.1.2.2",
    }


class GSSAPIToken(core.Asn1Value):
    class_ = 1
    tag = 0
    method = 1


class MechType(core.ObjectIdentifier):
    _map = {
        #'': 'SNMPv2-SMI::enterprises.311.2.2.30',
        "1.3.6.1.4.1.311.2.2.10": "NTLMSSP - Microsoft NTLM Security Support Provider",
        "1.2.840.48018.1.2.2": "MS KRB5 - Microsoft Kerberos 5",
        "1.2.840.113554.1.2.2": "KRB5 - Kerberos 5",
        "1.2.840.113554.1.2.2.3": "KRB5 - Kerberos 5 - User to User",
        "1.3.6.1.4.1.311.2.2.30": "NEGOEX - SPNEGO Extended Negotiation Security Mechanism",
    }


class InitialContextToken(core.Sequence):
    class_ = 1
    tag = 0
    _fields = [
        ("thisMech", MechType, {"optional": False}),
        ("unk_bool", core.Boolean, {"optional": False}),
        ("innerContextToken", core.Any, {"optional": False}),
    ]

    _oid_pair = ("thisMech", "innerContextToken")
    _oid_specs = {
        "KRB5 - Kerberos 5": AP_REQ,
    }


# https://tools.ietf.org/html/rfc4121#section-4.1.1.1
class ChecksumFlags(enum.IntFlag):
    GSS_C_DELEG_FLAG = 1
    GSS_C_MUTUAL_FLAG = 2
    GSS_C_REPLAY_FLAG = 4
    GSS_C_SEQUENCE_FLAG = 8
    GSS_C_CONF_FLAG = 16
    GSS_C_INTEG_FLAG = 32
    GSS_C_DCE_STYLE = 0x1000


# https://tools.ietf.org/html/rfc4121#section-4.1.1
class AuthenticatorChecksum:
    def __init__(self):
        self.length_of_binding = None
        self.channel_binding = None  # MD5 hash of gss_channel_bindings_struct
        self.flags = None  # ChecksumFlags
        self.delegation = None
        self.delegation_length = None
        self.delegation_data = None
        self.extensions = None

    @staticmethod
    def from_bytes(data):
        return AuthenticatorChecksum.from_buffer(io.BytesIO(data))

    @staticmethod
    def from_buffer(buffer):
        ac = AuthenticatorChecksum()
        ac.length_of_binding = int.from_bytes(
            buffer.read(4), byteorder="little", signed=False
        )
        ac.channel_binding = buffer.read(
            ac.length_of_binding
        )  # according to the latest RFC this is 16 bytes long always
        ac.flags = ChecksumFlags(
            int.from_bytes(buffer.read(4), byteorder="little", signed=False)
        )
        if ac.flags & ChecksumFlags.GSS_C_DELEG_FLAG:
            ac.delegation = bool(
                int.from_bytes(buffer.read(2), byteorder="little", signed=False)
            )
            ac.delegation_length = int.from_bytes(
                buffer.read(2), byteorder="little", signed=False
            )
            ac.delegation_data = buffer.read(ac.delegation_length)
        ac.extensions = buffer.read()
        return ac

    def to_bytes(self):
        t = len(self.channel_binding).to_bytes(4, byteorder="little", signed=False)
        t += self.channel_binding
        t += self.flags.to_bytes(4, byteorder="little", signed=False)
        if self.flags & ChecksumFlags.GSS_C_DELEG_FLAG:
            t += int(self.delegation).to_bytes(2, byteorder="little", signed=False)
            t += len(self.delegation_data.to_bytes()).to_bytes(
                2, byteorder="little", signed=False
            )
            t += self.delegation_data.to_bytes()
        if self.extensions:
            t += self.extensions.to_bytes()
        return t
