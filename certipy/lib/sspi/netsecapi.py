import enum
import io
from ctypes import (
    POINTER,
    Structure,
    WinError,
    addressof,
    byref,
    c_byte,
    c_char,
    c_char_p,
    c_int16,
    c_int32,
    c_longlong,
    c_ubyte,
    c_uint16,
    c_uint32,
    c_void_p,
    c_wchar_p,
    cast,
    create_string_buffer,
    pointer,
    sizeof,
    string_at,
    windll,
)

BYTE = c_ubyte
UCHAR = BYTE
SHORT = c_int16
USHORT = c_uint16
LONG = c_int32
LPWSTR = c_wchar_p
LPVOID = c_void_p
PVOID = LPVOID
PPVOID = POINTER(PVOID)
DWORD = c_uint32
HANDLE = LPVOID
PHANDLE = POINTER(HANDLE)
LPHANDLE = PHANDLE
NTSTATUS = LONG
PNTSTATUS = POINTER(NTSTATUS)
USHORT = c_uint16
ULONG = c_uint32
PULONG = POINTER(ULONG)
LARGE_INTEGER = c_longlong
PLARGE_INTEGER = POINTER(LARGE_INTEGER)
LPBYTE = POINTER(BYTE)
LPSTR = c_char_p
CHAR = c_char

LSA_OPERATIONAL_MODE = ULONG
PLSA_OPERATIONAL_MODE = POINTER(LSA_OPERATIONAL_MODE)
PCHAR = LPSTR
SEC_CHAR = CHAR
PSEC_CHAR = PCHAR


ERROR_SUCCESS = 0

maxtoken_size = 2880


class SID:
    def __init__(self):
        self.Revision = None
        self.SubAuthorityCount = None
        self.IdentifierAuthority = None
        self.SubAuthority = []

    def __str__(self):
        t = "S-1-"
        if self.IdentifierAuthority < 2**32:
            t += str(self.IdentifierAuthority)
        else:
            t += "0x" + self.IdentifierAuthority.to_bytes(6, "big").hex().upper().rjust(
                12, "0"
            )
        for i in self.SubAuthority:
            t += "-" + str(i)
        return t

    @staticmethod
    def from_ptr(ptr):
        if ptr == None:
            return None
        data = string_at(ptr, 8)
        buff = io.BytesIO(data)
        sid = SID()
        sid.Revision = int.from_bytes(buff.read(1), "little", signed=False)
        sid.SubAuthorityCount = int.from_bytes(buff.read(1), "little", signed=False)
        sid.IdentifierAuthority = int.from_bytes(buff.read(6), "big", signed=False)

        data = string_at(ptr + 8, sid.SubAuthorityCount * 4)
        buff = io.BytesIO(data)
        for _ in range(sid.SubAuthorityCount):
            sid.SubAuthority.append(
                int.from_bytes(buff.read(4), "little", signed=False)
            )
        return sid


class KERB_PROTOCOL_MESSAGE_TYPE(enum.Enum):
    KerbDebugRequestMessage = 0
    KerbQueryTicketCacheMessage = 1
    KerbChangeMachinePasswordMessage = 2
    KerbVerifyPacMessage = 3
    KerbRetrieveTicketMessage = 4
    KerbUpdateAddressesMessage = 5
    KerbPurgeTicketCacheMessage = 6
    KerbChangePasswordMessage = 7
    KerbRetrieveEncodedTicketMessage = 8
    KerbDecryptDataMessage = 9
    KerbAddBindingCacheEntryMessage = 10
    KerbSetPasswordMessage = 11
    KerbSetPasswordExMessage = 12
    KerbVerifyCredentialsMessage = 13
    KerbQueryTicketCacheExMessage = 14
    KerbPurgeTicketCacheExMessage = 15
    KerbRefreshSmartcardCredentialsMessage = 16
    KerbAddExtraCredentialsMessage = 17
    KerbQuerySupplementalCredentialsMessage = 18
    KerbTransferCredentialsMessage = 19
    KerbQueryTicketCacheEx2Message = 20
    KerbSubmitTicketMessage = 21
    KerbAddExtraCredentialsExMessage = 22
    KerbQueryKdcProxyCacheMessage = 23
    KerbPurgeKdcProxyCacheMessage = 24
    KerbQueryTicketCacheEx3Message = 25
    KerbCleanupMachinePkinitCredsMessage = 26
    KerbAddBindingCacheEntryExMessage = 27
    KerbQueryBindingCacheMessage = 28
    KerbPurgeBindingCacheMessage = 29
    KerbQueryDomainExtendedPoliciesMessage = 30
    KerbQueryS4U2ProxyCacheMessage = 31


# https://apidock.com/ruby/Win32/SSPI/SSPIResult
class SEC_E(enum.Enum):
    OK = 0x00000000
    CONTINUE_NEEDED = 0x00090312
    INSUFFICIENT_MEMORY = (
        0x80090300  # Not enough memory is available to complete this request.
    )
    INVALID_HANDLE = 0x80090301  # The handle specified is invalid.
    UNSUPPORTED_FUNCTION = 0x80090302  # The function requested is not supported.
    TARGET_UNKNOWN = 0x80090303  # The specified target is unknown or unreachable.
    INTERNAL_ERROR = (
        0x80090304  # The Local Security Authority (LSA) cannot be contacted.
    )
    SECPKG_NOT_FOUND = 0x80090305  # The requested security package does not exist.
    NOT_OWNER = 0x80090306  # The caller is not the owner of the desired credentials.
    CANNOT_INSTALL = (
        0x80090307  # The security package failed to initialize and cannot be installed.
    )
    INVALID_TOKEN = 0x80090308  # The token supplied to the function is invalid.
    CANNOT_PACK = 0x80090309  # The security package is not able to marshal the logon buffer, so the logon attempt has failed.
    QOP_NOT_SUPPORTED = 0x8009030A  # The per-message quality of protection is not supported by the security package.
    NO_IMPERSONATION = (
        0x8009030B  # The security context does not allow impersonation of the client.
    )
    LOGON_DENIED = 0x8009030C  # The logon attempt failed.
    UNKNOWN_CREDENTIALS = (
        0x8009030D  # The credentials supplied to the package were not recognized.
    )
    NO_CREDENTIALS = 0x8009030E  # No credentials are available in the security package.
    MESSAGE_ALTERED = 0x8009030F  # The message or signature supplied for verification has been altered.
    OUT_OF_SEQUENCE = (
        0x80090310  # The message supplied for verification is out of sequence.
    )
    NO_AUTHENTICATING_AUTHORITY = (
        0x80090311  # No authority could be contacted for authentication.
    )
    BAD_PKGID = 0x80090316  # The requested security package does not exist.
    CONTEXT_EXPIRED = 0x80090317  # The context has expired and can no longer be used.
    INCOMPLETE_MESSAGE = 0x80090318  # The supplied message is incomplete. The signature was not verified.
    INCOMPLETE_CREDENTIALS = 0x80090320  # The credentials supplied were not complete and could not be verified. The context could not be initialized.
    BUFFER_TOO_SMALL = 0x80090321  # The buffers supplied to a function was too small.
    WRONG_PRINCIPAL = 0x80090322  # The target principal name is incorrect.
    TIME_SKEW = 0x80090324  # The clocks on the client and server machines are skewed.
    UNTRUSTED_ROOT = 0x80090325  # The certificate chain was issued by an authority that is not trusted.
    ILLEGAL_MESSAGE = (
        0x80090326  # The message received was unexpected or badly formatted.
    )
    CERT_UNKNOWN = (
        0x80090327  # An unknown error occurred while processing the certificate.
    )
    CERT_EXPIRED = 0x80090328  # The received certificate has expired.
    ENCRYPT_FAILURE = 0x80090329  # The specified data could not be encrypted.
    DECRYPT_FAILURE = 0x80090330  # The specified data could not be decrypted.
    ALGORITHM_MISMATCH = 0x80090331  # The client and server cannot communicate because they do not possess a common algorithm.
    SECURITY_QOS_FAILED = 0x80090332  # The security context could not be established due to a failure in the requested quality of service (for example, mutual authentication or delegation).
    UNFINISHED_CONTEXT_DELETED = 0x80090333  # A security context was deleted before the context was completed. This is considered a logon failure.
    NO_TGT_REPLY = 0x80090334  # The client is trying to negotiate a context and the server requires user-to-user but did not send a ticket granting ticket (TGT) reply.
    NO_IP_ADDRESSES = 0x80090335  # Unable to accomplish the requested task because the local machine does not have an IP addresses.
    WRONG_CREDENTIAL_HANDLE = 0x80090336  # The supplied credential handle does not match the credential associated with the security context.
    CRYPTO_SYSTEM_INVALID = 0x80090337  # The cryptographic system or checksum function is invalid because a required function is unavailable.
    MAX_REFERRALS_EXCEEDED = (
        0x80090338  # The number of maximum ticket referrals has been exceeded.
    )
    MUST_BE_KDC = 0x80090339  # The local machine must be a Kerberos domain controller (KDC), and it is not.
    STRONG_CRYPTO_NOT_SUPPORTED = 0x8009033A  # The other end of the security negotiation requires strong cryptographics, but it is not supported on the local machine.
    TOO_MANY_PRINCIPALS = (
        0x8009033B  # The KDC reply contained more than one principal name.
    )
    NO_PA_DATA = 0x8009033C  # Expected to find PA data for a hint of what etype to use, but it was not found.
    PKINIT_NAME_MISMATCH = 0x8009033D  # The client certificate does not contain a valid user principal name (UPN), or does not match the client name in the logon request. Contact your administrator.
    SMARTCARD_LOGON_REQUIRED = (
        0x8009033E  # Smart card logon is required and was not used.
    )
    SHUTDOWN_IN_PROGRESS = 0x8009033F  # A system shutdown is in progress.
    KDC_INVALID_REQUEST = 0x80090340  # An invalid request was sent to the KDC.
    KDC_UNABLE_TO_REFER = 0x80090341  # The KDC was unable to generate a referral for the service requested.
    KDC_UNKNOWN_ETYPE = (
        0x80090342  # The encryption type requested is not supported by the KDC.
    )
    UNSUPPORTED_PREAUTH = 0x80090343  # An unsupported pre-authentication mechanism was presented to the Kerberos package.
    DELEGATION_REQUIRED = 0x80090345  # The requested operation cannot be completed. The computer must be trusted for delegation, and the current user account must be configured to allow delegation.
    BAD_BINDINGS = 0x80090346  # Client's supplied Security Support Provider Interface (SSPI) channel bindings were incorrect.
    MULTIPLE_ACCOUNTS = (
        0x80090347  # The received certificate was mapped to multiple accounts.
    )
    NO_KERB_KEY = 0x80090348  # No Kerberos key was found.
    CERT_WRONG_USAGE = (
        0x80090349  # The certificate is not valid for the requested usage.
    )
    DOWNGRADE_DETECTED = 0x80090350  # The system detected a possible attempt to compromise security. Ensure that you can contact the server that authenticated you.
    SMARTCARD_CERT_REVOKED = 0x80090351  # The smart card certificate used for authentication has been revoked. Contact your system administrator. The event log might contain additional information.
    ISSUING_CA_UNTRUSTED = 0x80090352  # An untrusted certification authority (CA) was detected while processing the smart card certificate used for authentication. Contact your system administrator.
    REVOCATION_OFFLINE_C = 0x80090353  # The revocation status of the smart card certificate used for authentication could not be determined. Contact your system administrator.
    PKINIT_CLIENT_FAILURE = 0x80090354  # The smart card certificate used for authentication was not trusted. Contact your system administrator.
    SMARTCARD_CERT_EXPIRED = 0x80090355  # The smart card certificate used for authentication has expired. Contact your system administrator.
    NO_S4U_PROT_SUPPORT = 0x80090356  # The Kerberos subsystem encountered an error. A service for user protocol requests was made against a domain controller that does not support services for users.
    CROSSREALM_DELEGATION_FAILURE = 0x80090357  # An attempt was made by this server to make a Kerberos-constrained delegation request for a target outside the server's realm. This is not supported and indicates a misconfiguration on this server's allowed-to-delegate-to list. Contact your administrator.
    REVOCATION_OFFLINE_KDC = 0x80090358  # The revocation status of the domain controller certificate used for smart card authentication could not be determined. The system event log contains additional information. Contact your system administrator.
    ISSUING_CA_UNTRUSTED_KDC = 0x80090359  # An untrusted CA was detected while processing the domain controller certificate used for authentication. The system event log contains additional information. Contact your system administrator.
    KDC_CERT_EXPIRED = 0x8009035A  # The domain controller certificate used for smart card logon has expired. Contact your system administrator with the contents of your system event log.
    KDC_CERT_REVOKED = 0x8009035B  # The domain controller certificate used for smart card logon has been revoked. Contact your system administrator with the contents of your system event log.
    INVALID_PARAMETER = (
        0x8009035D  # One or more of the parameters passed to the function were invalid.
    )
    DELEGATION_POLICY = 0x8009035E  # The client policy does not allow credential delegation to the target server.
    POLICY_NLTM_ONLY = 0x8009035F  # The client policy does not allow credential delegation to the target server with NLTM only authentication.
    RENEGOTIATE = 590625
    COMPLETE_AND_CONTINUE = 590612
    COMPLETE_NEEDED = 590611
    # INCOMPLETE_CREDENTIALS = 590624


class SECPKG_CRED(enum.IntFlag):
    AUTOLOGON_RESTRICTED = 0x00000010  # The security does not use default logon credentials or credentials from Credential Manager.
    # This value is supported only by the Negotiate security package.
    # Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP:  This value is not supported.

    BOTH = 3  # Validate an incoming credential or use a local credential to prepare an outgoing token. This flag enables both other flags. This flag is not valid with the Digest and Schannel SSPs.
    INBOUND = 1  # Validate an incoming server credential. Inbound credentials might be validated by using an authenticating authority when InitializeSecurityContext (General) or AcceptSecurityContext (General) is called. If such an authority is not available, the function will fail and return SEC_E_NO_AUTHENTICATING_AUTHORITY. Validation is package specific.
    OUTBOUND = 2  # Allow a local client credential to prepare an outgoing token.
    PROCESS_POLICY_ONLY = 0x00000020  # The function processes server policy and returns SEC_E_NO_CREDENTIALS, indicating that the application should prompt for credentials.
    # This value is supported only by the Negotiate security package.
    # Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP:  This value is not supported.


class ISC_REQ(enum.IntFlag):
    DELEGATE = 1
    MUTUAL_AUTH = 2
    REPLAY_DETECT = 4
    SEQUENCE_DETECT = 8
    CONFIDENTIALITY = 16
    USE_SESSION_KEY = 32
    PROMPT_FOR_CREDS = 64
    USE_SUPPLIED_CREDS = 128
    ALLOCATE_MEMORY = 256
    USE_DCE_STYLE = 512
    DATAGRAM = 1024
    CONNECTION = 2048
    CALL_LEVEL = 4096
    FRAGMENT_SUPPLIED = 8192
    EXTENDED_ERROR = 16384
    STREAM = 32768
    INTEGRITY = 65536
    IDENTIFY = 131072
    NULL_SESSION = 262144
    MANUAL_CRED_VALIDATION = 524288
    RESERVED1 = 1048576
    FRAGMENT_TO_FIT = 2097152
    HTTP = 0x10000000


class SECPKG_ATTR(enum.Enum):
    SESSION_KEY = 9
    C_ACCESS_TOKEN = 0x80000012  # The pBuffer parameter contains a pointer to a SecPkgContext_AccessToken structure that specifies the access token for the current security context. This attribute is supported only on the server.
    C_FULL_ACCESS_TOKEN = 0x80000082  # The pBuffer parameter contains a pointer to a SecPkgContext_AccessToken structure that specifies the access token for the current security context. This attribute is supported only on the server.
    CERT_TRUST_STATUS = 0x80000084  # The pBuffer parameter contains a pointer to a CERT_TRUST_STATUS structure that specifies trust information about the certificate.This attribute is supported only on the client.
    CREDS = 0x80000080  # The pBuffer parameter contains a pointer to a SecPkgContext_ClientCreds structure that specifies client credentials. The client credentials can be either user name and password or user name and smart card PIN. This attribute is supported only on the server.
    CREDS_2 = 0x80000086  # The pBuffer parameter contains a pointer to a SecPkgContext_ClientCreds structure that specifies client credentials. If the client credential is user name and password, the buffer is a packed KERB_INTERACTIVE_LOGON structure. If the client credential is user name and smart card PIN, the buffer is a packed KERB_CERTIFICATE_LOGON structure. If the client credential is an online identity credential, the buffer is a marshaled SEC_WINNT_AUTH_IDENTITY_EX2 structure. This attribute is supported only on the CredSSP server. Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP:  This value is not supported.
    NEGOTIATION_PACKAGE = 0x80000081  # The pBuffer parameter contains a pointer to a SecPkgContext_PackageInfo structure that specifies the name of the authentication package negotiated by the Microsoft Negotiate provider.
    PACKAGE_INFO = 10  # The pBuffer parameter contains a pointer to a SecPkgContext_PackageInfostructure.Returns information on the SSP in use.
    SERVER_AUTH_FLAGS = 0x80000083  # The pBuffer parameter contains a pointer to a SecPkgContext_Flags structure that specifies information about the flags in the current security context. This attribute is supported only on the client.
    SIZES = 0x0  # The pBuffer parameter contains a pointer to a SecPkgContext_Sizes structure. Queries the sizes of the structures used in the per-message functions and authentication exchanges.
    SUBJECT_SECURITY_ATTRIBUTES = 124  # 	The pBuffer parameter contains a pointer to a SecPkgContext_SubjectAttributes structure. This value returns information about the security attributes for the connection. This value is supported only on the CredSSP server. Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP:  This value is not supported.
    ENDPOINT_BINDINGS = 26


# https://docs.microsoft.com/en-us/windows/desktop/api/sspi/ns-sspi-_secbuffer
class SECBUFFER_TYPE(enum.Enum):
    SECBUFFER_ALERT = 17  # The buffer contains an alert message.
    SECBUFFER_ATTRMASK = 4026531840  # The buffer contains a bitmask for a SECBUFFER_READONLY_WITH_CHECKSUM buffer.
    SECBUFFER_CHANNEL_BINDINGS = 14  # 	The buffer contains channel binding information.
    SECBUFFER_CHANGE_PASS_RESPONSE = (
        15  # The buffer contains a DOMAIN_PASSWORD_INFORMATION structure.
    )
    SECBUFFER_DATA = 1  # The buffer contains common data. The security package can read and write this data, for example, to encrypt some or all of it.
    SECBUFFER_DTLS_MTU = 24  # The buffer contains the setting for the maximum transmission unit (MTU) size for DTLS only. The default value is 1096 and the valid configurable range is between 200 and 64*1024.
    SECBUFFER_EMPTY = 0  # This is a placeholder in the buffer array. The caller can supply several such entries in the array, and the security package can return information in them. For more information, see SSPI Context Semantics.
    SECBUFFER_EXTRA = 5  # The security package uses this value to indicate the number of extra or unprocessed bytes in a message.
    SECBUFFER_MECHLIST = 11  # The buffer contains a protocol-specific list of object identifiers (OIDs). It is not usually of interest to callers.
    SECBUFFER_MECHLIST_SIGNATURE = 12  # The buffer contains a signature of a SECBUFFER_MECHLIST buffer. It is not usually of interest to callers.
    SECBUFFER_MISSING = 4  # The security package uses this value to indicate the number of missing bytes in a particular message. The pvBuffer member is ignored in this type.
    SECBUFFER_PKG_PARAMS = 3  # These are transport-to-package–specific parameters. For example, the NetWare redirector may supply the server object identifier, while DCE RPC can supply an association UUID, and so on.
    SECBUFFER_PRESHARED_KEY = 22  # The buffer contains the preshared key. The maximum allowed PSK buffer size is 256 bytes.
    SECBUFFER_PRESHARED_KEY_IDENTITY = (
        23  # The buffer contains the preshared key identity.
    )
    SECBUFFER_SRTP_MASTER_KEY_IDENTIFIER = (
        20  # The buffer contains the SRTP master key identifier.
    )
    SECBUFFER_SRTP_PROTECTION_PROFILES = 19  # The buffer contains the list of SRTP protection profiles, in descending order of preference.
    SECBUFFER_STREAM_HEADER = 7  # The buffer contains a protocol-specific header for a particular record. It is not usually of interest to callers.
    SECBUFFER_STREAM_TRAILER = 6  # The buffer contains a protocol-specific trailer for a particular record. It is not usually of interest to callers.
    SECBUFFER_TARGET = 13  # This flag is reserved. Do not use it.
    SECBUFFER_TARGET_HOST = (
        16  # The buffer specifies the service principal name (SPN) of the target.
    )
    # This value is supported by the Digest security package when used with channel bindings.
    # Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP:  This value is not supported.
    SECBUFFER_TOKEN = 2  # The buffer contains the security token portion of the message. This is read-only for input parameters or read/write for output parameters.
    SECBUFFER_TOKEN_BINDING = 21  # The buffer contains the supported token binding protocol version and key parameters, in descending order of preference.
    SECBUFFER_APPLICATION_PROTOCOLS = 18  # The buffer contains a list of application protocol IDs, one list per application protocol negotiation extension type to be enabled.
    SECBUFFER_PADDING = 9


class FILETIME(Structure):
    _fields_ = [
        ("dwLowDateTime", DWORD),
        ("dwHighDateTime", DWORD),
    ]


PFILETIME = POINTER(FILETIME)
TimeStamp = FILETIME
PTimeStamp = PFILETIME

# https://docs.microsoft.com/en-us/windows/desktop/api/sspi/ns-sspi-secpkgcontext_sessionkey
class SecPkgContext_SessionKey(Structure):
    _fields_ = [("SessionKeyLength", ULONG), ("SessionKey", LPBYTE)]

    @property
    def Buffer(self):
        return string_at(self.SessionKey, size=self.SessionKeyLength)


# https://github.com/benjimin/pywebcorp/blob/master/pywebcorp/ctypes_sspi.py
class SecHandle(Structure):

    _fields_ = [("dwLower", POINTER(ULONG)), ("dwUpper", POINTER(ULONG))]

    def __init__(
        self,
    ):  # populate deeply (empty memory fields) rather than shallow null POINTERs.
        super(SecHandle, self).__init__(pointer(ULONG()), pointer(ULONG()))


class SecBuffer(Structure):
    """Stores a memory buffer: size, type-flag, and POINTER.
    The type can be empty (0) or token (2).
    InitializeSecurityContext will write to the buffer that is flagged "token"
    and update the size, or else fail 0x80090321=SEC_E_BUFFER_TOO_SMALL."""

    _fields_ = [("cbBuffer", ULONG), ("BufferType", ULONG), ("pvBuffer", PVOID)]

    def __init__(
        self, token=b"\x00" * maxtoken_size, buffer_type=SECBUFFER_TYPE.SECBUFFER_TOKEN
    ):
        buf = create_string_buffer(token, size=len(token))
        Structure.__init__(
            self, sizeof(buf), buffer_type.value, cast(byref(buf), PVOID)
        )

    @property
    def Buffer(self):
        return (
            SECBUFFER_TYPE(self.BufferType),
            string_at(self.pvBuffer, size=self.cbBuffer),
        )


class SecBufferDesc(Structure):
    """Descriptor stores SECBUFFER_VERSION=0, number of buffers (e.g. one),
    and POINTER to an array of SecBuffer structs."""

    _fields_ = [
        ("ulVersion", ULONG),
        ("cBuffers", ULONG),
        ("pBuffers", POINTER(SecBuffer)),
    ]

    def __init__(self, secbuffers=None):
        # secbuffers = a list of security buffers (SecBuffer)
        if secbuffers is not None:
            Structure.__init__(
                self, 0, len(secbuffers), (SecBuffer * len(secbuffers))(*secbuffers)
            )
        else:
            Structure.__init__(self, 0, 1, pointer(SecBuffer()))

    def __getitem__(self, index):
        return self.pBuffers[index]

    @property
    def Buffers(self):
        data = []
        for i in range(self.cBuffers):
            data.append(self.pBuffers[i].Buffer)
        return data


PSecBufferDesc = POINTER(SecBufferDesc)

PSecHandle = POINTER(SecHandle)
CredHandle = SecHandle
PCredHandle = PSecHandle
CtxtHandle = SecHandle
PCtxtHandle = PSecHandle


class LUID(Structure):
    _fields_ = [
        ("LowPart", DWORD),
        ("HighPart", LONG),
    ]

    def to_int(self):
        return LUID.luid_to_int(self)

    @staticmethod
    def luid_to_int(luid):
        return (luid.HighPart << 32) + luid.LowPart

    @staticmethod
    def from_int(i):
        luid = LUID()
        luid.HighPart = i >> 32
        luid.LowPart = i & 0xFFFFFFFF
        return luid


PLUID = POINTER(LUID)


class LSA_STRING(Structure):
    _fields_ = [
        ("Length", USHORT),
        ("MaximumLength", USHORT),
        ("Buffer", POINTER(c_char)),
    ]

    def to_string(self):
        return string_at(self.Buffer, self.MaximumLength).decode()


PLSA_STRING = POINTER(LSA_STRING)


class LSA_UNICODE_STRING(Structure):
    _fields_ = [
        ("Length", USHORT),
        ("MaximumLength", USHORT),
        ("Buffer", POINTER(c_char)),
    ]

    @staticmethod
    def from_string(s):
        s = s.encode("utf-16-le")
        lus = LSA_UNICODE_STRING()
        lus.Buffer = create_string_buffer(s, len(s))
        lus.MaximumLength = len(s) + 1
        lus.Length = len(s)
        return lus

    def to_string(self):
        return (
            string_at(self.Buffer, self.MaximumLength)
            .decode("utf-16-le")
            .replace("\x00", "")
        )


PLSA_UNICODE_STRING = POINTER(LSA_UNICODE_STRING)


class LSA_LAST_INTER_LOGON_INFO(Structure):
    _fields_ = [
        ("LastSuccessfulLogon", LARGE_INTEGER),
        ("LastFailedLogon", LARGE_INTEGER),
        ("FailedAttemptCountSinceLastSuccessfulLogon", ULONG),
    ]

    def to_dict(self):
        return {
            "LastSuccessfulLogon": self.LastSuccessfulLogon,
            "LastFailedLogon": self.LastFailedLogon,
            "FailedAttemptCountSinceLastSuccessfulLogon": self.FailedAttemptCountSinceLastSuccessfulLogon,
        }


PLSA_LAST_INTER_LOGON_INFO = POINTER(LSA_LAST_INTER_LOGON_INFO)


class SECURITY_LOGON_SESSION_DATA(Structure):
    _fields_ = [
        ("Size", ULONG),
        ("LogonId", LUID),
        ("UserName", LSA_UNICODE_STRING),
        ("LogonDomain", LSA_UNICODE_STRING),
        ("AuthenticationPackage", LSA_UNICODE_STRING),
        ("LogonType", ULONG),
        ("Session", ULONG),
        ("Sid", PVOID),
        ("LogonTime", LARGE_INTEGER),
        ("LogonServer", LSA_UNICODE_STRING),
        ("DnsDomainName", LSA_UNICODE_STRING),
        ("Upn", LSA_UNICODE_STRING),
        ("UserFlags", ULONG),
        ("LastLogonInfo", LSA_LAST_INTER_LOGON_INFO),
        ("LogonScript", LSA_UNICODE_STRING),
        ("ProfilePath", LSA_UNICODE_STRING),
        ("HomeDirectory", LSA_UNICODE_STRING),
        ("HomeDirectoryDrive", LSA_UNICODE_STRING),
        ("LogoffTime", LARGE_INTEGER),
        ("KickOffTime", LARGE_INTEGER),
        ("PasswordLastSet", LARGE_INTEGER),
        ("PasswordCanChange", LARGE_INTEGER),
        ("PasswordMustChange", LARGE_INTEGER),
    ]

    def to_dict(self):
        return {
            "LogonId": self.LogonId.to_int(),
            "UserName": self.UserName.to_string(),
            "LogonDomain": self.LogonDomain.to_string(),
            "AuthenticationPackage": self.AuthenticationPackage.to_string(),
            "LogonType": self.LogonType,
            "Session": self.Session,
            "Sid": str(SID.from_ptr(self.Sid)),  # PVOID), # PSID
            "LogonTime": self.LogonTime,
            "LogonServer": self.LogonServer.to_string(),
            "DnsDomainName": self.DnsDomainName.to_string(),
            "Upn": self.Upn.to_string(),
            "UserFlags": self.UserFlags,
            "LastLogonInfo": self.LastLogonInfo.to_dict(),
            "LogonScript": self.LogonScript.to_string(),
            "ProfilePath": self.ProfilePath.to_string(),
            "HomeDirectory": self.HomeDirectory.to_string(),
            "HomeDirectoryDrive": self.HomeDirectoryDrive.to_string(),
            "LogoffTime": self.LogoffTime,
            "KickOffTime": self.KickOffTime,
            "PasswordLastSet": self.PasswordLastSet,
            "PasswordCanChange": self.PasswordCanChange,
            "PasswordMustChange": self.PasswordMustChange,
        }


PSECURITY_LOGON_SESSION_DATA = POINTER(SECURITY_LOGON_SESSION_DATA)


class KERB_PURGE_TKT_CACHE_REQUEST(Structure):
    _fields_ = [
        ("MessageType", DWORD),
        ("LogonId", LUID),
        ("ServerName", LSA_STRING),
        ("RealmName", LSA_STRING),
    ]

    def __init__(self, logonid=0, servername=None, realname=None):
        if isinstance(logonid, int):
            logonid = LUID.from_int(logonid)

        super(KERB_PURGE_TKT_CACHE_REQUEST, self).__init__(
            KERB_PROTOCOL_MESSAGE_TYPE.KerbPurgeTicketCacheMessage.value, logonid
        )


class KERB_TICKET_CACHE_INFO(Structure):
    _fields_ = [
        ("ServerName", LSA_UNICODE_STRING),
        ("RealmName", LSA_UNICODE_STRING),
        ("StartTime", LARGE_INTEGER),
        ("EndTime", LARGE_INTEGER),
        ("RenewTime", LARGE_INTEGER),
        ("EncryptionType", LONG),
        ("TicketFlags", ULONG),
    ]

    def to_dict(self):
        return {
            "ServerName": self.ServerName.to_string(),
            "RealmName": self.RealmName.to_string(),
            "StartTime": self.StartTime,
            "EndTime": self.EndTime,
            "RenewTime": self.RenewTime,
            "EncryptionType": self.EncryptionType,
            "TicketFlags": self.TicketFlags,
        }


PKERB_TICKET_CACHE_INFO = POINTER(KERB_TICKET_CACHE_INFO)


class KERB_CRYPTO_KEY(Structure):
    _fields_ = [
        ("KeyType", LONG),
        ("Length", ULONG),
        ("Value", PVOID),  # PUCHAR
    ]

    def to_dict(self):
        return {"KeyType": self.KeyType, "Key": string_at(self.Value, self.Length)}


PKERB_CRYPTO_KEY = POINTER(KERB_CRYPTO_KEY)


class KERB_EXTERNAL_NAME(Structure):
    _fields_ = [
        ("NameType", SHORT),
        ("NameCount", USHORT),
        ("Names", LSA_UNICODE_STRING),  # LIST!!!! not implemented!
    ]


PKERB_EXTERNAL_NAME = POINTER(KERB_EXTERNAL_NAME)


class KERB_EXTERNAL_TICKET(Structure):
    _fields_ = [
        ("ServiceName", PVOID),  # PKERB_EXTERNAL_NAME
        ("TargetName", PVOID),  # PKERB_EXTERNAL_NAME
        ("ClientName", PVOID),  # PKERB_EXTERNAL_NAME
        ("DomainName", LSA_UNICODE_STRING),
        ("TargetDomainName", LSA_UNICODE_STRING),
        ("AltTargetDomainName", LSA_UNICODE_STRING),
        ("SessionKey", KERB_CRYPTO_KEY),
        ("TicketFlags", ULONG),
        ("Flags", ULONG),
        ("KeyExpirationTime", LARGE_INTEGER),
        ("StartTime", LARGE_INTEGER),
        ("EndTime", LARGE_INTEGER),
        ("RenewUntil", LARGE_INTEGER),
        ("TimeSkew", LARGE_INTEGER),
        ("EncodedTicketSize", ULONG),
        ("EncodedTicket", PVOID),
    ]

    def get_data(self):
        return {
            "Key": self.SessionKey.to_dict(),
            "Ticket": string_at(self.EncodedTicket, self.EncodedTicketSize),
        }


PKERB_EXTERNAL_TICKET = KERB_EXTERNAL_TICKET


class KERB_QUERY_TKT_CACHE_REQUEST(Structure):
    _fields_ = [
        ("MessageType", DWORD),
        ("LogonId", LUID),
    ]

    def __init__(self, logonid=0):
        if isinstance(logonid, int):
            logonid = LUID.from_int(logonid)

        super(KERB_QUERY_TKT_CACHE_REQUEST, self).__init__(
            KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheMessage.value, logonid
        )


class KERB_QUERY_TKT_CACHE_RESPONSE_SIZE(Structure):
    _fields_ = [
        ("MessageType", DWORD),
        ("CountOfTickets", ULONG),
    ]


class KERB_QUERY_TKT_CACHE_RESPONSE(Structure):
    _fields_ = [
        ("MessageType", DWORD),
        ("CountOfTickets", ULONG),
        ("Tickets", KERB_TICKET_CACHE_INFO),  # array of tickets!!
    ]


class KERB_SUBMIT_TKT_REQUEST(Structure):
    _fields_ = [
        ("MessageType", DWORD),
        ("LogonId", LUID),
        ("TicketFlags", ULONG),
        ("Key", KERB_CRYPTO_KEY),
        ("KerbCredSize", ULONG),
        ("KerbCredOffset", ULONG),
    ]


KERB_SUBMIT_TKT_REQUEST_OFFSET = sizeof(KERB_SUBMIT_TKT_REQUEST())


def submit_tkt_helper(ticket_data, logonid=0):
    offset = KERB_SUBMIT_TKT_REQUEST_OFFSET - 4
    if isinstance(logonid, int):
        logonid = LUID.from_int(logonid)

    class KERB_SUBMIT_TKT_REQUEST(Structure):
        _pack_ = 4
        _fields_ = [
            ("MessageType", DWORD),
            ("LogonId", LUID),
            ("TicketFlags", ULONG),
            # ("KeyType", LONG),
            ("Length", ULONG),
            ("Value", PVOID),  # PUCHAR
            ("KerbCredSize", ULONG),
            ("KerbCredOffset", ULONG),
            ("TicketData", c_byte * len(ticket_data)),
        ]

    req = KERB_SUBMIT_TKT_REQUEST()
    req.MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbSubmitTicketMessage.value
    req.LogonId = logonid
    req.TicketFlags = 0
    req.Key = KERB_CRYPTO_KEY()  # empty key
    req.KerbCredSize = len(ticket_data)
    # req.KerbCredOffset =
    req.TicketData = (c_byte * len(ticket_data))(*ticket_data)

    # struct_end = addressof(req) + sizeof(req)
    # print('struct_end %s' % hex(struct_end))
    # ticketdata_start = struct_end - len(ticket_data)
    # targetname_start_padded = ticketdata_start - (ticketdata_start % sizeof(c_void_p))
    # print('targetname_start_padded %s' % hex(targetname_start_padded))
    # print('offset %s' % offset)
    # print('len(ticket_data) %s' % len(ticket_data))
    req.KerbCredOffset = offset  # targetname_start_padded

    # print(hexdump(string_at(addressof(req), sizeof(req)), start = addressof(req)))
    # print()
    # print(hexdump(string_at(addressof(req) + req.KerbCredOffset, 10 )))
    # if string_at(addressof(req) + req.KerbCredOffset, req.KerbCredSize) != ticket_data:
    # 	print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')

    return req


class KERB_RETRIEVE_TKT_REQUEST(Structure):
    _fields_ = [
        ("MessageType", DWORD),
        ("LogonId", LUID),
        ("TargetName", LSA_UNICODE_STRING),
        ("TicketFlags", ULONG),
        ("CacheOptions", ULONG),
        ("EncryptionType", LONG),
        ("CredentialsHandle", PVOID),  # SecHandle
    ]

    def __init__(
        self,
        targetname,
        ticketflags=0x0,
        cacheoptions=0x8,
        encryptiontype=0x0,
        logonid=0,
    ):
        if isinstance(logonid, int):
            logonid = LUID.from_int(logonid)

        super(KERB_RETRIEVE_TKT_REQUEST, self).__init__(
            KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage.value,
            logonid,
            LSA_UNICODE_STRING.from_string(targetname),
            ticketflags,
            cacheoptions,
            encryptiontype,
            None,
        )


def retrieve_tkt_helper(
    targetname,
    logonid=0,
    ticketflags=0x0,
    cacheoptions=0x8,
    encryptiontype=0x0,
    temp_offset=0,
):
    # Rubeus helped me here with the info that the "targetname" structure's internal pointer
    # must be pointing to the bottom of the actual KERB_RETRIEVE_TKT_REQUEST otherwise you will get a generic error
    # Sadly that wasn't completely enough because <insert vauge reasons here>. So I introduced an extra pointer to serve
    # as a platform-independent padding between the oringinal structure and the actual targetname bytes.
    #
    # For reference:
    # https://github.com/GhostPack/Rubeus/blob/master/Rubeus/lib/LSA.cs

    if isinstance(logonid, int):
        logonid = LUID.from_int(logonid)

    targetname_enc = targetname.encode("utf-16-le") + b"\x00\x00"
    targetname_len_alloc = len(targetname_enc)

    class KERB_RETRIEVE_TKT_REQUEST(Structure):
        _fields_ = [
            ("MessageType", DWORD),
            ("LogonId", LUID),
            ("TargetName", LSA_UNICODE_STRING),
            ("TicketFlags", ULONG),
            ("CacheOptions", ULONG),
            ("EncryptionType", LONG),
            ("CredentialsHandle", PVOID),  # SecHandle
            (
                "UNK",
                PVOID,
            ),  # I put this here otherwise there is an error "Invalid parameter". Probably padding issue but  I dunno
            ("TargetNameData", (c_byte * targetname_len_alloc)),
        ]

    req = KERB_RETRIEVE_TKT_REQUEST()
    req.MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage.value
    req.LogonId = logonid
    req.TicketFlags = ticketflags
    req.CacheOptions = cacheoptions
    req.EncryptionType = encryptiontype
    req.TargetNameData = (c_byte * len(targetname_enc))(*targetname_enc)

    struct_end = addressof(req) + sizeof(req)
    targetname_start = struct_end - targetname_len_alloc
    targetname_start_padded = targetname_start - (targetname_start % sizeof(c_void_p))

    lsa_target = LSA_UNICODE_STRING()
    lsa_target.Length = len(targetname.encode("utf-16-le"))
    lsa_target.MaximumLength = targetname_len_alloc
    lsa_target.Buffer = cast(targetname_start_padded, POINTER(c_char))

    req.TargetName = lsa_target

    # print(targetname_start_padded)
    # print(lsa_target.Buffer.contents)
    ##print(lsa_target.to_string())
    # print(string_at(targetname_start_padded, lsa_target.MaximumLength))
    # print('a %s' % addressof(req))
    # print('s %s' % sizeof(req))
    # hd = hexdump(string_at(addressof(req), sizeof(req)), start = addressof(req))
    # print(hd)

    return req


class KERB_RETRIEVE_TKT_RESPONSE(Structure):
    _fields_ = [
        ("Ticket", KERB_EXTERNAL_TICKET),
    ]


# Invalid handle value is -1 casted to void pointer.
try:
    INVALID_HANDLE_VALUE = c_void_p(-1).value  # -1 #0xFFFFFFFF
except TypeError:
    if sizeof(c_void_p) == 4:
        INVALID_HANDLE_VALUE = 0xFFFFFFFF
    elif sizeof(c_void_p) == 8:
        INVALID_HANDLE_VALUE = 0xFFFFFFFFFFFFFFFF
    else:
        raise


def get_lsa_error(ret_status):
    return WinError(LsaNtStatusToWinError(ret_status))


def RaiseIfZero(result, func=None, arguments=()):
    """
    Error checking for most Win32 API calls.

    The function is assumed to return an integer, which is C{0} on error.
    In that case the C{WindowsError} exception is raised.
    """
    if not result:
        raise WinError()
    return result


def LsaRaiseIfNotErrorSuccess(result, func=None, arguments=()):
    """
    Error checking for Win32 Registry API calls.

    The function is assumed to return a Win32 error code. If the code is not
    C{ERROR_SUCCESS} then a C{WindowsError} exception is raised.
    """
    if result != ERROR_SUCCESS:
        raise WinError(LsaNtStatusToWinError(result))
    return result


# https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsantstatustowinerror
def LsaNtStatusToWinError(errcode):
    _LsaConnectUntrusted = windll.Advapi32.LsaNtStatusToWinError
    _LsaConnectUntrusted.argtypes = [NTSTATUS]
    _LsaConnectUntrusted.restype = ULONG

    res = _LsaConnectUntrusted(errcode)
    if res == 0x13D:
        raise Exception("ERROR_MR_MID_NOT_FOUND for %s" % errcode)
    return res


# https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsafreereturnbuffer
def LsaFreeReturnBuffer(pbuffer):
    _LsaFreeReturnBuffer = windll.Secur32.LsaFreeReturnBuffer
    _LsaFreeReturnBuffer.argtypes = [PVOID]
    _LsaFreeReturnBuffer.restype = NTSTATUS
    _LsaFreeReturnBuffer.errcheck = LsaRaiseIfNotErrorSuccess

    _LsaFreeReturnBuffer(pbuffer)


# https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaconnectuntrusted
def LsaConnectUntrusted():
    _LsaConnectUntrusted = windll.Secur32.LsaConnectUntrusted
    _LsaConnectUntrusted.argtypes = [PHANDLE]
    _LsaConnectUntrusted.restype = NTSTATUS
    _LsaConnectUntrusted.errcheck = LsaRaiseIfNotErrorSuccess

    lsa_handle = HANDLE(INVALID_HANDLE_VALUE)
    _LsaConnectUntrusted(byref(lsa_handle))
    return lsa_handle


# https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaderegisterlogonprocess
def LsaDeregisterLogonProcess(lsa_handle):
    _LsaDeregisterLogonProcess = windll.Secur32.LsaDeregisterLogonProcess
    _LsaDeregisterLogonProcess.argtypes = [HANDLE]
    _LsaDeregisterLogonProcess.restype = NTSTATUS
    _LsaDeregisterLogonProcess.errcheck = LsaRaiseIfNotErrorSuccess

    _LsaDeregisterLogonProcess(lsa_handle)

    return


# https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaregisterlogonprocess
def LsaRegisterLogonProcess(logon_process_name):
    # logon_process_name == This string must not exceed 127 bytes.
    _LsaRegisterLogonProcess = windll.Secur32.LsaRegisterLogonProcess
    _LsaRegisterLogonProcess.argtypes = [PLSA_STRING, PHANDLE, PLSA_OPERATIONAL_MODE]
    _LsaRegisterLogonProcess.restype = NTSTATUS
    _LsaRegisterLogonProcess.errcheck = LsaRaiseIfNotErrorSuccess

    if isinstance(logon_process_name, str):
        logon_process_name = logon_process_name.encode()

    pname = LSA_STRING()
    pname.Buffer = create_string_buffer(logon_process_name)
    pname.Length = len(logon_process_name)
    pname.MaximumLength = len(logon_process_name) + 1

    lsa_handle = HANDLE(INVALID_HANDLE_VALUE)
    dummy = LSA_OPERATIONAL_MODE(0)
    _LsaRegisterLogonProcess(byref(pname), byref(lsa_handle), byref(dummy))

    return lsa_handle


# https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsalookupauthenticationpackage
def LsaLookupAuthenticationPackage(lsa_handle, package_name):
    # logon_process_name == This string must not exceed 127 bytes.
    _LsaLookupAuthenticationPackage = windll.Secur32.LsaLookupAuthenticationPackage
    _LsaLookupAuthenticationPackage.argtypes = [HANDLE, PLSA_STRING, PULONG]
    _LsaLookupAuthenticationPackage.restype = NTSTATUS
    _LsaLookupAuthenticationPackage.errcheck = LsaRaiseIfNotErrorSuccess

    if isinstance(package_name, str):
        package_name = package_name.encode()

    pname = LSA_STRING()
    pname.Buffer = create_string_buffer(package_name)
    pname.Length = len(package_name)
    pname.MaximumLength = len(package_name) + 1

    package_id = ULONG(0)
    _LsaLookupAuthenticationPackage(lsa_handle, byref(pname), byref(package_id))

    return package_id.value


# https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsacallauthenticationpackage
def LsaCallAuthenticationPackage(lsa_handle, package_id, message):
    # message bytes
    _LsaCallAuthenticationPackage = windll.Secur32.LsaCallAuthenticationPackage
    _LsaCallAuthenticationPackage.argtypes = [
        HANDLE,
        ULONG,
        PVOID,
        ULONG,
        PVOID,
        PULONG,
        PNTSTATUS,
    ]
    _LsaCallAuthenticationPackage.restype = DWORD
    _LsaCallAuthenticationPackage.errcheck = LsaRaiseIfNotErrorSuccess

    if not isinstance(message, Structure):
        message = bytes(message)
        message_len = len(message)
    else:
        message_len = len(bytes(message))

    return_msg_p = c_void_p()
    return_msg_len = ULONG(0)
    return_status = NTSTATUS(INVALID_HANDLE_VALUE)
    _LsaCallAuthenticationPackage(
        lsa_handle,
        package_id,
        byref(message),
        message_len,
        byref(return_msg_p),
        byref(return_msg_len),
        byref(return_status),
    )

    return_msg = b""
    free_ptr = None  # please free this pointer when the parsing is finished on the upper levels using LsaFreeReturnBuffer. Problem is that if we call LsaFreeReturnBuffer here then the parsing will fail if the message has nested structures with pointers involved because by the time of parsing those pointers will be freed. sad.
    if return_msg_len.value > 0:
        return_msg = string_at(return_msg_p, return_msg_len.value)
        free_ptr = return_msg_p
        # LsaFreeReturnBuffer(return_msg_p)

    return return_msg, return_status.value, free_ptr


# https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaenumeratelogonsessions
def LsaEnumerateLogonSessions():
    # logon_process_name == This string must not exceed 127 bytes.
    _LsaEnumerateLogonSessions = windll.Secur32.LsaEnumerateLogonSessions
    _LsaEnumerateLogonSessions.argtypes = [PULONG, PVOID]  # PLUID
    _LsaEnumerateLogonSessions.restype = NTSTATUS
    _LsaEnumerateLogonSessions.errcheck = LsaRaiseIfNotErrorSuccess

    LogonSessionCount = ULONG(0)
    start_luid = c_void_p()
    _LsaEnumerateLogonSessions(byref(LogonSessionCount), byref(start_luid))

    class LUIDList(Structure):
        _fields_ = [
            ("LogonIds", LUID * LogonSessionCount.value),
        ]

    PLUIDList = POINTER(LUIDList)

    res_luids = []
    pluids = cast(start_luid, PLUIDList)
    for luid in pluids.contents.LogonIds:
        res_luids.append(luid.to_int())

    LsaFreeReturnBuffer(start_luid)

    return res_luids


# https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsagetlogonsessiondata
def LsaGetLogonSessionData(luid):
    # logon_process_name == This string must not exceed 127 bytes.
    _LsaGetLogonSessionData = windll.Secur32.LsaGetLogonSessionData
    _LsaGetLogonSessionData.argtypes = [PLUID, PVOID]  # PSECURITY_LOGON_SESSION_DATA
    _LsaGetLogonSessionData.restype = NTSTATUS
    _LsaGetLogonSessionData.errcheck = LsaRaiseIfNotErrorSuccess

    if isinstance(luid, int):
        luid = LUID.from_int(luid)

    ppsessiondata = c_void_p()
    _LsaGetLogonSessionData(byref(luid), byref(ppsessiondata))

    psessiondata = cast(ppsessiondata, PSECURITY_LOGON_SESSION_DATA)
    sessiondata = psessiondata.contents.to_dict()
    LsaFreeReturnBuffer(ppsessiondata)

    return sessiondata


# https://github.com/mhammond/pywin32/blob/d64fac8d7bda2cb1d81e2c9366daf99e802e327f/win32/Lib/sspi.py#L108
# https://docs.microsoft.com/en-us/windows/desktop/secauthn/using-sspi-with-a-windows-sockets-client
# https://msdn.microsoft.com/en-us/library/Aa374712(v=VS.85).aspx
def AcquireCredentialsHandle(
    client_name, package_name, tragetspn, cred_usage, pluid=None, authdata=None
):
    def errc(result, func, arguments):
        if SEC_E(result) == SEC_E.OK:
            return result
        raise Exception(
            "%s failed with error code %s (%s)"
            % ("AcquireCredentialsHandle", result, SEC_E(result))
        )

    _AcquireCredentialsHandle = windll.Secur32.AcquireCredentialsHandleA
    _AcquireCredentialsHandle.argtypes = [
        PSEC_CHAR,
        PSEC_CHAR,
        ULONG,
        PLUID,
        PVOID,
        PVOID,
        PVOID,
        PCredHandle,
        PTimeStamp,
    ]
    _AcquireCredentialsHandle.restype = DWORD
    _AcquireCredentialsHandle.errcheck = errc

    # TODO: package_name might be different from version to version. implement functionality to poll it properly!

    cn = None
    if client_name:
        cn = LPSTR(client_name.encode("ascii"))
    pn = LPSTR(package_name.encode("ascii"))

    creds = CredHandle()
    ts = TimeStamp()
    _AcquireCredentialsHandle(
        cn, pn, cred_usage, pluid, authdata, None, None, byref(creds), byref(ts)
    )
    return creds


# https://docs.microsoft.com/en-us/windows/desktop/api/sspi/nf-sspi-querycontextattributesa
def QueryContextAttributes(ctx, attr, sec_struct):
    # attr = SECPKG_ATTR enum
    def errc(result, func, arguments):
        if SEC_E(result) == SEC_E.OK:
            return SEC_E(result)
        raise Exception(
            "%s failed with error code %s (%s)"
            % ("QueryContextAttributes", result, SEC_E(result))
        )

    _QueryContextAttributes = windll.Secur32.QueryContextAttributesW
    _QueryContextAttributes.argtypes = [PCtxtHandle, ULONG, PVOID]
    _QueryContextAttributes.restype = DWORD
    _QueryContextAttributes.errcheck = errc

    _QueryContextAttributes(byref(ctx), attr.value, byref(sec_struct))

    return


# https://msdn.microsoft.com/en-us/library/windows/desktop/aa375507(v=vs.85).aspx
def InitializeSecurityContext(
    creds,
    target,
    ctx=None,
    flags=ISC_REQ.INTEGRITY
    | ISC_REQ.CONFIDENTIALITY
    | ISC_REQ.SEQUENCE_DETECT
    | ISC_REQ.REPLAY_DETECT,
    TargetDataRep=0,
    token=None,
):
    # print('==== InitializeSecurityContext ====')
    # print('Creds: %s' % creds)
    # print('Target: %s' % target)
    # print('ctx: %s' % ctx)
    # print('token: %s' % token)
    def errc(result, func, arguments):
        if SEC_E(result) in [
            SEC_E.OK,
            SEC_E.COMPLETE_AND_CONTINUE,
            SEC_E.COMPLETE_NEEDED,
            SEC_E.CONTINUE_NEEDED,
            SEC_E.INCOMPLETE_CREDENTIALS,
        ]:
            return SEC_E(result)
        raise Exception(
            "%s failed with error code %s (%s)"
            % ("InitializeSecurityContext", result, SEC_E(result))
        )

    _InitializeSecurityContext = windll.Secur32.InitializeSecurityContextA
    _InitializeSecurityContext.argtypes = [
        PCredHandle,
        PCtxtHandle,
        PSEC_CHAR,
        ULONG,
        ULONG,
        ULONG,
        PSecBufferDesc,
        ULONG,
        PCtxtHandle,
        PSecBufferDesc,
        PULONG,
        PTimeStamp,
    ]
    _InitializeSecurityContext.restype = DWORD
    _InitializeSecurityContext.errcheck = errc

    if target:
        ptarget = LPSTR(target.encode("ascii"))
    else:
        ptarget = None
    newbuf = SecBufferDesc()
    outputflags = ULONG()
    expiry = TimeStamp()

    if token:
        token = SecBufferDesc([SecBuffer(token)])

    if not ctx:
        ctx = CtxtHandle()
        res = _InitializeSecurityContext(
            byref(creds),
            None,
            ptarget,
            int(flags),
            0,
            TargetDataRep,
            byref(token) if token else None,
            0,
            byref(ctx),
            byref(newbuf),
            byref(outputflags),
            byref(expiry),
        )
    else:
        res = _InitializeSecurityContext(
            byref(creds),
            byref(ctx),
            ptarget,
            int(flags),
            0,
            TargetDataRep,
            byref(token) if token else None,
            0,
            byref(ctx),
            byref(newbuf),
            byref(outputflags),
            byref(expiry),
        )

    data = newbuf.Buffers

    return res, ctx, data, ISC_REQ(outputflags.value), expiry


def get_ticket_cache_info_helper(lsa_handle, package_id, luid, throw=True):
    result = []
    message = KERB_QUERY_TKT_CACHE_REQUEST(luid)
    ret_msg, ret_status, free_prt = LsaCallAuthenticationPackage(
        lsa_handle, package_id, message
    )

    if ret_status != 0:
        if throw is True:
            raise WinError(LsaNtStatusToWinError(ret_status))
        return result

    response_preparse = KERB_QUERY_TKT_CACHE_RESPONSE_SIZE.from_buffer_copy(ret_msg)
    if response_preparse.CountOfTickets > 0:
        # new class
        class KERB_QUERY_TKT_CACHE_RESPONSE_ARRAY(Structure):
            _fields_ = [
                ("MessageType", DWORD),
                ("CountOfTickets", ULONG),
                ("Tickets", KERB_TICKET_CACHE_INFO * response_preparse.CountOfTickets),
            ]

        response = KERB_QUERY_TKT_CACHE_RESPONSE_ARRAY.from_buffer_copy(ret_msg)
        for ticket in response.Tickets:
            result.append(ticket.to_dict())

        LsaFreeReturnBuffer(free_prt)

    return result


def extract_ticket(lsa_handle, package_id, luid, target_name):
    message = retrieve_tkt_helper(target_name, logonid=luid)
    ret_msg, ret_status, free_ptr = LsaCallAuthenticationPackage(
        lsa_handle, package_id, message
    )

    ticket = {}
    if ret_status != 0:
        raise WinError(LsaNtStatusToWinError(ret_status))
    if len(ret_msg) > 0:
        resp = KERB_RETRIEVE_TKT_RESPONSE.from_buffer_copy(ret_msg)
        ticket = resp.Ticket.get_data()
        LsaFreeReturnBuffer(free_ptr)

    return ticket


if __name__ == "__main__":

    # luids = LsaEnumerateLogonSessions()
    # for luid in luids:
    # 	try:
    # 		session_info = LsaGetLogonSessionData(luid)
    # 		print(session_info)
    # 	except Exception as e:
    # 		import traceback
    # 		traceback.print_exc()
    # 		print(e)
    from pypykatz.commons.readers.local.common.privileges import RtlAdjustPrivilege
    from pypykatz.commons.winapi.processmanipulator import ProcessManipulator

    pm = ProcessManipulator()

    # lsa_handle = LsaConnectUntrusted()

    # package_id = LsaLookupAuthenticationPackage(lsa_handle, 'kerberos')
    # print(package_id)
    # message = KERB_PURGE_TKT_CACHE_REQUEST()
    # LsaCallAuthenticationPackage(lsa_handle, package_id, message)
    # LsaDeregisterLogonProcess(lsa_handle)

    # print(LsaGetLogonSessionData(0))
    # retrieve_tkt_helper('almaaaaasaaaa')
    # sys.exit()

    pm.getsystem()
    lsa_handle = LsaRegisterLogonProcess("HELLOOO")
    pm.dropsystem()
    package_id = LsaLookupAuthenticationPackage(lsa_handle, "kerberos")

    with open("test_9.kirbi", "rb") as f:
        ticket_data = f.read()

    luid = 0
    message = submit_tkt_helper(ticket_data, logonid=luid)
    ret_msg, ret_status, free_ptr = LsaCallAuthenticationPackage(
        lsa_handle, package_id, message
    )

    print(get_lsa_error(ret_status))
    print(ret_msg)

    #

    # print(lsa_handle_2)
    # LsaDeregisterLogonProcess(lsa_handle_2)
