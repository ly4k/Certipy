"""
Constants module for Certipy.

This module defines various constants used throughout Certipy for:
- User agent strings for HTTP requests
- Well-known security identifiers (SIDs) and relative identifiers (RIDs)
- PKI certificate flags and options
- Access control and rights constants
- Extended permissions mapping
- OID (Object Identifier) mappings

These constants are primarily used when interacting with Active Directory,
certificate services, and security descriptors.
"""

from certipy.lib.structs import IntFlag

# =========================================================================
# User Agent
# =========================================================================

LATEST_EDGE_VERSION = "136.0.3240.50"

USER_AGENT = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{LATEST_EDGE_VERSION.split('.')[0]}.0.0.0 Safari/537.36 Edg/{LATEST_EDGE_VERSION}"

# =========================================================================
# Security Identifiers (SIDs) and Relative Identifiers (RIDs)
# =========================================================================

# Well-known SIDs mapping to (name, object type)
# Source: https://github.com/fox-it/BloodHound.py/blob/d665959c58d881900378040e6670fa12f801ccd4/bloodhound/ad/utils.py#L36
WELLKNOWN_SIDS = {
    # Null and World Authority
    "S-1-0": ("Null Authority", "USER"),
    "S-1-0-0": ("Nobody", "USER"),
    "S-1-1": ("World Authority", "USER"),
    "S-1-1-0": ("Everyone", "GROUP"),
    # Local Authority
    "S-1-2": ("Local Authority", "USER"),
    "S-1-2-0": ("Local", "GROUP"),
    "S-1-2-1": ("Console Logon", "GROUP"),
    # Creator Authority
    "S-1-3": ("Creator Authority", "USER"),
    "S-1-3-0": ("Creator Owner", "USER"),
    "S-1-3-1": ("Creator Group", "GROUP"),
    "S-1-3-2": ("Creator Owner Server", "COMPUTER"),
    "S-1-3-3": ("Creator Group Server", "COMPUTER"),
    "S-1-3-4": ("Owner Rights", "GROUP"),
    # Non-unique and NT Authority
    "S-1-4": ("Non-unique Authority", "USER"),
    "S-1-5": ("NT Authority", "USER"),
    "S-1-5-1": ("Dialup", "GROUP"),
    "S-1-5-2": ("Network", "GROUP"),
    "S-1-5-3": ("Batch", "GROUP"),
    "S-1-5-4": ("Interactive", "GROUP"),
    "S-1-5-6": ("Service", "GROUP"),
    "S-1-5-7": ("Anonymous", "GROUP"),
    "S-1-5-8": ("Proxy", "GROUP"),
    "S-1-5-9": ("Enterprise Domain Controllers", "GROUP"),
    "S-1-5-10": ("Principal Self", "USER"),
    "S-1-5-11": ("Authenticated Users", "GROUP"),
    "S-1-5-12": ("Restricted Code", "GROUP"),
    "S-1-5-13": ("Terminal Server Users", "GROUP"),
    "S-1-5-14": ("Remote Interactive Logon", "GROUP"),
    "S-1-5-15": ("This Organization", "GROUP"),
    "S-1-5-17": ("IUSR", "USER"),
    "S-1-5-18": ("Local System", "USER"),
    "S-1-5-19": ("NT Authority", "USER"),
    "S-1-5-20": ("Network Service", "USER"),
    "S-1-5-80-0": ("All Services", "GROUP"),
    # Built-in local groups
    "S-1-5-32-544": ("Administrators", "GROUP"),
    "S-1-5-32-545": ("Users", "GROUP"),
    "S-1-5-32-546": ("Guests", "GROUP"),
    "S-1-5-32-547": ("Power Users", "GROUP"),
    "S-1-5-32-548": ("Account Operators", "GROUP"),
    "S-1-5-32-549": ("Server Operators", "GROUP"),
    "S-1-5-32-550": ("Print Operators", "GROUP"),
    "S-1-5-32-551": ("Backup Operators", "GROUP"),
    "S-1-5-32-552": ("Replicators", "GROUP"),
    "S-1-5-32-554": ("Pre-Windows 2000 Compatible Access", "GROUP"),
    "S-1-5-32-555": ("Remote Desktop Users", "GROUP"),
    "S-1-5-32-556": ("Network Configuration Operators", "GROUP"),
    "S-1-5-32-557": ("Incoming Forest Trust Builders", "GROUP"),
    "S-1-5-32-558": ("Performance Monitor Users", "GROUP"),
    "S-1-5-32-559": ("Performance Log Users", "GROUP"),
    "S-1-5-32-560": ("Windows Authorization Access Group", "GROUP"),
    "S-1-5-32-561": ("Terminal Server License Servers", "GROUP"),
    "S-1-5-32-562": ("Distributed COM Users", "GROUP"),
    "S-1-5-32-568": ("IIS_IUSRS", "GROUP"),
    "S-1-5-32-569": ("Cryptographic Operators", "GROUP"),
    "S-1-5-32-573": ("Event Log Readers", "GROUP"),
    "S-1-5-32-574": ("Certificate Service DCOM Access", "GROUP"),
    "S-1-5-32-575": ("RDS Remote Access Servers", "GROUP"),
    "S-1-5-32-576": ("RDS Endpoint Servers", "GROUP"),
    "S-1-5-32-577": ("RDS Management Servers", "GROUP"),
    "S-1-5-32-578": ("Hyper-V Administrators", "GROUP"),
    "S-1-5-32-579": ("Access Control Assistance Operators", "GROUP"),
    "S-1-5-32-580": ("Access Control Assistance Operators", "GROUP"),
}

# Well-known RIDs mapping to (name, object type)
# Source: https://github.com/garrettfoster13/aced/blob/b5d1ad1b8cfb84a6420be22658beec340ef9e396/lib/sid.py#L48
WELLKNOWN_RIDS = {
    # Special accounts
    "500": ("Administrator", "USER"),
    "501": ("Guest", "USER"),
    "502": ("KRBTGT", "USER"),
    # Domain groups
    "512": ("Domain Admins", "GROUP"),
    "513": ("Domain Users", "GROUP"),
    "514": ("Domain Guests", "GROUP"),
    "515": ("Domain Computers", "GROUP"),
    "516": ("Domain Controllers", "GROUP"),
    "517": ("Cert Publishers", "GROUP"),
    # Administrative groups
    "518": ("Schema Admins", "GROUP"),
    "519": ("Enterprise Admins", "GROUP"),
    "520": ("Group Policy Creator Owners", "GROUP"),
    # Special controllers
    "521": ("Read-only Domain Controllers", "GROUP"),
    "522": ("Cloneable Domain Controllers", "GROUP"),
    "498": ("Enterprise Read-only Domain Controllers", "GROUP"),
    # Special purpose groups
    "526": ("Key Admins", "GROUP"),
    "527": ("Enterprise Key Admins", "GROUP"),
    "553": ("RAS and IAS Servers", "GROUP"),
}

# =========================================================================
# PKI Certificate Flags
# =========================================================================


# Template flags
# Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/6cc7eb79-3e84-477a-b398-b0ff2b68a6c0
class TemplateFlags(IntFlag):
    """
    Certificate template flags that control template behavior.

    These flags define how certificate templates operate in Active Directory
    Certificate Services, including enrollment options, certificate type,
    and template modification restrictions.

    Reference: MS-CRTD 2.4 flags Attribute
    """

    NONE = 0x00000000

    # Reserved flags (must be ignored by all protocols)
    ADD_EMAIL = 0x00000002  # Include email in certificate
    PUBLISH_TO_DS = 0x00000008  # Publish certificate to directory
    EXPORTABLE_KEY = 0x00000010  # Allow private key export

    # Enrollment flags
    AUTO_ENROLLMENT = 0x00000020  # Template supports auto-enrollment

    # Certificate type flags
    MACHINE_TYPE = 0x00000040  # Certificate for machine authentication
    IS_CA = 0x00000080  # Certificate for CA issuance
    IS_CROSS_CA = 0x00000800  # Certificate for cross-certification

    # Certificate content flags
    ADD_TEMPLATE_NAME = 0x00000200  # Include template name in certificate extension

    # Database flags
    DO_NOT_PERSIST_IN_DB = 0x00001000  # Don't persist request in CA database

    # Template management flags
    IS_DEFAULT = 0x00010000  # Template should not be modified
    IS_MODIFIED = 0x00020000  # Template may be modified if required


# Enrollment flags
# Source: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1
class EnrollmentFlag(IntFlag):
    """
    Flags controlling certificate enrollment behavior.

    These flags determine how certificates are enrolled, published, and managed
    throughout their lifecycle in Active Directory Certificate Services.

    Reference: MS-CRTD 2.26 msPKI-Enrollment-Flag Attribute
    """

    # Base value
    NONE = 0x00000000  # No special enrollment behavior

    # Enrollment processing options
    INCLUDE_SYMMETRIC_ALGORITHMS = (
        0x00000001  # Include symmetric algorithms in requests
    )
    PEND_ALL_REQUESTS = 0x00000002  # All requests must be manually approved
    USER_INTERACTION_REQUIRED = (
        0x00000100  # User interaction required during enrollment
    )

    # Publication options
    PUBLISH_TO_KRA_CONTAINER = (
        0x00000004  # Publish certificates to Key Recovery Agent container
    )
    PUBLISH_TO_DS = 0x00000008  # Publish certificates to Active Directory
    ADD_TEMPLATE_NAME = 0x00000200  # Add template name to issued certificates
    ADD_OCSP_NOCHECK = 0x00001000  # Add OCSP NoCheck extension

    # Auto-enrollment options
    AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = (
        0x00000010  # Check DS for existing certificate before auto-enrollment
    )
    AUTO_ENROLLMENT = 0x00000020  # Enable auto-enrollment for this template
    SKIP_AUTO_RENEWAL = 0x00040000  # Skip auto-renewal even if otherwise enabled

    # Authentication options
    CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED = (
        0x00000080  # Domain authentication not required for enrollment
    )
    PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = (
        0x00000040  # Validate re-enrollment requests requiring approval
    )
    ALLOW_ENROLL_ON_BEHALF_OF = (
        0x00000800  # Allow enrollment on behalf of another user/computer
    )
    ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT = (
        0x00010000  # Allow key-based renewal with previous approval
    )

    # Certificate store management
    REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = (
        0x00000400  # Remove invalid certificates from personal store
    )
    ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL = (
        0x00002000  # Enable key reuse when token storage is full
    )

    # Certificate content options
    NOREVOCATIONINFOINISSUEDCERTS = (
        0x00004000  # Don't include revocation info in certificates
    )
    INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS = (
        0x00008000  # Include Basic Constraints for end-entity certs
    )
    ISSUANCE_POLICIES_FROM_REQUEST = 0x00020000  # Obtain issuance policies from request
    NO_SECURITY_EXTENSION = 0x00080000  # Don't include security extension


# Private key flags
# Source: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/f6122d87-b999-4b92-bff8-f465e8949667
class PrivateKeyFlag(IntFlag):
    """
    Flags controlling certificate private key behavior.

    These flags define the handling, storage, and restrictions of private keys
    associated with certificates issued from a template.

    Reference: MS-CRTD 2.27 msPKI-Private-Key-Flag Attribute
    """

    # Default value
    NONE = 0x00000000  # No special private key handling

    # Key archival and export settings
    REQUIRE_PRIVATE_KEY_ARCHIVAL = 0x00000001  # Require private key archival to KRA
    EXPORTABLE_KEY = 0x00000010  # Private key can be exported
    STRONG_KEY_PROTECTION_REQUIRED = (
        0x00000020  # Require strong key protection (password)
    )

    # Key algorithm settings
    REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM = (
        0x00000040  # Require alternate signature algorithm
    )
    REQUIRE_SAME_KEY_RENEWAL = 0x00000080  # Require same key for renewal
    USE_LEGACY_PROVIDER = 0x00000100  # Use legacy cryptographic provider

    # Key attestation levels
    ATTEST_NONE = 0x00000000  # No attestation required
    ATTEST_PREFERRED = 0x00001000  # Attestation preferred but not required
    ATTEST_REQUIRED = 0x00002000  # Attestation required
    ATTESTATION_WITHOUT_POLICY = 0x00004000  # Attestation without specific policy

    # Endorsement key options
    EK_TRUST_ON_USE = 0x00000200  # Trust endorsement key on first use
    EK_VALIDATE_CERT = 0x00000400  # Validate endorsement key certificate
    EK_VALIDATE_KEY = 0x00000800  # Validate endorsement key itself

    # Special key types
    HELLO_LOGON_KEY = 0x00200000  # Key for Hello logon/Windows Hello


# Certificate name flags
# Source: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1
class CertificateNameFlag(IntFlag):
    """
    Flags controlling certificate subject name creation and validation.

    These flags define how subject names and subject alternative names (SANs) are created,
    what information is included in certificates, and what naming constraints are enforced
    during certificate enrollment.

    Reference: MS-CRTD 2.28 msPKI-Certificate-Name-Flag Attribute
    """

    # Base value
    NONE = 0x00000000  # No special naming behavior

    # Subject name source options
    ENROLLEE_SUPPLIES_SUBJECT = 0x00000001  # Enrollee can specify subject name
    OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = (
        0x00000008  # Use subject from previous cert during renewal
    )

    # Subject content inclusion options
    ADD_EMAIL = 0x00000002  # Include email address in subject name
    ADD_OBJ_GUID = 0x00000004  # Include Active Directory object GUID in SAN
    ADD_DIRECTORY_PATH = 0x00000100  # Include directory path (DN) in subject name

    # Subject alternative name options
    ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = (
        0x00010000  # Enrollee can specify subject alternative names
    )

    # Subject alternative name requirements
    SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000  # Require domain DNS name in SAN
    SUBJECT_ALT_REQUIRE_SPN = 0x00800000  # Require Service Principal Name in SAN
    SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000  # Require directory GUID in SAN
    SUBJECT_ALT_REQUIRE_UPN = 0x02000000  # Require User Principal Name in SAN
    SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000  # Require email address in SAN
    SUBJECT_ALT_REQUIRE_DNS = 0x08000000  # Require DNS name in SAN

    # Subject name requirements
    SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000  # Require DNS name as common name (CN)
    SUBJECT_REQUIRE_EMAIL = 0x20000000  # Require email in subject name
    SUBJECT_REQUIRE_COMMON_NAME = 0x40000000  # Require common name (CN) in subject
    SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000  # Require directory path in subject


# =========================================================================
# Access Control and Rights
# =========================================================================


# Access control types
# Source: https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.accesscontroltype?view=net-5.0
class AccessControlType(IntFlag):
    """Access control types for access control entries."""

    ALLOW = 0
    DENY = 1


# Active Directory rights
# Source: https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=net-5.0
class ActiveDirectoryRights(IntFlag):
    """Rights applicable to Active Directory objects."""

    # Object-level rights
    CREATE_CHILD = 1
    DELETE_CHILD = 2
    LIST_CHILDREN = 4
    SELF = 8
    READ_PROPERTY = 16
    WRITE_PROPERTY = 32
    DELETE_TREE = 64
    LIST_OBJECT = 128
    EXTENDED_RIGHT = 256

    # Standard rights
    DELETE = 65536
    READ_CONTROL = 131072
    WRITE_DACL = 262144
    WRITE_OWNER = 524288
    SYNCHRONIZE = 1048576
    ACCESS_SYSTEM_SECURITY = 16777216

    # Generic rights
    GENERIC_READ = 131220
    GENERIC_WRITE = 131112
    GENERIC_EXECUTE = 131076
    GENERIC_ALL = 983551


# Certificate rights
class CertificateRights(IntFlag):
    """Rights applicable to certificate templates and related objects."""

    WRITE_PROPERTY = 32
    EXTENDED_RIGHT = 256
    WRITE_DACL = 262144
    WRITE_OWNER = 524288
    GENERIC_WRITE = 131112
    GENERIC_ALL = 983551


# Certificate issuance policy rights
class IssuancePolicyRights(IntFlag):
    """Rights applicable to certificate issuance policies."""

    WRITE_PROPERTY = 32
    WRITE_DACL = 262144
    WRITE_OWNER = 524288
    GENERIC_READ = 131220
    GENERIC_ALL = 983551


# Certificate authority rights
# Source: https://github.com/GhostPack/Certify/blob/2b1530309c0c5eaf41b2505dfd5a68c83403d031/Certify/Domain/CertificateAuthority.cs#L11
class CertificateAuthorityRights(IntFlag):
    """Rights applicable to certification authorities."""

    MANAGE_CA = 1
    MANAGE_CERTIFICATES = 2
    AUDITOR = 4
    OPERATOR = 8
    READ = 256
    ENROLL = 512


# =========================================================================
# Object Identifier (OID) Mappings
# =========================================================================

# OID mappings to human-readable names
# Source: https://www.pkisolutions.com/object-identifiers-oid-in-pki/
OID_TO_STR_MAP = {
    # Windows system and infrastructure
    "1.3.6.1.4.1.311.76.6.1": "Windows Update",
    "1.3.6.1.4.1.311.10.3.11": "Key Recovery",
    "1.3.6.1.4.1.311.10.3.25": "Windows Third Party Application Component",
    "1.3.6.1.4.1.311.21.6": "Key Recovery Agent",
    "1.3.6.1.4.1.311.10.3.6": "Windows System Component Verification",
    "1.3.6.1.4.1.311.61.4.1": "Early Launch Antimalware Drive",
    "1.3.6.1.4.1.311.10.3.23": "Windows TCB Component",
    "1.3.6.1.4.1.311.61.1.1": "Kernel Mode Code Signing",
    "1.3.6.1.4.1.311.10.3.26": "Windows Software Extension Verification",
    "1.3.6.1.4.1.311.76.3.1": "Windows Store",
    "1.3.6.1.4.1.311.10.6.1": "Key Pack Licenses",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "1.3.6.1.4.1.311.10.3.8": "Embedded Windows System Component Verification",
    "1.3.6.1.4.1.311.10.3.20": "Windows Kits Component",
    "1.3.6.1.4.1.311.10.3.5": "Windows Hardware Driver Verification",
    "1.3.6.1.4.1.311.10.3.39": "Windows Hardware Driver Extended Verification",
    "1.3.6.1.4.1.311.10.6.2": "License Server Verification",
    "1.3.6.1.4.1.311.10.3.5.1": "Windows Hardware Driver Attested Verification",
    "1.3.6.1.4.1.311.76.5.1": "Dynamic Code Generator",
    "1.3.6.1.4.1.311.10.3.4.1": "File Recovery",
    "1.3.6.1.4.1.311.2.6.1": "SpcRelaxedPEMarkerCheck",
    "1.3.6.1.4.1.311.2.6.2": "SpcEncryptedDigestRetryCount",
    "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
    "1.3.6.1.4.1.311.61.5.1": "HAL Extension",
    "1.3.6.1.4.1.311.10.3.9": "Root List Signer",
    "1.3.6.1.4.1.311.10.3.30": "Disallowed List",
    "1.3.6.1.4.1.311.10.3.19": "Revoked List Signer",
    "1.3.6.1.4.1.311.10.3.21": "Windows RT Verification",
    "1.3.6.1.4.1.311.10.3.10": "Qualified Subordination",
    "1.3.6.1.4.1.311.10.3.12": "Document Signing",
    "1.3.6.1.4.1.311.10.3.24": "Protected Process Verification",
    "1.3.6.1.4.1.311.80.1": "Document Encryption",
    "1.3.6.1.4.1.311.10.3.22": "Protected Process Light Verification",
    "1.3.6.1.4.1.311.21.19": "Directory Service Email Replication",
    "1.3.6.1.4.1.311.21.5": "Private Key Archival",
    "1.3.6.1.4.1.311.10.5.1": "Digital Rights",
    "1.3.6.1.4.1.311.10.3.27": "Preview Build Signing",
    "1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent",
    "1.3.6.1.4.1.311.20.1": "CTL Usage",
    "1.3.6.1.4.1.311.10.3.1": "Microsoft Trust List Signing",
    "1.3.6.1.4.1.311.10.3.2": "Microsoft Time Stamping",
    "1.3.6.1.4.1.311.76.8.1": "Microsoft Publisher",
    # Standard certificate usages
    "1.3.6.1.5.5.7.3.1": "Server Authentication",
    "1.3.6.1.5.5.7.3.2": "Client Authentication",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.5.5.7.3.4": "Secure Email",
    "1.3.6.1.5.5.7.3.5": "IP security end system",
    "1.3.6.1.5.5.7.3.6": "IP security tunnel termination",
    "1.3.6.1.5.5.7.3.7": "IP security use",
    "1.3.6.1.5.5.7.3.8": "Time Stamping",
    "1.3.6.1.5.5.7.3.9": "OCSP Signing",
    "1.3.6.1.5.5.8.2.2": "IP security IKE intermediate",
    # Attestation and Platform Trust
    "2.23.133.8.1": "Endorsement Key Certificate",
    "2.23.133.8.2": "Platform Certificate",
    "2.23.133.8.3": "Attestation Identity Key Certificate",
    # Kerberos
    "1.3.6.1.5.2.3.4": "PKINIT Client Authentication",
    "1.3.6.1.5.2.3.5": "KDC Authentication",
    # Special purpose
    "1.3.6.1.4.1.311.10.3.13": "Lifetime Signing",
    "2.5.29.37.0": "Any Purpose",
    "1.3.6.1.4.1.311.64.1.1": "Server Trust",
}

OID_TO_STR_NAME_MAP = {v.lower(): k for k, v in OID_TO_STR_MAP.items()}


# =========================================================================
# Extended Rights Mapping
# =========================================================================

# Extended rights mapping from UUID to name
# Retrieved from Windows 2022 server via LDAP (CN=Extended-Rights,CN=Configuration,DC=...)
EXTENDED_RIGHTS_MAP = {
    # Domain administration
    "ab721a52-1e2f-11d0-9819-00aa0040529b": "Domain-Administer-Server",
    "e48d0154-bcf8-11d1-8702-00c04fb96050": "Public-Information",
    "4c164200-20c0-11d0-a768-00aa006e0529": "User-Account-Restrictions",
    "59ba2f42-79a2-11d0-9020-00c04fc2d3cf": "General-Information",
    "77b5b886-944a-11d1-aebd-0000f80367c1": "Personal-Information",
    "e45795b2-9455-11d1-aebd-0000f80367c1": "Email-Information",
    "e45795b3-9455-11d1-aebd-0000f80367c1": "Web-Information",
    "91e647de-d96f-4b70-9557-d63ff4f3ccd8": "Private-Information",
    "037088f8-0ae1-11d2-b422-00a0c968f939": "RAS-Information",
    # Password and authentication rights
    "ab721a53-1e2f-11d0-9819-00aa0040529b": "User-Change-Password",
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
    "c7407360-20bf-11d0-a768-00aa006e0529": "Domain-Password",
    "ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501": "Unexpire-Password",
    "280f369c-67c7-438e-ae98-1d46f3c6f541": "Update-Password-Not-Required-Bit",
    "05c74c5e-4deb-43b4-bd9f-86664c2a7fd5": "Enable-Per-User-Reversibly-Encrypted-Password",
    # Replication and directory service rights
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Synchronize",
    "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Manage-Topology",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
    "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2": "Read-Only-Replication-Secret-Synchronization",
    "9923a32a-3607-11d2-b9be-0000f87a36b2": "DS-Install-Replica",
    "f98340fb-7c5b-4cdb-a00b-2ebdfa115a96": "DS-Replication-Monitor-Topology",
    "4125c71f-7fac-4ff0-bcb7-f09a41325286": "DS-Set-Owner",
    "084c93a2-620d-4879-a836-f0ae47de0e89": "DS-Read-Partition-Secrets",
    "94825a8d-b171-4116-8146-1e34d8f54401": "DS-Write-Partition-Secrets",
    "4ecc03fe-ffc0-4947-b630-eb672a8a9dbc": "DS-Query-Self-Quota",
    "88a9933e-e5c8-4f2a-9dd7-2527416b8092": "DS-Bypass-Quota",
    "9b026da6-0d3c-465c-8bee-5199d7165cba": "DS-Validated-Write-Computer",
    # Infrastructure roles and operations
    "e12b56b6-0a95-11d1-adbb-00c04fd8d5cd": "Change-Schema-Master",
    "d58d5f36-0a98-11d1-adbb-00c04fd8d5cd": "Change-Rid-Master",
    "fec364e0-0a98-11d1-adbb-00c04fd8d5cd": "Do-Garbage-Collection",
    "0bc1554e-0a99-11d1-adbb-00c04fd8d5cd": "Recalculate-Hierarchy",
    "1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd": "Allocate-Rids",
    "bae50096-4752-11d1-9052-00c04fc2d4cf": "Change-PDC",
    "014bf69c-7b3b-11d1-85f6-08002be74fab": "Change-Domain-Master",
    "cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd": "Change-Infrastructure-Master",
    "be2bb760-7f46-11d2-b9ad-00c04f79f805": "Update-Schema-Cache",
    "62dd28a8-7f46-11d2-b9ad-00c04f79f805": "Recalculate-Security-Inheritance",
    "69ae6200-7f46-11d2-b9ad-00c04f79f805": "DS-Check-Stale-Phantoms",
    "440820ad-65b4-11d1-a3da-0000f875ae0d": "Add-GUID",
    "2f16c4a5-b98e-432c-952a-cb388ba33f2e": "DS-Execute-Intentions-Script",
    # Email and messaging related
    "ab721a54-1e2f-11d0-9819-00aa0040529b": "Send-As",
    "ab721a56-1e2f-11d0-9819-00aa0040529b": "Receive-As",
    "ab721a55-1e2f-11d0-9819-00aa0040529b": "Send-To",
    "4b6e08c0-df3c-11d1-9c86-006008764d0e": "msmq-Receive-Dead-Letter",
    "4b6e08c1-df3c-11d1-9c86-006008764d0e": "msmq-Peek-Dead-Letter",
    "4b6e08c2-df3c-11d1-9c86-006008764d0e": "msmq-Receive-computer-Journal",
    "4b6e08c3-df3c-11d1-9c86-006008764d0e": "msmq-Peek-computer-Journal",
    "06bd3200-df3e-11d1-9c86-006008764d0e": "msmq-Receive",
    "06bd3201-df3e-11d1-9c86-006008764d0e": "msmq-Peek",
    "06bd3202-df3e-11d1-9c86-006008764d0e": "msmq-Send",
    "06bd3203-df3e-11d1-9c86-006008764d0e": "msmq-Receive-journal",
    "b4e60130-df3f-11d1-9c86-006008764d0e": "msmq-Open-Connector",
    # Authentication and access
    "5f202010-79a5-11d0-9020-00c04fc2d4cf": "User-Logon",
    "bc0ac240-79a9-11d0-9020-00c04fc2d4cf": "Membership",
    "a1990816-4298-11d1-ade2-00c04fd8d5cd": "Open-Address-Book",
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "Self-Membership",
    "72e39547-7b18-11d1-adef-00c04fd8d5cd": "DNS-Host-Name-Attributes",
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "Validated-SPN",
    "ba33815a-4f93-4c76-87f3-57574bff8109": "Migrate-SID-History",
    "45ec5156-db7e-47bb-b53f-dbeb2d03c40f": "Reanimate-Tombstones",
    "68b1d179-0d15-4d4f-ab71-46152e79a7bc": "Allowed-To-Authenticate",
    "91d67418-0135-4acc-8d79-c08e857cfbec": "SAM-Enumerate-Entire-Domain",
    "d31a8757-2447-4545-8081-3bb610cacbf2": "Validated-MS-DS-Behavior-Version",
    "80863791-dbe9-4eb8-837e-7f0ab55d9ac7": "Validated-MS-DS-Additional-DNS-Host-Name",
    "3e0f7e18-2c7a-4c10-ba82-4d926db99a3e": "DS-Clone-Domain-Controller",
    # Policy and system management
    "edacfd8f-ffb3-11d1-b41d-00a0c968f939": "Apply-Group-Policy",
    "b7b1b3dd-ab09-4242-9e30-9980e5d322f7": "Generate-RSoP-Planning",
    "b7b1b3de-ab09-4242-9e30-9980e5d322f7": "Generate-RSoP-Logging",
    "9432c620-033c-4db7-8b58-14ef6d0bf477": "Refresh-Group-Cache",
    "b8119fd0-04f6-4762-ab7a-4986c76b3f9a": "Domain-Other-Parameters",
    "e2a36dc9-ae17-47c3-b58b-be34c55ba633": "Create-Inbound-Forest-Trust",
    "7726b9d5-a4b4-4288-a6b2-dce952e80a7f": "Run-Protect-Admin-Groups-Task",
    "7c0e2a7c-a419-48e4-a995-10180aad54dd": "Manage-Optional-Features",
    # Certificate and cryptography
    "0e10c968-78fb-11d2-90d4-00c04f79dc55": "Enroll",
    "a05b8cc2-17bc-4802-a710-e7c15ab866a2": "AutoEnroll",
    "1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8": "Reload-SSL-Certificate",
    "5805bc62-bdc9-4428-a5e2-856a0f4c185e": "Terminal-Server-License-Server",
    "ffa6f046-ca4b-4feb-b40d-04dfee722543": "MS-TS-GatewayAccess",
    # Special rights
    "00000000-0000-0000-0000-000000000000": "All-Extended-Rights",
}

# Create reverse mapping from name to UUID for lookup by name
EXTENDED_RIGHTS_NAME_MAP = {v: k for k, v in EXTENDED_RIGHTS_MAP.items()}
