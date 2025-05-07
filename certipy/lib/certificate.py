"""
Certificate handling utilities for Certipy.

This module provides functions and classes for:
- Creating and manipulating X.509 certificates and CSRs
- Handling private keys in various formats
- Supporting Microsoft certificate extensions
- Creating PKCS#12 (PFX) files
- Implementing certificate renewal and archival operations

Key components:
- Certificate creation and conversion functions
- CSR (Certificate Signing Request) operations
- Support for Microsoft-specific extensions
- Key management utilities
"""

import argparse
import base64
import math
import os
import struct
import sys
from typing import List, Optional, Tuple, Union

from asn1crypto import cms as asn1cms
from asn1crypto import core as asn1core
from asn1crypto import csr as asn1csr
from asn1crypto import x509 as asn1x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    padding,
    rsa,
)
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    pkcs12,
)
from cryptography.x509 import SubjectAlternativeName, SubjectKeyIdentifier
from cryptography.x509.oid import ExtensionOID, NameOID
from impacket.dcerpc.v5.nrpc import checkNullString
from pyasn1.codec.der import decoder
from pyasn1.type.char import UTF8String

from certipy.lib.files import try_to_save_file
from certipy.lib.logger import logging
from certipy.lib.structs import (
    CMCAddAttributesInfo,
    EnrollmentNameValuePair,
    OtherMsgs,
    PKIData,
    TaggedAttribute,
    TaggedCertificationRequest,
    TaggedContentInfos,
    TaggedRequest,
)

# =========================================================================
# Constants and mappings
# =========================================================================

# Map common DN attribute names to cryptography OIDs
DN_MAP = {
    "CN": NameOID.COMMON_NAME,
    "SN": NameOID.SURNAME,
    "SERIALNUMBER": NameOID.SERIAL_NUMBER,
    "C": NameOID.COUNTRY_NAME,
    "L": NameOID.LOCALITY_NAME,
    "S": NameOID.STATE_OR_PROVINCE_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "STREET": NameOID.STREET_ADDRESS,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "T": NameOID.TITLE,
    "TITLE": NameOID.TITLE,
    "G": NameOID.GIVEN_NAME,
    "GN": NameOID.GIVEN_NAME,
    "E": NameOID.EMAIL_ADDRESS,
    "UID": NameOID.USER_ID,
    "DC": NameOID.DOMAIN_COMPONENT,
}

# Microsoft-specific OIDs
PRINCIPAL_NAME = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
NTDS_CA_SECURITY_EXT = x509.ObjectIdentifier("1.3.6.1.4.1.311.25.2")
NTDS_OBJECTSID = x509.ObjectIdentifier("1.3.6.1.4.1.311.25.2.1")

# Microsoft-specific ASN.1 OIDs
szOID_RENEWAL_CERTIFICATE = asn1cms.ObjectIdentifier("1.3.6.1.4.1.311.13.1")
szOID_ENCRYPTED_KEY_HASH = asn1cms.ObjectIdentifier("1.3.6.1.4.1.311.21.21")
szOID_PRINCIPAL_NAME = asn1cms.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
szOID_CMC_ADD_ATTRIBUTES = asn1cms.ObjectIdentifier("1.3.6.1.4.1.311.10.10.1")
szOID_NTDS_CA_SECURITY_EXT = asn1cms.ObjectIdentifier("1.3.6.1.4.1.311.25.2")
szOID_NTDS_OBJECTSID = asn1cms.ObjectIdentifier("1.3.6.1.4.1.311.25.2.1")

# Register Microsoft-specific extensions
asn1x509.ExtensionId._map.update(
    {
        "1.3.6.1.4.1.311.25.2": "security_ext",
    }
)

asn1x509.Extension._oid_specs.update(
    {
        "security_ext": asn1x509.GeneralNames,
    }
)

asn1x509.Extension._oid_specs.update(
    {
        "smime_capability": asn1core.ObjectIdentifier,  # type: ignore
    }
)  # type: ignore

# SMIME capabilities mapping
SMIME_MAP = {
    "des": "1.3.14.3.2.7",
    "rc4": "1.2.840.113549.3.4",
    "3des": "1.2.840.113549.1.9.16.3.6",
    "aes128": "2.16.840.1.101.3.4.1.5",
    "aes192": "2.16.840.1.101.3.4.1.25",
    "aes256": "2.16.840.1.101.3.4.1.45",
}


# =========================================================================
# Certificate identification and parsing functions
# =========================================================================


def cert_id_to_parts(
    identifications: List[Tuple[Optional[str], Optional[str]]],
) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract username and domain from certificate identifications.

    Args:
        identifications: List of (id_type, id_value) tuples from certificate

    Returns:
        Tuple of (username, domain)
    """
    usernames: List[str] = []
    domains: List[str] = []

    if len(identifications) == 0:
        return (None, None)

    for id_type, identification in identifications:
        if id_type is None or identification is None:
            continue

        if id_type != "DNS Host Name" and id_type != "UPN":
            continue

        cert_username = ""
        cert_domain = ""

        if id_type == "DNS Host Name":
            parts = identification.split(".")
            if len(parts) == 1:
                cert_username = identification
                cert_domain = ""
            else:
                cert_username = parts[0] + "$"
                cert_domain = ".".join(parts[1:])
        elif id_type == "UPN":
            parts = identification.split("@")
            if len(parts) == 1:
                cert_username = identification
                cert_domain = ""
            else:
                cert_username = "@".join(parts[:-1])
                cert_domain = parts[-1]

        usernames.append(cert_username)
        domains.append(cert_domain)

    return ("_".join(usernames), "_".join(domains))


def get_identifications_from_certificate(
    certificate: x509.Certificate,
) -> List[Tuple[str, str]]:
    """
    Extract identity information from a certificate.

    Args:
        certificate: X.509 certificate to analyze

    Returns:
        List of tuples with (id_type, id_value)
    """
    identifications = []

    try:
        # Get Subject Alternative Name extension
        san = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )

        if not isinstance(san.value, SubjectAlternativeName):
            raise ValueError("Invalid SAN value")

        # Extract UPN from OtherName fields
        for name in san.value.get_values_for_type(x509.OtherName):
            if name.type_id == PRINCIPAL_NAME:
                identifications.append(
                    (
                        "UPN",
                        decoder.decode(name.value, asn1Spec=UTF8String)[0].decode(),
                    )
                )

        # Extract DNS names
        for name in san.value.get_values_for_type(x509.DNSName):
            identifications.append(("DNS Host Name", name))

    except Exception:
        pass  # Ignore errors if SAN is missing or malformed

    return identifications


def get_object_sid_from_certificate(
    certificate: x509.Certificate,
) -> Optional[str]:
    """
    Extract the object SID from a certificate.

    Args:
        certificate: X.509 certificate to analyze

    Returns:
        Security Identifier as string, or None if not found
    """
    try:
        # Get Microsoft security extension
        object_sid = certificate.extensions.get_extension_for_oid(NTDS_CA_SECURITY_EXT)

        if not isinstance(object_sid.value, x509.UnrecognizedExtension):
            raise ValueError(
                f"Expected UnrecognizedExtension, got {type(object_sid.value)}"
            )

        # Extract SID string
        sid = object_sid.value.value
        return sid[sid.find(b"S-1-5") :].decode()

    except Exception:
        pass  # Ignore errors if extension is missing or malformed

    return None


# =========================================================================
# Format conversion utilities
# =========================================================================


def csr_to_der(csr: x509.CertificateSigningRequest) -> bytes:
    """Convert CSR to DER format."""
    return csr.public_bytes(Encoding.DER)


def csr_to_pem(csr: x509.CertificateSigningRequest) -> bytes:
    """Convert CSR to PEM format."""
    return csr.public_bytes(Encoding.PEM)


def cert_to_pem(cert: x509.Certificate) -> bytes:
    """Convert certificate to PEM format."""
    return cert.public_bytes(Encoding.PEM)


def cert_to_der(cert: x509.Certificate) -> bytes:
    """Convert certificate to DER format."""
    return cert.public_bytes(Encoding.DER)


def key_to_pem(key: PrivateKeyTypes) -> bytes:
    """
    Convert private key to PEM format (PKCS#8).

    Args:
        key: Private key object

    Returns:
        PEM-encoded key as bytes
    """
    return key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
    )


def key_to_der(key: PrivateKeyTypes) -> bytes:
    """
    Convert private key to DER format (PKCS#8).

    Args:
        key: Private key object

    Returns:
        DER-encoded key as bytes
    """
    return key.private_bytes(
        Encoding.DER, PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
    )


def der_to_pem(der: bytes, pem_type: str) -> str:
    """
    Convert DER-encoded data to PEM format.

    Args:
        der: DER-encoded binary data
        pem_type: PEM header/footer type (e.g., "CERTIFICATE")

    Returns:
        PEM-encoded data as string
    """
    pem_type = pem_type.upper()
    b64_data = base64.b64encode(der).decode()
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (
        pem_type,
        "\n".join([b64_data[i : i + 64] for i in range(0, len(b64_data), 64)]),
        pem_type,
    )


def der_to_csr(csr: bytes) -> x509.CertificateSigningRequest:
    """Convert DER-encoded CSR to object."""
    return x509.load_der_x509_csr(csr)


def der_to_key(key: bytes) -> PrivateKeyTypes:
    """Convert DER-encoded private key to object."""
    return serialization.load_der_private_key(key, None)


def pem_to_key(key: bytes) -> PrivateKeyTypes:
    """Convert PEM-encoded private key to object."""
    return serialization.load_pem_private_key(key, None)


def der_to_cert(certificate: bytes) -> x509.Certificate:
    """Convert DER-encoded certificate to object."""
    return x509.load_der_x509_certificate(certificate)


def pem_to_cert(certificate: bytes) -> x509.Certificate:
    """Convert PEM-encoded certificate to object."""
    return x509.load_pem_x509_certificate(certificate)


# =========================================================================
# Key and certificate operations
# =========================================================================


def generate_rsa_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """
    Generate a new RSA private key.

    Args:
        key_size: Key size in bits (default: 2048)

    Returns:
        RSA private key object
    """
    return rsa.generate_private_key(public_exponent=0x10001, key_size=key_size)


def private_key_to_ms_blob(private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Convert RSA private key to Microsoft BLOB format.

    Args:
        private_key: RSA private key

    Returns:
        Microsoft BLOB format key data
    """
    # Get key size
    bitlen = private_key.key_size
    private_numbers = private_key.private_numbers()
    public_numbers = private_numbers.public_numbers

    # Calculate byte lengths
    bitlen8 = math.ceil(bitlen / 8)
    bitlen16 = math.ceil(bitlen / 16)

    # Pack in Microsoft's format
    return struct.pack(
        "<bbHI4sII%ds%ds%ds%ds%ds%ds%ds"
        % (bitlen8, bitlen16, bitlen16, bitlen16, bitlen16, bitlen16, bitlen8),
        7,  # PRIVATEKEYBLOB
        2,  # Version
        0,  # Reserved
        41984,  # Algorithm ID
        b"RSA2",  # Magic
        bitlen,  # Key size in bits
        public_numbers.e,  # Public exponent
        public_numbers.n.to_bytes(bitlen8, "little"),  # Modulus
        private_numbers.p.to_bytes(bitlen16, "little"),  # Prime 1
        private_numbers.q.to_bytes(bitlen16, "little"),  # Prime 2
        private_numbers.dmp1.to_bytes(bitlen16, "little"),  # Exponent 1
        private_numbers.dmq1.to_bytes(bitlen16, "little"),  # Exponent 2
        private_numbers.iqmp.to_bytes(bitlen16, "little"),  # Coefficient
        private_numbers.d.to_bytes(bitlen8, "little"),  # Private exponent
    )


def create_pfx(
    key: PrivateKeyTypes, cert: x509.Certificate, password: Optional[str] = None
) -> bytes:
    """
    Create a PKCS#12/PFX container with certificate and private key.

    Args:
        key: Private key object
        cert: Certificate object
        password: Optional encryption password

    Returns:
        PKCS#12 data as bytes

    Raises:
        TypeError: If key type is not supported
    """
    # Validate key type
    if not (
        isinstance(key, rsa.RSAPrivateKey)
        or isinstance(key, dsa.DSAPrivateKey)
        or isinstance(key, ec.EllipticCurvePrivateKey)
        or isinstance(key, ed25519.Ed25519PrivateKey)
        or isinstance(key, ed448.Ed448PrivateKey)
    ):
        # Log error with details to help diagnose the issue
        logging.error(
            "Private key must be an instance of RSAPrivateKey, DSAPrivateKey, "
            f"EllipticCurvePrivateKey, Ed25519PrivateKey or Ed448PrivateKey. Received {type(key)}"
        )
        logging.error("Dumping private key to PEM format")
        logging.error(
            key.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
            )
        )
        logging.error("Dumping certificate to PEM format")
        logging.error(cert.public_bytes(Encoding.PEM))
        raise TypeError(
            "Private key must be an instance of RSAPrivateKey, DSAPrivateKey, "
            "EllipticCurvePrivateKey, Ed25519PrivateKey or Ed448PrivateKey"
        )

    # Configure encryption algorithm
    encryption = NoEncryption()
    if password is not None:
        encryption = (
            PrivateFormat.PKCS12.encryption_builder()
            .kdf_rounds(50000)
            .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
            .hmac_hash(hashes.SHA1())
            .build(bytes(password, "utf-8"))
        )

    # Create PFX
    return pkcs12.serialize_key_and_certificates(
        name=b"",
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=encryption,
    )


def load_pfx(
    pfx: bytes, password: Optional[bytes] = None
) -> Tuple[Optional[PrivateKeyTypes], Optional[x509.Certificate]]:
    """
    Load key and certificate from PKCS#12/PFX data.

    Args:
        pfx: PKCS#12 data
        password: Optional decryption password

    Returns:
        Tuple of (private_key, certificate)
    """
    return pkcs12.load_key_and_certificates(pfx, password)[:-1]


def rsa_pkcs1v15_sign(
    data: bytes,
    key: PrivateKeyTypes,
    hash_algorithm: type[hashes.HashAlgorithm] = hashes.SHA256,
) -> bytes:
    """
    Sign data using RSA PKCS#1 v1.5 padding.

    Args:
        data: Data to sign
        key: Private key for signing
        hash_algorithm: Hash algorithm to use

    Returns:
        Signature bytes

    Raises:
        TypeError: If key is not an RSA private key
    """
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("key must be an instance of RSAPrivateKey")

    return key.sign(data, padding.PKCS1v15(), hash_algorithm())


def hash_digest(data: bytes, hash_algorithm: type[hashes.HashAlgorithm]) -> bytes:
    """
    Compute hash digest of data.

    Args:
        data: Data to hash
        hash_algorithm: Hash algorithm to use

    Returns:
        Hash digest as bytes
    """
    digest = hashes.Hash(hash_algorithm())
    digest.update(data)
    return digest.finalize()


# =========================================================================
# Subject handling functions
# =========================================================================


def dn_to_components(dn: str) -> List[Tuple[str, str]]:
    """
    Parse a Distinguished Name string into components.

    Args:
        dn: DN string (e.g., "CN=username,DC=domain,DC=local")

    Returns:
        List of (attribute_name, value) tuples
    """
    components = []
    component = ""
    escape_sequence = False

    for c in dn:
        if c == "\\":
            escape_sequence = True
        elif escape_sequence and c != " ":
            escape_sequence = False
        elif c == ",":
            if "=" in component:
                attr_name, _, value = component.partition("=")
                component = (attr_name.strip().upper(), value.strip())
                components.append(component)
                component = ""
                continue

        component += c

    # Add the last component
    attr_name, _, value = component.partition("=")
    component = (attr_name.strip().upper(), value.strip())
    components.append(component)

    return components


def get_subject_from_str(subject: str) -> x509.Name:
    """
    Create a Name object from a subject string.

    Args:
        subject: Subject DN string

    Returns:
        x509.Name object
    """
    return x509.Name(x509.Name.from_rfc4514_string(subject).rdns[::-1])


# =========================================================================
# Certificate Signing Request (CSR) functions
# =========================================================================


def create_csr(
    username: str,
    alt_dns: Optional[Union[bytes, str]] = None,
    alt_upn: Optional[Union[bytes, str]] = None,
    alt_sid: Optional[Union[bytes, str]] = None,
    key: Optional[rsa.RSAPrivateKey] = None,
    key_size: int = 2048,
    subject: Optional[str] = None,
    renewal_cert: Optional[x509.Certificate] = None,
    application_policies: Optional[List[str]] = None,
    smime: Optional[str] = None,
) -> Tuple[x509.CertificateSigningRequest, rsa.RSAPrivateKey]:
    """
    Create a certificate signing request (CSR) with optional extensions.

    Args:
        username: Username for the subject
        alt_dns: Alternative DNS name
        alt_upn: Alternative UPN (User Principal Name)
        alt_sid: Alternative SID (Security Identifier)
        key: RSA private key (generated if None)
        key_size: Key size in bits (for key generation)
        subject: Subject DN string
        renewal_cert: Certificate being renewed
        application_policies: List of application policy OIDs
        smime: SMIME capability identifier

    Returns:
        Tuple of (CSR, private_key)
    """
    # Generate key if not provided
    if key is None:
        logging.debug("Generating RSA key")
        key = generate_rsa_key(key_size)

    # Start building CSR
    certification_request_info = asn1csr.CertificationRequestInfo()
    certification_request_info["version"] = "v1"

    # Set subject name
    if subject:
        subject_name = get_subject_from_str(subject)
    else:
        subject_name = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, username.capitalize()),
            ]
        )

    certification_request_info["subject"] = asn1csr.Name.load(
        subject_name.public_bytes()
    )

    # Set public key
    public_key = key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    subject_pk_info = asn1csr.PublicKeyInfo.load(public_key)
    certification_request_info["subject_pk_info"] = subject_pk_info

    # Build CSR attributes
    cri_attributes = []

    # Add Subject Alternative Name extension if needed
    if alt_dns or alt_upn:
        general_names = []

        # Add DNS name
        if alt_dns:
            if isinstance(alt_dns, bytes):
                alt_dns = alt_dns.decode()
            general_names.append(asn1x509.GeneralName({"dns_name": alt_dns}))

        # Add UPN
        if alt_upn:
            if isinstance(alt_upn, bytes):
                alt_upn = alt_upn.decode()

            general_names.append(
                asn1x509.GeneralName(
                    {
                        "other_name": asn1x509.AnotherName(
                            {
                                "type_id": szOID_PRINCIPAL_NAME,
                                "value": asn1x509.UTF8String(alt_upn).retag(
                                    {"explicit": 0}
                                ),
                            }
                        )
                    }
                )
            )

        # Create SAN extension
        san_extension = asn1x509.Extension(
            {"extn_id": "subject_alt_name", "extn_value": general_names}
        )

        # Add extension to CSR attributes
        set_of_extensions = asn1csr.SetOfExtensions([[san_extension]])
        cri_attribute = asn1csr.CRIAttribute(
            {"type": "extension_request", "values": set_of_extensions}
        )
        cri_attributes.append(cri_attribute)

    # Add SMIME capability extension if requested
    if smime:
        asn1x509.ExtensionId._map.update(
            {
                "1.2.840.113549.1.9.15": "smime_capability",
            }
        )

        # Create SMIME extension
        smime_extension = asn1x509.Extension(
            {"extn_id": "1.2.840.113549.1.9.15", "extn_value": SMIME_MAP[smime]}
        )

        # Add extension to CSR attributes
        set_of_extensions = asn1csr.SetOfExtensions([[smime_extension]])
        cri_attribute = asn1csr.CRIAttribute(
            {"type": "extension_request", "values": set_of_extensions}
        )
        cri_attributes.append(cri_attribute)

    # Add Security Identifier extension if requested
    if alt_sid:
        if isinstance(alt_sid, str):
            alt_sid = alt_sid.encode()

        # Create security extension
        san_extension = asn1x509.Extension(
            {
                "extn_id": "security_ext",
                "extn_value": [
                    asn1x509.GeneralName(
                        {
                            "other_name": asn1x509.AnotherName(
                                {
                                    "type_id": szOID_NTDS_OBJECTSID,
                                    "value": asn1x509.OctetString(alt_sid).retag(
                                        {"explicit": 0}
                                    ),
                                }
                            )
                        }
                    )
                ],
            }
        )

        # Add extension to CSR attributes
        set_of_extensions = asn1csr.SetOfExtensions([[san_extension]])
        cri_attribute = asn1csr.CRIAttribute(
            {"type": "extension_request", "values": set_of_extensions}
        )
        cri_attributes.append(cri_attribute)

    # Add renewal certificate if provided
    if renewal_cert:
        cri_attributes.append(
            asn1csr.CRIAttribute(
                {
                    "type": "1.3.6.1.4.1.311.13.1",
                    "values": asn1x509.SetOf(
                        [asn1x509.Certificate.load(cert_to_der(renewal_cert))],
                        spec=asn1x509.Certificate,
                    ),
                }
            )
        )

    # Add Microsoft Application Policies if requested
    if application_policies:
        # Convert each policy OID string to PolicyIdentifier
        application_policy_oids = [
            asn1x509.PolicyInformation(
                {"policy_identifier": asn1x509.PolicyIdentifier(ap)}
            )
            for ap in application_policies
        ]

        # Create certificate policies extension
        cert_policies = asn1x509.CertificatePolicies(application_policy_oids)
        der_encoded_cert_policies = cert_policies.dump()

        # Create application policies extension
        app_policy_extension = asn1x509.Extension(
            {
                "extn_id": "1.3.6.1.4.1.311.21.10",  # OID for Microsoft Application Policies
                "critical": False,
                "extn_value": asn1x509.ParsableOctetString(der_encoded_cert_policies),
            }
        )

        # Add extension to CSR attributes
        set_of_extensions = asn1csr.SetOfExtensions([[app_policy_extension]])
        cri_attribute = asn1csr.CRIAttribute(
            {"type": "extension_request", "values": set_of_extensions}
        )
        cri_attributes.append(cri_attribute)

    # Set all CSR attributes
    certification_request_info["attributes"] = cri_attributes

    # Sign the CSR
    signature = rsa_pkcs1v15_sign(certification_request_info.dump(), key)

    # Create the final CSR
    csr = asn1csr.CertificationRequest(
        {
            "certification_request_info": certification_request_info,
            "signature_algorithm": asn1csr.SignedDigestAlgorithm(
                {"algorithm": "sha256_rsa"}
            ),
            "signature": signature,
        }
    )

    return (der_to_csr(csr.dump()), key)


# =========================================================================
# Advanced certificate operations
# =========================================================================


def create_renewal(
    request: bytes,
    cert: x509.Certificate,
    key: rsa.RSAPrivateKey,
) -> bytes:
    """
    Create a certificate renewal request.

    Args:
        request: Original request data
        cert: Certificate being renewed
        key: Private key for signing

    Returns:
        CMC renewal request as bytes

    Raises:
        ValueError: If signature algorithm is not set
    """
    x509_cert = asn1x509.Certificate.load(cert_to_der(cert))
    signature_hash_algorithm = cert.signature_hash_algorithm.__class__

    if signature_hash_algorithm is type(None):
        raise ValueError("Signature hash algorithm is not set in the certificate")

    # Create SignerInfo

    issuer_and_serial = asn1cms.IssuerAndSerialNumber(
        {
            "issuer": x509_cert.issuer,
            "serial_number": x509_cert.serial_number,
        }
    )

    digest_algorithm = asn1cms.DigestAlgorithm(
        {"algorithm": signature_hash_algorithm.name}
    )

    # Create signed attributes with renewal certificate
    signed_attribs = asn1cms.CMSAttributes(
        [
            asn1cms.CMSAttribute(
                {
                    "type": "1.3.6.1.4.1.311.13.1",
                    "values": asn1cms.SetOfAny(
                        [asn1x509.Certificate.load(cert_to_der(cert))],
                        spec=asn1x509.Certificate,
                    ),
                }
            ),
            asn1cms.CMSAttribute(
                {
                    "type": "message_digest",
                    "values": [hash_digest(request, signature_hash_algorithm)],
                }
            ),
        ]
    )

    # Sign the attributes
    attribs_signature = rsa_pkcs1v15_sign(
        signed_attribs.dump(), key, hash_algorithm=signature_hash_algorithm
    )

    # Create SignerInfo
    signer_info = asn1cms.SignerInfo(
        {
            "version": 1,
            "sid": issuer_and_serial,
            "digest_algorithm": digest_algorithm,
            "signature_algorithm": x509_cert["signature_algorithm"],
            "signature": attribs_signature,
            "signed_attrs": signed_attribs,
        }
    )

    # Create SignedData

    content_info = asn1cms.EncapsulatedContentInfo(
        {
            "content_type": "data",
            "content": request,
        }
    )

    signed_data = asn1cms.SignedData(
        {
            "version": 3,
            "digest_algorithms": [digest_algorithm],
            "encap_content_info": content_info,
            "certificates": [asn1cms.CertificateChoices({"certificate": x509_cert})],
            "signer_infos": [signer_info],
        }
    )

    # Create CMC ContentInfo

    cmc = asn1cms.ContentInfo(
        {
            "content_type": "signed_data",
            "content": signed_data,
        }
    )

    return cmc.dump()


def create_on_behalf_of(
    request: bytes,
    on_behalf_of: str,
    cert: x509.Certificate,
    key: rsa.RSAPrivateKey,
) -> bytes:
    """
    Create a certificate request on behalf of another user.

    Args:
        request: Original request data
        on_behalf_of: Username to request on behalf of
        cert: Certificate for signing
        key: Private key for signing

    Returns:
        CMC on-behalf-of request as bytes

    Raises:
        ValueError: If signature algorithm is not set
    """
    x509_cert = asn1x509.Certificate.load(cert_to_der(cert))
    signature_hash_algorithm = cert.signature_hash_algorithm.__class__

    if signature_hash_algorithm is type(None):
        raise ValueError("Signature hash algorithm is not set in the certificate")

    # Create SignerInfo

    issuer_and_serial = asn1cms.IssuerAndSerialNumber(
        {
            "issuer": x509_cert.issuer,
            "serial_number": x509_cert.serial_number,
        }
    )

    digest_algorithm = asn1cms.DigestAlgorithm(
        {"algorithm": signature_hash_algorithm.name}
    )

    # Create requester name attribute
    requester_name = EnrollmentNameValuePair(
        {
            "name": checkNullString("requestername"),
            "value": checkNullString(on_behalf_of),
        }
    )

    # Create signed attributes with requester name
    signed_attribs = asn1cms.CMSAttributes(
        [
            asn1cms.CMSAttribute(
                {"type": "1.3.6.1.4.1.311.13.2.1", "values": [requester_name]}
            ),
            asn1cms.CMSAttribute(
                {
                    "type": "message_digest",
                    "values": [hash_digest(request, signature_hash_algorithm)],
                }
            ),
        ]
    )

    # Sign the attributes
    attribs_signature = rsa_pkcs1v15_sign(
        signed_attribs.dump(), key, hash_algorithm=signature_hash_algorithm
    )

    # Create SignerInfo
    signer_info = asn1cms.SignerInfo(
        {
            "version": 1,
            "sid": issuer_and_serial,
            "digest_algorithm": digest_algorithm,
            "signature_algorithm": x509_cert["signature_algorithm"],
            "signature": attribs_signature,
            "signed_attrs": signed_attribs,
        }
    )

    # Create SignedData

    content_info = asn1cms.EncapsulatedContentInfo(
        {
            "content_type": "data",
            "content": request,
        }
    )

    signed_data = asn1cms.SignedData(
        {
            "version": 3,
            "digest_algorithms": [digest_algorithm],
            "encap_content_info": content_info,
            "certificates": [asn1cms.CertificateChoices({"certificate": x509_cert})],
            "signer_infos": [signer_info],
        }
    )

    # Create CMC ContentInfo

    cmc = asn1cms.ContentInfo(
        {
            "content_type": "signed_data",
            "content": signed_data,
        }
    )

    return cmc.dump()


def create_key_archival(
    csr: x509.CertificateSigningRequest,
    private_key: rsa.RSAPrivateKey,
    cax_cert: x509.Certificate,
) -> bytes:
    """
    Create a key archival request.

    Args:
        csr: Certificate signing request
        private_key: Private key to be archived
        cax_cert: Key archival agent certificate

    Returns:
        CMC key archival request as bytes

    Raises:
        ValueError: If signature algorithm is not set
        TypeError: If CAX certificate doesn't have an RSA public key
    """
    x509_cax_cert = asn1x509.Certificate.load(cert_to_der(cax_cert))
    x509_csr = asn1csr.CertificationRequest.load(csr_to_der(csr))

    signature_hash_algorithm = csr.signature_hash_algorithm.__class__

    if signature_hash_algorithm is type(None):
        raise ValueError("Signature hash algorithm is not set in the CSR")

    # Generate symmetric encryption key and IV
    symmetric_key = os.urandom(32)  # 256-bit AES key
    iv = os.urandom(16)  # 128-bit IV for CBC mode

    # Get CAX certificate public key
    cax_key = cax_cert.public_key()

    if not isinstance(cax_key, rsa.RSAPublicKey):
        raise TypeError("cax_key must be an instance of RSAPublicKey")

    # Encrypt symmetric key with CAX public key
    encrypted_key = cax_key.encrypt(symmetric_key, padding.PKCS1v15())

    # Create EnvelopedData

    # Set up recipient info
    cax_issuer_and_serial = asn1cms.IssuerAndSerialNumber(
        {
            "issuer": x509_cax_cert.issuer,
            "serial_number": x509_cax_cert.serial_number,
        }
    )
    recipient_info = asn1cms.KeyTransRecipientInfo(
        {
            "version": 0,
            "rid": cax_issuer_and_serial,
            "key_encryption_algorithm": asn1cms.KeyEncryptionAlgorithm(
                {"algorithm": "rsaes_pkcs1v15"}
            ),
            "encrypted_key": encrypted_key,
        }
    )

    # Set up encryption algorithm parameters
    encryption_algorithm = asn1cms.EncryptionAlgorithm(
        {"algorithm": "aes256_cbc", "parameters": iv}
    )

    # Convert private key to Microsoft BLOB format
    private_key_bytes = private_key_to_ms_blob(private_key)

    # Encrypt private key with symmetric key
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))

    # Pad data to block size
    padder = PKCS7(encryption_algorithm.encryption_block_size * 8).padder()
    padded_private_key_bytes = padder.update(private_key_bytes) + padder.finalize()

    # Encrypt the padded data
    encryptor = cipher.encryptor()
    encrypted_private_key_bytes = (
        encryptor.update(padded_private_key_bytes) + encryptor.finalize()
    )

    # Create encrypted content info
    encrypted_content_info = asn1cms.EncryptedContentInfo(
        {
            "content_type": "data",
            "content_encryption_algorithm": encryption_algorithm,
            "encrypted_content": encrypted_private_key_bytes,
        }
    )

    # Create enveloped data structure
    enveloped_data = asn1cms.EnvelopedData(
        {
            "version": 0,
            "recipient_infos": asn1cms.RecipientInfos([recipient_info]),
            "encrypted_content_info": encrypted_content_info,
        }
    )

    # Wrap in ContentInfo
    enveloped_data_info = asn1cms.ContentInfo(
        {
            "content_type": "1.2.840.113549.1.7.3",
            "content": enveloped_data,
        }
    )

    # Calculate encrypted key hash
    encrypted_key_hash = hash_digest(
        enveloped_data_info.dump(), signature_hash_algorithm
    )

    # Create PKIData

    # Create attribute set with encrypted key hash
    attributes = asn1csr.SetOfAttributes(
        [
            asn1csr.Attribute(
                {
                    "type": szOID_ENCRYPTED_KEY_HASH,
                    "values": [asn1core.OctetString(encrypted_key_hash)],
                }
            )
        ]
    )

    # Create CMC add attributes info
    attributes_info = CMCAddAttributesInfo(
        {"data_reference": 0, "cert_reference": [1], "attributes": attributes}
    )

    # Create tagged attribute
    tagged_attribute = TaggedAttribute(
        {
            "bodyPartID": 2,
            "attrType": szOID_CMC_ADD_ATTRIBUTES,
            "attrValues": [attributes_info],
        }
    )

    # Create tagged request with CSR
    tagged_request = TaggedRequest(
        {
            "tcr": TaggedCertificationRequest(
                {
                    "bodyPartID": 1,
                    "certificationRequest": asn1csr.CertificationRequest().load(
                        csr_to_der(csr)
                    ),
                }
            )
        }
    )

    # Assemble PKIData
    pki_data = PKIData(
        {
            "controlSequence": [tagged_attribute],
            "reqSequence": [tagged_request],
            "cmsSequence": TaggedContentInfos([]),
            "otherMsgSequence": OtherMsgs([]),
        }
    )

    pki_data_bytes = pki_data.dump()

    # Calculate request hash
    cmc_request_hash = hash_digest(pki_data_bytes, signature_hash_algorithm)

    # Create SignerInfo

    digest_algorithm = asn1cms.DigestAlgorithm(
        {"algorithm": signature_hash_algorithm.name}
    )

    # Create subject key identifier from CSR public key
    skid = SubjectKeyIdentifier.from_public_key(csr.public_key()).digest

    # Create signed attributes
    signed_attribs = asn1cms.CMSAttributes(
        [
            asn1cms.CMSAttribute(
                {"type": "content_type", "values": ["1.3.6.1.5.5.7.12.2"]}
            ),
            asn1cms.CMSAttribute(
                {
                    "type": "message_digest",
                    "values": [cmc_request_hash],
                }
            ),
        ]
    )

    # Sign the attributes
    attribs_signature = rsa_pkcs1v15_sign(
        signed_attribs.dump(), private_key, hash_algorithm=signature_hash_algorithm
    )

    # Create signer info with enveloped data in unsigned attributes
    signer_info = asn1cms.SignerInfo(
        {
            "version": 3,
            "sid": asn1cms.SignerIdentifier({"subject_key_identifier": skid}),
            "digest_algorithm": digest_algorithm,
            "signature_algorithm": x509_csr["signature_algorithm"],
            "signature": attribs_signature,
            "signed_attrs": signed_attribs,
            "unsigned_attrs": asn1cms.CMSAttributes(
                [
                    asn1cms.CMSAttribute(
                        {
                            "type": "1.3.6.1.4.1.311.21.13",
                            "values": [enveloped_data_info],
                        }
                    )
                ]
            ),
        }
    )

    # Create SignedData

    content_info = asn1cms.EncapsulatedContentInfo(
        {
            "content_type": "1.3.6.1.5.5.7.12.2",
            "content": pki_data_bytes,
        }
    )

    signed_data = asn1cms.SignedData(
        {
            "version": 3,
            "digest_algorithms": [digest_algorithm],
            "encap_content_info": content_info,
            "signer_infos": [signer_info],
        }
    )

    # Create CMC ContentInfo

    cmc = asn1cms.ContentInfo(
        {
            "content_type": "signed_data",
            "content": signed_data,
        }
    )

    return cmc.dump()


# =========================================================================
# Command-line interface function
# =========================================================================


def entry(options: argparse.Namespace) -> None:
    """
    Command-line entry point for certificate operations.

    Args:
        options: Command line arguments
    """
    cert, key = None, None

    # Validate input options
    if not any([options.pfx, options.cert, options.key]):
        logging.error("-pfx, -cert, or -key is required")
        return

    # Load from PFX if specified
    if options.pfx:
        password = None
        if options.password:
            logging.debug(
                f"Loading PFX {repr(options.pfx)} with password {repr(options.password)}"
            )
            password = options.password.encode()
        else:
            logging.debug(f"Loading PFX {repr(options.pfx)} without password")

        with open(options.pfx, "rb") as f:
            pfx = f.read()

        key, cert = load_pfx(pfx, password)

    # Load certificate if specified
    if options.cert:
        logging.debug(f"Loading certificate from {repr(options.cert)}")

        with open(options.cert, "rb") as f:
            cert_data = f.read()
        try:
            cert = pem_to_cert(cert_data)
        except Exception:
            cert = der_to_cert(cert_data)

    # Load private key if specified
    if options.key:
        logging.debug(f"Loading private key from {repr(options.key)}")

        with open(options.key, "rb") as f:
            key_data = f.read()
        try:
            key = pem_to_key(key_data)
        except Exception:
            key = der_to_key(key_data)

    # Export as PFX if requested
    if options.export:
        if not key:
            logging.error("Private key is required for export")
            return

        if not cert:
            logging.error("Certificate is required for export")
            return

        pfx = create_pfx(key, cert)
        if options.out:
            logging.info(f"Saving certificate and private key to {options.out!r}")
            output_path = try_to_save_file(pfx, options.out)
            logging.info(f"Wrote certificate and private key to {output_path!r}")
        else:
            _ = sys.stdout.buffer.write(pfx)
    else:
        # Export as PEM
        output = ""
        log_str = ""

        if cert and not options.nocert:
            output += cert_to_pem(cert).decode()
            log_str += "certificate"
            if key and not options.nokey:
                log_str += " and "

        if key and not options.nokey:
            output += key_to_pem(key).decode()
            log_str += "private key"

        if len(output) == 0:
            logging.error("Output is empty")
            return

        if options.out:
            logging.info(f"Saving {log_str} to {options.out!r}")
            output_path = try_to_save_file(output.encode(), options.out)
            logging.info(f"Wrote {log_str} to {output_path!r}")
        else:
            print(output)
