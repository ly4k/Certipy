"""
Parser for certificate forging command.

This module defines the command-line interface for the 'forge' command,
which allows creating custom certificates by forging them with a compromised CA certificate.
"""

import argparse
from typing import Callable, Tuple

# Command name identifier
NAME = "forge"


def entry(options: argparse.Namespace) -> None:
    """
    Entry point for the forge command.

    This function imports and calls the actual implementation of the forge
    command from the certipy.commands module.

    Args:
        options: Parsed command-line arguments
    """
    from certipy.commands import forge

    forge.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    """
    Add the certificate forging command subparser to the main parser.

    This function creates and configures a subparser for forging certificates
    with a compromised CA certificate, allowing creation of Golden Certificates
    that can be used for authentication and privilege escalation.

    Args:
        subparsers: Parent parser to attach the subparser to

    Returns:
        Tuple of (command_name, entry_function) for command registration
    """
    # Create the forge subparser with description
    subparser = subparsers.add_parser(
        NAME,
        help="Create Golden Certificates",
        description=(
            "Forge certificates using a compromised CA certificate. "
            "This allows creating certificates for any identity in the domain."
        ),
    )

    # CA certificate (required)
    subparser.add_argument(
        "-ca-pfx",
        action="store",
        metavar="pfx/p12 file name",
        help="Path to CA certificate and private key (PFX/P12 format)",
        required=True,
    )

    # CA certificate password
    subparser.add_argument(
        "-ca-password",
        action="store",
        metavar="password",
        help="Password for the CA PFX file",
    )

    # Subject Alternative Name options
    san_group = subparser.add_argument_group("subject alternative name options")
    san_group.add_argument(
        "-upn",
        action="store",
        metavar="alternative UPN",
        help="User Principal Name to include in the Subject Alternative Name",
    )
    san_group.add_argument(
        "-dns",
        action="store",
        metavar="alternative DNS",
        help="DNS name to include in the Subject Alternative Name",
    )
    san_group.add_argument(
        "-sid",
        action="store",
        metavar="alternative Object SID",
        help="Object SID to include in the Subject Alternative Name",
    )

    # Certificate content options
    cert_group = subparser.add_argument_group("certificate content options")
    cert_group.add_argument(
        "-template",
        action="store",
        metavar="pfx/p12 file name",
        help="Path to template certificate to clone properties from",
    )
    cert_group.add_argument(
        "-subject",
        action="store",
        metavar="subject",
        help="Subject to include in certificate (e.g., CN=User,DC=domain,DC=local)",
    )
    cert_group.add_argument(
        "-issuer",
        action="store",
        metavar="issuer",
        help="Issuer to include in certificate. If not specified, the issuer from the CA cert will be used",
    )
    cert_group.add_argument(
        "-crl",
        action="store",
        metavar="ldap path",
        help="LDAP path to a CRL distribution point",
    )
    cert_group.add_argument(
        "-serial",
        action="store",
        metavar="serial number",
        help="Custom serial number for the certificate",
    )

    # Key options
    key_group = subparser.add_argument_group("key options")
    key_group.add_argument(
        "-key-size",
        action="store",
        metavar="RSA key length",
        help="Length of RSA key (default: 2048)",
        default=2048,
        type=int,
    )

    # Validity options
    validity_group = subparser.add_argument_group("validity options")
    validity_group.add_argument(
        "-validity-period",
        action="store",
        metavar="days",
        help="Validity period in days (default: 365)",
        default=365,
        type=int,
    )

    # Output options
    output_group = subparser.add_argument_group("output options")
    output_group.add_argument(
        "-out",
        action="store",
        metavar="output file name",
        help="Path to save the forged certificate and private key (PFX format)",
    )
    output_group.add_argument(
        "-pfx-password",
        action="store",
        metavar="password",
        help="Password to protect the output PFX file",
    )

    return NAME, entry
