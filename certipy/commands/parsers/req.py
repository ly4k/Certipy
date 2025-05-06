"""
Parser for certificate request command.

This module defines the command-line interface for the 'req' command,
which allows requesting certificates from Active Directory Certificate Services (AD CS).
"""

import argparse
from typing import Callable, Tuple

from . import target

# Command name identifier
NAME = "req"


def entry(options: argparse.Namespace) -> None:
    """
    Entry point for the certificate request command.

    This function imports and calls the actual implementation of the req
    command from the certipy.commands module.

    Args:
        options: Parsed command-line arguments
    """
    from certipy.commands import req

    req.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:  # type: ignore
    """
    Add the certificate request command subparser to the main parser.

    This function creates and configures a subparser for requesting certificates
    from AD CS, including options for certificate templates, subject alternative names,
    and various enrollment methods.

    Args:
        subparsers: Parent parser to attach the subparser to

    Returns:
        Tuple of (command_name, entry_function) for command registration
    """
    # Create the req subparser with description
    subparser = subparsers.add_parser(
        NAME,
        help="Request certificates",
        description=(
            "Request and retrieve certificates from Active Directory Certificate Services (AD CS). "
            "This command supports multiple enrollment protocols and certificate template types."
        ),
    )

    # CA name (required)
    subparser.add_argument(
        "-ca",
        action="store",
        metavar="certificate authority name",
        help="Name of the Certificate Authority to request certificates from. Required for RPC and DCOM methods",
    )

    # Certificate request parameters
    cert_group = subparser.add_argument_group("certificate request options")
    cert_group.add_argument(
        "-template",
        action="store",
        metavar="template name",
        default="User",
        help="Certificate template to request (default: User)",
    )

    # Subject Alternative Name options
    cert_group.add_argument(
        "-upn",
        action="store",
        metavar="alternative UPN",
        help="User Principal Name to include in the Subject Alternative Name",
    )
    cert_group.add_argument(
        "-dns",
        action="store",
        metavar="alternative DNS",
        help="DNS name to include in the Subject Alternative Name",
    )
    cert_group.add_argument(
        "-sid",
        action="store",
        metavar="alternative Object SID",
        help="Object SID to include in the Subject Alternative Name",
    )
    cert_group.add_argument(
        "-subject",
        action="store",
        metavar="subject",
        help="Subject to include in certificate, e.g. CN=Administrator,CN=Users,DC=CORP,DC=LOCAL",
    )

    # Certificate retrieval options
    cert_group.add_argument(
        "-retrieve",
        action="store",
        metavar="request ID",
        help="Retrieve an issued certificate specified by a request ID instead of requesting a new certificate",
        default=None,
        type=int,
    )

    # Certificate request agent options
    cert_group.add_argument(
        "-on-behalf-of",
        action="store",
        metavar="domain\\account",
        help="Use a Certificate Request Agent certificate to request on behalf of another user",
    )
    cert_group.add_argument(
        "-pfx",
        action="store",
        metavar="pfx/p12 file name",
        help="Path to PFX for -on-behalf-of or -renew",
    )
    cert_group.add_argument(
        "-pfx-password",
        action="store",
        metavar="PFX file password",
        help="Password for the PFX file",
    )

    # Key options
    cert_group.add_argument(
        "-key-size",
        action="store",
        metavar="RSA key length",
        help="Length of RSA key (default: 2048)",
        default=2048,
        type=int,
    )
    cert_group.add_argument(
        "-archive-key", action="store_true", help="Send private key for Key Archival"
    )
    cert_group.add_argument(
        "-cax-cert",
        action="store_true",
        help="Retrieve CAX Cert for relay with enabled Key Archival",
    )
    cert_group.add_argument(
        "-renew", action="store_true", help="Create renewal request"
    )

    # Advanced certificate options
    cert_group.add_argument(
        "-application-policies",
        action="store",
        nargs="+",
        metavar="Application Policy",
        help="Specify application policies for the certificate request using OIDs (e.g., '1.3.6.1.4.1.311.10.3.4' or 'Client Authentication')",
    )
    cert_group.add_argument(
        "-smime",
        action="store",
        metavar="encryption algorithm",
        help="Specify SMIME Extension that gets added to CSR (e.g., des, rc4, 3des, aes128, aes192, aes256)",
    )

    # Output options
    output_group = subparser.add_argument_group("output options")
    output_group.add_argument(
        "-out",
        action="store",
        metavar="output file name",
        help="Path to save the certificate and private key (PFX format)",
    )

    # Connection method options
    connection_group = subparser.add_argument_group("connection options")
    connection_group.add_argument(
        "-web", action="store_true", help="Use Web Enrollment instead of RPC"
    )
    connection_group.add_argument(
        "-dcom", action="store_true", help="Use DCOM Enrollment instead of RPC"
    )

    # RPC-specific options
    rpc_group = subparser.add_argument_group("rpc connection options")
    rpc_group.add_argument(
        "-dynamic-endpoint",
        action="store_true",
        help="Prefer dynamic TCP endpoint over named pipe",
    )

    # HTTP-specific options
    http_group = subparser.add_argument_group("http connection options")
    http_group.add_argument(
        "-http-scheme",
        action="store",
        metavar="http scheme",
        choices=["http", "https"],
        default="http",
        help="HTTP scheme to use for Web Enrollment (default: http)",
    )
    http_group.add_argument(
        "-http-port",
        action="store",
        metavar="port number",
        help="Web Enrollment port (default: 80 for http, 443 for https)",
        type=int,
    )
    http_group.add_argument(
        "-no-channel-binding",
        action="store_true",
        help="Disable channel binding for HTTP connections",
    )

    # Add standard target arguments
    target.add_argument_group(subparser, connection_options=connection_group)

    return NAME, entry
