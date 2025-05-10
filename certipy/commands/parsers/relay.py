"""
Parser for NTLM Relay command.

This module defines the command-line interface for the 'relay' command,
which enables NTLM relay attacks against Active Directory Certificate Services
HTTP endpoints for certificate theft and escalation.
"""

import argparse
from typing import Callable, Tuple

# Command name identifier
NAME = "relay"


def entry(options: argparse.Namespace) -> None:
    """
    Entry point for the relay command.

    This function imports and calls the actual implementation of the relay
    command from the certipy.commands module.

    Args:
        options: Parsed command-line arguments
    """
    from certipy.commands import relay

    relay.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:  # type: ignore
    """
    Add the NTLM relay command subparser to the main parser.

    This function creates and configures a subparser for relaying NTLM authentication
    to AD CS HTTP endpoints, enabling certificate theft and account takeover via
    certificate-based authentication.

    Args:
        subparsers: Parent parser to attach the subparser to

    Returns:
        Tuple of (command_name, entry_function) for command registration
    """
    # Create the relay subparser with description
    subparser = subparsers.add_parser(
        NAME,
        help="NTLM Relay to AD CS HTTP Endpoints",
        description=(
            "Perform NTLM relay attacks against Active Directory Certificate Services. "
            "This allows obtaining certificates for relayed users and computers, "
            "which can be used for authentication and potential privilege escalation."
        ),
    )

    # Target CA (required)
    subparser.add_argument(
        "-target",
        action="store",
        metavar="protocol://<ip address or hostname>",
        required=True,
        help=(
            "protocol://<IP address or hostname> of certificate authority. "
            "Example: http://ca.corp.local for ESC8 or rpc://ca.corp.local for ESC11"
        ),
    )

    # Certificate request parameters
    cert_group = subparser.add_argument_group("certificate request options")
    cert_group.add_argument(
        "-ca",
        action="store",
        metavar="certificate authority name",
        help=(
            "CA name to request certificate from. Example: 'CORP-CA'. "
            "Only required for RPC relay (ESC11)"
        ),
    )
    cert_group.add_argument(
        "-template",
        action="store",
        metavar="template name",
        help=(
            "If omitted, the template 'Machine' or 'User' is chosen by default "
            "depending on whether the relayed account name ends with '$'. "
            "Relaying a DC should require specifying the 'DomainController' template"
        ),
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

    # Certificate options
    cert_group.add_argument(
        "-retrieve",
        action="store",
        metavar="request ID",
        help="Retrieve an issued certificate specified by a request ID instead of requesting a new certificate",
        default=None,
        type=int,
    )
    cert_group.add_argument(
        "-key-size",
        action="store",
        metavar="RSA key length",
        help="Length of RSA key (default: 2048)",
        default=2048,
        type=int,
    )
    cert_group.add_argument(
        "-archive-key",
        action="store",
        metavar="cax cert file",
        help="Specify CAX Certificate for Key Archival. You can request the cax cert with 'certipy req -cax-cert'",
    )
    cert_group.add_argument(
        "-pfx-password",
        action="store",
        metavar="PFX file password",
        help="Password for the PFX file",
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

    # Server configuration options
    server_group = subparser.add_argument_group("server options")
    server_group.add_argument(
        "-interface",
        action="store",
        metavar="ip address",
        help="IP Address of interface to listen on (default: 0.0.0.0)",
        default="0.0.0.0",
    )
    server_group.add_argument(
        "-port",
        action="store",
        metavar="port number",
        help="Port to listen on (default: 445)",
        default=445,
        type=int,
    )

    # Relay behavior options
    relay_group = subparser.add_argument_group("relay options")
    relay_group.add_argument(
        "-forever",
        action="store_true",
        help="Don't stop the relay server after the first successful relay",
    )
    relay_group.add_argument(
        "-no-skip",
        action="store_true",
        help="Don't skip previously attacked users (use with -forever)",
    )
    relay_group.add_argument(
        "-enum-templates",
        action="store_true",
        help="Relay to /certsrv/certrqxt.asp and parse available certificate templates",
    )

    # Connection parameters
    conn_group = subparser.add_argument_group("connection options")
    conn_group.add_argument(
        "-timeout",
        action="store",
        metavar="seconds",
        help="Timeout for connections in seconds (default: 10)",
        default=10,
        type=int,
    )

    return NAME, entry
