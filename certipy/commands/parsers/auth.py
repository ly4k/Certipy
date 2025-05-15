"""
Parser for certificate authentication command.

This module defines the command-line interface for the 'auth' command,
which allows authentication to Active Directory services using certificates
and retrieving Kerberos tickets or NT hashes.
"""

import argparse
from typing import Callable, Tuple

# Command name identifier
NAME = "auth"


def entry(options: argparse.Namespace) -> None:
    """
    Entry point for the auth command.

    This function imports and calls the actual implementation of the auth
    command from the certipy.commands module.

    Args:
        options: Parsed command-line arguments
    """
    from certipy.commands import auth

    auth.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:  # type: ignore
    """
    Add the certificate authentication command subparser to the main parser.

    This function creates and configures a subparser for authenticating with
    certificates to Active Directory services, including options for retrieving
    Kerberos tickets and establishing LDAP connections.

    Args:
        subparsers: Parent parser to attach the subparser to

    Returns:
        Tuple of (command_name, entry_function) for command registration
    """
    # Create the auth subparser with description
    subparser = subparsers.add_parser(
        NAME,
        help="Authenticate using certificates",
        description=(
            "Authenticate to Active Directory services using certificates. "
            "This command enables certificate-based authentication to obtain "
            "Kerberos tickets, NT hashes, or establish LDAP connections."
        ),
    )

    # Certificate options
    cert_group = subparser.add_argument_group("certificate options")
    cert_group.add_argument(
        "-pfx",
        action="store",
        metavar="pfx/p12 file name",
        help="Path to certificate and private key (PFX/P12 format)",
        required=True,
    )
    cert_group.add_argument(
        "-password",
        action="store",
        metavar="password",
        help="Password for the PFX/P12 file",
    )

    # Output options
    output_group = subparser.add_argument_group("output options")
    output_group.add_argument(
        "-no-save", action="store_true", help="Don't save Kerberos TGT to file"
    )
    output_group.add_argument(
        "-no-hash", action="store_true", help="Don't request NT hash from Kerberos"
    )
    output_group.add_argument(
        "-print",
        action="store_true",
        help="Print Kerberos TGT in Kirbi format to console",
    )
    output_group.add_argument(
        "-kirbi",
        action="store_true",
        help="Save Kerberos TGT in Kirbi format (default is ccache)",
    )

    # Connection options
    conn_group = subparser.add_argument_group("connection options")
    conn_group.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help=(
            "IP Address of the domain controller. If omitted, it will use the domain "
            "part (FQDN) specified in the target parameter"
        ),
    )
    conn_group.add_argument(
        "-ns",
        action="store",
        metavar="nameserver",
        help="Nameserver for DNS resolution",
    )
    conn_group.add_argument(
        "-dns-tcp", action="store_true", help="Use TCP instead of UDP for DNS queries"
    )
    conn_group.add_argument(
        "-timeout",
        action="store",
        metavar="seconds",
        help="Timeout for connections in seconds",
        default=5,
        type=int,
    )

    # Authentication options
    auth_group = subparser.add_argument_group("authentication options")
    auth_group.add_argument(
        "-username",
        action="store",
        metavar="username",
        help="Username to authenticate as (extracted from certificate if omitted)",
    )
    auth_group.add_argument(
        "-domain",
        action="store",
        metavar="domain",
        help="Domain name to authenticate to (extracted from certificate if omitted)",
    )
    auth_group.add_argument(
        "-ldap-shell",
        action="store_true",
        help="Authenticate with the certificate via Schannel against LDAP",
    )

    # LDAP Options Group
    ldap_group = subparser.add_argument_group("ldap options")
    _ = ldap_group.add_argument(
        "-ldap-scheme",
        action="store",
        metavar="ldap scheme",
        choices=["ldap", "ldaps"],
        default="ldaps",
        help="LDAP connection scheme to use (default: ldaps)",
    )
    _ = ldap_group.add_argument(
        "-ldap-port",
        action="store",
        metavar="port",
        type=int,
        help="Port for LDAP communication (default: 636 for ldaps, 389 for ldap)",
    )
    _ = ldap_group.add_argument(
        "-ldap-user-dn",
        action="store",
        metavar="dn",
        help="Distinguished Name of target account for LDAP authentication",
    )

    return NAME, entry
