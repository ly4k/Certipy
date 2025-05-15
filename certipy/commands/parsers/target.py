"""
Target Configuration Parser Module.

This module provides functions to add common target and authentication options
to command parsers, ensuring consistent options across all Certipy commands
when connecting to Active Directory services.
"""

import argparse
from typing import Optional


def add_argument_group(
    parser: argparse.ArgumentParser,
    connection_options: Optional[argparse._ArgumentGroup] = None,
) -> None:
    """
    Add common target, connection, and authentication arguments to a parser.

    This function adds standard options for connecting to Active Directory targets,
    including domain controllers, authentication methods, and network settings.

    Args:
        parser: The parser to add argument groups to
        connection_options: Optional existing argument group for connection options
    """
    # Connection Options Group
    if connection_options is not None:
        conn_group = connection_options
    else:
        conn_group = parser.add_argument_group("connection options")

    # Domain controller options
    _ = conn_group.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help=(
            "IP address of the domain controller. If omitted, it will use the domain "
            "part (FQDN) specified in the target parameter"
        ),
    )
    _ = conn_group.add_argument(
        "-dc-host",
        action="store",
        metavar="hostname",
        help=(
            "Hostname of the domain controller. Required for Kerberos authentication "
            "during certain operations. If omitted, the domain part (FQDN) "
            "specified in the account parameter will be used"
        ),
    )

    # Target machine options
    _ = conn_group.add_argument(
        "-target-ip",
        action="store",
        metavar="ip address",
        help=(
            "IP address of the target machine. If omitted, it will use whatever was "
            "specified as target. Useful when target is the NetBIOS name and cannot be resolved"
        ),
    )
    _ = conn_group.add_argument(
        "-target",
        action="store",
        metavar="dns/ip address",
        help="DNS name or IP address of the target machine. Required for Kerberos authentication",
    )

    # DNS options
    _ = conn_group.add_argument(
        "-ns",
        action="store",
        metavar="ip address",
        help="Nameserver for DNS resolution",
    )
    _ = conn_group.add_argument(
        "-dns-tcp", action="store_true", help="Use TCP instead of UDP for DNS queries"
    )

    # Connection options
    _ = conn_group.add_argument(
        "-timeout",
        action="store",
        metavar="seconds",
        help="Timeout for connections in seconds (default: 10)",
        default=10,
        type=int,
    )

    # Authentication Options Group
    auth_group = parser.add_argument_group("authentication options")

    # Credential options
    _ = auth_group.add_argument(
        "-u",
        "-username",
        metavar="username@domain",
        dest="username",
        action="store",
        help="Username to authenticate with",
    )
    _ = auth_group.add_argument(
        "-p",
        "-password",
        metavar="password",
        dest="password",
        action="store",
        help="Password for authentication",
    )
    _ = auth_group.add_argument(
        "-hashes",
        action="store",
        metavar="[lmhash:]nthash",
        help="NTLM hash",
    )

    # Authentication options
    _ = auth_group.add_argument(
        "-k",
        action="store_true",
        dest="do_kerberos",
        help=(
            "Use Kerberos authentication. Grabs credentials from ccache file "
            "(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, "
            "it will use the ones specified in the command line"
        ),
    )
    _ = auth_group.add_argument(
        "-aes",
        action="store",
        metavar="hex key",
        help="AES key to use for Kerberos Authentication (128 or 256 bits)",
    )
    _ = auth_group.add_argument(
        "-no-pass",
        action="store_true",
        help="Don't ask for password (useful for -k)",
    )

    # LDAP Options Group
    ldap_group = parser.add_argument_group("ldap options")
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
        "-no-ldap-channel-binding",
        action="store_true",
        help="Don't use LDAP channel binding for LDAP communication (LDAPS only)",
    )
    _ = ldap_group.add_argument(
        "-no-ldap-signing",
        action="store_true",
        help="Don't use LDAP signing for LDAP communication (LDAP only)",
    )
    _ = ldap_group.add_argument(
        "-ldap-simple-auth",
        action="store_true",
        dest="do_simple",
        help="Use SIMPLE LDAP authentication instead of NTLM",
    )
    _ = ldap_group.add_argument(
        "-ldap-user-dn",
        action="store",
        metavar="dn",
        help="Distinguished Name of target account for LDAP authentication",
    )
