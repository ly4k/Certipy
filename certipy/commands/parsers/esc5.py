"""
Parser for ESC5 (Vulnerable PKI Object Access Control) command.

This module defines the command-line interface for the 'esc5' command, which
audits and (optionally) exploits dangerous access control on the Active
Directory objects that make up AD CS itself, as opposed to a single
certificate template (ESC4) or a CA's ManageCA/ManageCertificates security
descriptor (ESC7). 'find' does not check any of this -- it enumerates
certificate templates, CAs, and issuance policies, none of which are the PKI
containers, CA-adjacent objects, or NTAuthCertificates this command audits.
"""

import argparse
from typing import Callable, Tuple

from . import target

# Command name identifier
NAME = "esc5"


def entry(options: argparse.Namespace) -> None:
    """
    Entry point for the esc5 command.

    This function imports and calls the actual implementation of the esc5
    command from the certipy.commands module.

    Args:
        options: Parsed command-line arguments
    """
    from certipy.commands import esc5

    esc5.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:  # type: ignore
    """
    Add the ESC5 command subparser to the main parser.

    This function creates and configures a subparser for auditing and
    exploiting ESC5 (vulnerable PKI object access control): dangerous ACEs
    on the Public Key Services container tree (Enrollment Services,
    Certificate Templates, Certification Authorities, and OID containers),
    each CA's own AD object and its underlying computer object, and
    NTAuthCertificates.

    Args:
        subparsers: Parent parser to attach the subparser to

    Returns:
        Tuple of (command_name, entry_function) for command registration
    """
    subparser = subparsers.add_parser(
        NAME,
        help="Audit and exploit ESC5 (vulnerable PKI object access control)",
        description=(
            "Audit access control on the Active Directory objects that make up AD CS "
            "itself, rather than an individual certificate template: the Public Key "
            "Services container tree (Enrollment Services, Certificate Templates, "
            "Certification Authorities, OID), each CA's own AD object and its "
            "underlying computer object, and NTAuthCertificates. Reports whether the "
            "authenticated identity holds a qualifying right on any of them, and can "
            "carry out the one fully automatable escalation this implies: adding a "
            "self-signed rogue CA certificate to NTAuthCertificates, a forest-wide "
            "trust change."
        ),
    )

    subparser.add_argument(
        "esc5_action",
        choices=["audit", "exploit", "restore"],
        help=(
            "Operation to perform: "
            "audit (default-safe precondition check, read-only), "
            "exploit (add a rogue CA certificate to NTAuthCertificates -- forest-wide "
            "trust change, requires the audited identity to hold a qualifying right), "
            "restore (undo a prior exploit run using its restore file)"
        ),
    )

    # Output options
    output_group = subparser.add_argument_group("output options")
    output_group.add_argument(
        "-output",
        action="store",
        metavar="csv file",
        help="Write audit findings to a CSV file",
    )
    output_group.add_argument(
        "-hide-admins",
        action="store_true",
        help="Don't show well-known administrative grantees in the audit output",
    )

    # Identity options for cross-domain operation, matching 'find'
    identity_group = subparser.add_argument_group("identity options")
    identity_group.add_argument(
        "-sid",
        action="store",
        metavar="object sid",
        help="SID of the user provided in the command line. Useful for cross domain authentication",
    )
    identity_group.add_argument(
        "-dn",
        action="store",
        metavar="distinguished name",
        help="Distinguished name of the user provided in the command line. Useful for cross domain authentication",
    )

    # Exploit options
    exploit_group = subparser.add_argument_group(
        "exploit options (only used with the 'exploit' action)"
    )
    exploit_group.add_argument(
        "-force",
        action="store_true",
        help=(
            "Don't prompt for confirmation, and attempt the NTAuthCertificates write "
            "even if the audit found no qualifying right for the authenticated "
            "identity. The domain controller is the final arbiter of authorization, "
            "not this command's own ACL parse"
        ),
    )
    exploit_group.add_argument(
        "-ca-pfx",
        action="store",
        metavar="pfx/p12 file name",
        help="Rogue CA certificate and private key to add (PFX). If omitted, a self-signed one is generated",
    )
    exploit_group.add_argument(
        "-ca-password",
        action="store",
        metavar="password",
        help="Password for -ca-pfx, if it is encrypted",
    )
    exploit_group.add_argument(
        "-ca-subject",
        action="store",
        metavar="subject",
        help="Subject for a self-generated rogue CA (default: 'CN=ESC5-PoC-CA-<random>')",
    )
    exploit_group.add_argument(
        "-key-size",
        action="store",
        metavar="RSA key length",
        type=int,
        default=2048,
        help="Length of RSA key for a self-generated rogue CA (default: 2048)",
    )
    exploit_group.add_argument(
        "-validity-period",
        action="store",
        metavar="days",
        type=int,
        default=3650,
        help="Validity period in days for a self-generated rogue CA (default: 3650)",
    )
    exploit_group.add_argument(
        "-out-dir",
        action="store",
        metavar="directory",
        default="./esc5",
        help="Directory to write the rogue CA PFX and restore file to (default: ./esc5)",
    )

    # Restore options
    restore_group = subparser.add_argument_group(
        "restore options (only used with the 'restore' action)"
    )
    restore_group.add_argument(
        "-restore",
        action="store",
        metavar="restore file",
        help="Restore file written by a prior 'esc5 exploit' run",
    )

    # Add standard target arguments from shared module
    target.add_argument_group(subparser)

    return NAME, entry
