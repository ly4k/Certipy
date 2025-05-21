"""
Parser for AD CS enumeration command.

This module defines the command-line interface for the 'find' command,
which allows enumerating and analyzing Active Directory Certificate Services
components and configurations to identify security vulnerabilities.
"""

import argparse
from typing import Callable, Tuple

from . import target

# Command name identifier
NAME = "find"


def entry(options: argparse.Namespace) -> None:
    """
    Entry point for the find command.

    This function imports and calls the actual implementation of the find
    command from the certipy.commands module.

    Args:
        options: Parsed command-line arguments
    """
    from certipy.commands import find

    find.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:  # type: ignore
    """
    Add the AD CS enumeration command subparser to the main parser.

    This function creates and configures a subparser for finding and analyzing
    Active Directory Certificate Services components, including certificate
    templates, enrollment services, and CA configurations.

    Args:
        subparsers: Parent parser to attach the subparser to

    Returns:
        Tuple of (command_name, entry_function) for command registration
    """
    # Create the find subparser with description
    subparser = subparsers.add_parser(
        NAME,
        help="Enumerate AD CS",
        description=(
            "Discover and analyze Active Directory Certificate Services (AD CS) components. "
            "This command identifies vulnerable certificate templates, security misconfigurations, "
            "and potential certificate-based privilege escalation paths."
        ),
    )

    # Output options group
    output_group = subparser.add_argument_group("output options")
    output_group.add_argument(
        "-text",
        action="store_true",
        help="Output result as formatted text file",
    )
    output_group.add_argument(
        "-stdout",
        action="store_true",
        help="Output result as text directly to console",
    )
    output_group.add_argument(
        "-json",
        action="store_true",
        help="Output result as JSON",
    )
    output_group.add_argument(
        "-csv",
        action="store_true",
        help="Output result as CSV",
    )
    output_group.add_argument(
        "-output",
        action="store",
        metavar="prefix",
        help="Filename prefix for writing results to",
    )

    # Find options group
    find_group = subparser.add_argument_group("find options")
    find_group.add_argument(
        "-enabled",
        action="store_true",
        help="Show only enabled certificate templates",
    )
    find_group.add_argument(
        "-dc-only",
        action="store_true",
        help=(
            "Collects data only from the domain controller. Will not try to retrieve "
            "CA security/configuration or check for Web Enrollment"
        ),
    )
    find_group.add_argument(
        "-vulnerable",
        action="store_true",
        help="Show only vulnerable certificate templates based on nested group memberships",
    )
    find_group.add_argument(
        "-oids",
        action="store_true",
        help="Show OIDs (Issuance Policies) and their properties",
    )
    find_group.add_argument(
        "-hide-admins",
        action="store_true",
        help="Don't show administrator permissions for -text, -stdout, -json, and -csv",
    )

    # Identity options for cross-domain operation
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

    # Add standard target arguments from shared module
    target.add_argument_group(subparser)

    return NAME, entry
