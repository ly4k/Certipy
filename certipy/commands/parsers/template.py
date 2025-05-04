"""
Parser for certificate template management commands.

This module defines the command-line interface for the 'template' command,
which allows manipulating certificate templates in Active Directory.
"""

import argparse
from typing import Callable, Tuple

from . import target

# Command name identifier
NAME = "template"


def entry(options: argparse.Namespace) -> None:
    """
    Entry point for the template command.

    This function imports and calls the actual implementation of the template
    command from the certipy.commands module.

    Args:
        options: Parsed command-line arguments
    """
    from certipy.commands import template

    template.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    """
    Add the certificate template command subparser to the main parser.

    This function creates and configures a subparser for managing certificate templates
    in Active Directory, including options for viewing, modifying, and saving
    template configurations.

    Args:
        subparsers: Parent parser to attach the subparser to

    Returns:
        Tuple of (command_name, entry_function) for command registration
    """
    # Create the template subparser with description
    subparser = subparsers.add_parser(
        NAME,
        help="Manage certificate templates",
        description=(
            "Manipulate certificate templates in Active Directory. "
            "This command allows modifying template configurations."
        ),
    )

    # Required template name argument
    subparser.add_argument(
        "-template",
        action="store",
        metavar="template name",
        required=True,
        help="Name of the certificate template to operate on",
    )

    # Group configuration-related options
    config_group = subparser.add_argument_group("configuration options")
    config_group.add_argument(
        "-configuration",
        action="store",
        metavar="configuration file",
        help=(
            "Configuration to apply to the certificate template. "
            "If omitted, a default vulnerable configuration (ESC1) will be applied. "
            "Useful for restoring an old configuration or applying custom settings."
        ),
    )
    config_group.add_argument(
        "-save-old",
        action="store_true",
        help="Save the old configuration to a file before applying changes",
    )

    # Group connection-related options
    conn_group = subparser.add_argument_group("connection options")
    conn_group.add_argument(
        "-scheme",
        action="store",
        metavar="ldap scheme",
        choices=["ldap", "ldaps"],
        default="ldaps",
        help="LDAP connection scheme to use (default: ldaps)",
    )

    # Add standard target arguments (domain, username, etc.) from shared module
    target.add_argument_group(subparser, connection_options=conn_group)

    return NAME, entry
