"""
Parser for Certificate Authority management command.

This module defines the command-line interface for the 'ca' command,
which allows managing Certificate Authority configurations, templates,
certificate requests, and role assignments in Active Directory.
"""

import argparse
from typing import Callable, Tuple

from . import target

# Command name identifier
NAME = "ca"


def entry(options: argparse.Namespace) -> None:
    """
    Entry point for the CA management command.

    This function imports and calls the actual implementation of the CA
    command from the certipy.commands module.

    Args:
        options: Parsed command-line arguments
    """
    from certipy.commands import ca

    ca.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:  # type: ignore
    """
    Add the Certificate Authority management command subparser to the main parser.

    This function creates and configures a subparser for managing Certificate
    Authorities in Active Directory, including template management, request
    processing, permission assignments, and CA backup operations.

    Args:
        subparsers: Parent parser to attach the subparser to

    Returns:
        Tuple of (command_name, entry_function) for command registration
    """
    # Create the CA subparser with description
    subparser = subparsers.add_parser(
        NAME,
        help="Manage CA and certificates",
        description=(
            "Manage Certificate Authority configurations, templates, and permissions. "
            "This command allows enabling/disabling templates, processing certificate "
            "requests, managing role assignments, and backing up CA certificates."
        ),
    )

    # CA identification
    subparser.add_argument(
        "-ca",
        action="store",
        metavar="certificate authority name",
        help="Name of the Certificate Authority to manage",
    )

    # Certificate template management options
    template_group = subparser.add_argument_group("certificate template options")
    template_group.add_argument(
        "-enable-template",
        action="store",
        metavar="template name",
        help="Enable a certificate template on the CA",
    )
    template_group.add_argument(
        "-disable-template",
        action="store",
        metavar="template name",
        help="Disable a certificate template on the CA",
    )
    template_group.add_argument(
        "-list-templates",
        action="store_true",
        help="List all enabled certificate templates on the CA",
    )

    # Certificate request processing options
    request_group = subparser.add_argument_group("certificate request options")
    request_group.add_argument(
        "-issue-request",
        action="store",
        metavar="request ID",
        help="Issue a pending or failed certificate request",
    )
    request_group.add_argument(
        "-deny-request",
        action="store",
        metavar="request ID",
        help="Deny a pending certificate request",
    )

    # Certificate officer management
    officer_group = subparser.add_argument_group("officer options")
    officer_group.add_argument(
        "-add-officer",
        action="store",
        metavar="officer",
        help="Add a new officer (Certificate Manager) to the CA",
    )
    officer_group.add_argument(
        "-remove-officer",
        action="store",
        metavar="officer",
        help="Remove an existing officer (Certificate Manager) from the CA",
    )

    # CA manager role management
    manager_group = subparser.add_argument_group("manager options")
    manager_group.add_argument(
        "-add-manager",
        action="store",
        metavar="manager",
        help="Add a new manager (CA Manager) to the CA",
    )
    manager_group.add_argument(
        "-remove-manager",
        action="store",
        metavar="manager",
        help="Remove an existing manager (CA Manager) from the CA",
    )

    # Backup operations
    backup_group = subparser.add_argument_group("backup options")
    backup_group.add_argument(
        "-backup",
        action="store_true",
        help="Backup CA certificate and private key",
    )
    backup_group.add_argument(
        "-config",
        action="store",
        metavar="Machine\\CA",
        help="CA configuration string in format Machine\\CAName",
    )

    # Connection options
    conn_group = subparser.add_argument_group("connection options")
    conn_group.add_argument(
        "-dynamic-endpoint",
        action="store_true",
        help="Prefer dynamic TCP endpoint over named pipe",
    )

    # Add standard target arguments from shared module
    target.add_argument_group(subparser, connection_options=conn_group)

    return NAME, entry
