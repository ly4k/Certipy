"""
Parser for Shadow Credentials command.

This module defines the command-line interface for the 'shadow' command,
which allows manipulation of Key Credential links (Shadow Credentials) on
Active Directory accounts for potential account takeover.
"""

import argparse
from typing import Callable, Tuple

from . import target

# Command name identifier
NAME = "shadow"


def entry(options: argparse.Namespace) -> None:
    """
    Entry point for the shadow command.

    This function imports and calls the actual implementation of the shadow
    command from the certipy.commands module.

    Args:
        options: Parsed command-line arguments
    """
    from certipy.commands import shadow

    shadow.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:  # type: ignore
    """
    Add the shadow credentials command subparser to the main parser.

    This function creates and configures a subparser for managing Shadow Credentials
    (Key Credential Links) in Active Directory, including options for listing, adding,
    and removing credential links for account takeover.

    Args:
        subparsers: Parent parser to attach the subparser to

    Returns:
        Tuple of (command_name, entry_function) for command registration
    """
    # Create the shadow subparser with description
    subparser = subparsers.add_parser(
        NAME,
        help="Abuse Shadow Credentials for account takeover",
        description=(
            "Manipulate Key Credential Links (Shadow Credentials) on Active Directory accounts. "
            "This allows for account takeover by adding or modifying Key Credential Links."
        ),
    )

    # Main action argument (required)
    subparser.add_argument(
        "shadow_action",
        choices=["list", "add", "remove", "clear", "info", "auto"],
        help=(
            "Operation to perform on Key Credential Links: "
            "list (view all), "
            "add (create new), "
            "remove (delete specific), "
            "clear (remove all), "
            "info (display detailed information), "
            "auto (automatically exploit)"
        ),
    )

    # Target account options
    account_group = subparser.add_argument_group("account options")
    account_group.add_argument(
        "-account",
        action="store",
        metavar="target account",
        help=(
            "Account to target. If omitted, the user "
            "specified in the target will be used"
        ),
    )
    account_group.add_argument(
        "-device-id",
        action="store",
        metavar="device id",
        help="Device ID of the Key Credential Link to target",
    )

    # Output options
    output_group = subparser.add_argument_group("output options")
    output_group.add_argument(
        "-out",
        action="store",
        metavar="output file name",
        help="Output file for saving certificate or results",
    )

    # Add standard target arguments from shared module
    target.add_argument_group(subparser)

    return NAME, entry
