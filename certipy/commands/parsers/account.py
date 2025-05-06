"""
Parser for Active Directory account management command.

This module defines the command-line interface for the 'account' command,
which allows creating, reading, updating, and deleting user and computer accounts
in Active Directory.
"""

import argparse
from typing import Callable, Tuple

from . import target

# Command name identifier
NAME = "account"


def entry(options: argparse.Namespace) -> None:
    """
    Entry point for the account management command.

    This function imports and calls the actual implementation of the account
    command from the certipy.commands module.

    Args:
        options: Parsed command-line arguments
    """
    from certipy.commands import account

    account.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:  # type: ignore
    """
    Add the account management command subparser to the main parser.

    This function creates and configures a subparser for managing Active Directory
    accounts, including options for creating, reading, updating, and deleting
    user and computer accounts.

    Args:
        subparsers: Parent parser to attach the subparser to

    Returns:
        Tuple of (command_name, entry_function) for command registration
    """
    # Create the account subparser with description
    subparser = subparsers.add_parser(
        NAME,
        help="Manage user and machine accounts",
        description=(
            "Create, read, update, and delete Active Directory user and computer accounts. "
            "This command allows manipulating account properties including DNS names, "
            "service principal names (SPNs), and passwords."
        ),
    )

    # Main action argument
    subparser.add_argument(
        "account_action",
        choices=["create", "read", "update", "delete"],
        help=(
            "Action to perform: "
            "create (new account), "
            "read (view account properties), "
            "update (modify existing account), "
            "delete (remove account)"
        ),
    )

    # Target account options
    target_group = subparser.add_argument_group("target options")
    target_group.add_argument(
        "-user",
        action="store",
        metavar="SAM Account Name",
        help="Logon name for the account to target",
        required=True,
    )
    target_group.add_argument(
        "-group",
        action="store",
        metavar="CN=Computers,DC=test,DC=local",
        help=(
            "Group to which the account will be added. "
            "If omitted, CN=Computers,<default path> will be used"
        ),
    )

    # Account attribute options
    attr_group = subparser.add_argument_group("attribute options")
    attr_group.add_argument(
        "-dns",
        action="store",
        metavar="hostname",
        help="Set the DNS hostname for the account (e.g., computer.domain.local)",
    )
    attr_group.add_argument(
        "-upn",
        action="store",
        metavar="principal name",
        help="Set the User Principal Name for the account (e.g., user@domain.local)",
    )
    attr_group.add_argument(
        "-sam",
        action="store",
        metavar="account name",
        help="Set the SAM Account Name for the account (e.g., computer$ or username)",
    )
    attr_group.add_argument(
        "-spns",
        action="store",
        metavar="service names",
        help="Set the Service Principal Names for the account (comma-separated)",
    )
    attr_group.add_argument(
        "-pass",
        action="store",
        dest="passw",
        metavar="password",
        help="Set the password for the account",
    )

    # Add standard target arguments from shared module
    target.add_argument_group(subparser)

    return NAME, entry
