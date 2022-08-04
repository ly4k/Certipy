NAME = "account"

import argparse
from typing import Callable, Tuple

from . import target


def entry(options: argparse.Namespace):
    from certipy.commands import account

    account.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(NAME, help="Manage user and machine accounts")

    subparser.add_argument("-debug", action="store_true", help="Turn debug output on")

    subparser.add_argument(
        "account_action",
        choices=["create", "read", "update", "delete"],
        help="Action",
    )

    group = subparser.add_argument_group("target")
    group.add_argument(
        "-user",
        action="store",
        metavar="SAM Account Name",
        help="Logon name for the account to target",
        required=True,
    )
    group.add_argument(
        "-group",
        action="store",
        metavar="CN=Computers,DC=test,DC=local",
        help="Group to which the account will be added."
        "If omitted, CN=Computers,<default path> will be used,",
    )
    group = subparser.add_argument_group("attribute options")
    group.add_argument(
        "-dns",
        action="store",
        metavar="Set the DNS host name for the account",
    )
    group.add_argument(
        "-upn",
        action="store",
        metavar="Set the UPN for the account",
    )
    group.add_argument(
        "-sam",
        action="store",
        metavar="Set the SAM Account Name for the account",
    )
    group.add_argument(
        "-spns",
        action="store",
        metavar="Set the SPNS for the account (comma-separated)",
    )
    group.add_argument(
        "-pass",
        action="store",
        dest="passw",
        metavar="Set the password for the account",
    )
    group = subparser.add_argument_group("connection options")
    group.add_argument(
        "-scheme",
        action="store",
        metavar="ldap scheme",
        choices=["ldap", "ldaps"],
        default="ldaps",
    )

    target.add_argument_group(subparser, connection_options=group)

    return NAME, entry
