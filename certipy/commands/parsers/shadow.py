NAME = "shadow"

import argparse
from typing import Callable, Tuple

from . import target


def entry(options: argparse.Namespace):
    from certipy.commands import shadow

    shadow.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(
        NAME, help="Abuse Shadow Credentials for account takeover"
    )

    subparser.add_argument(
        "shadow_action",
        choices=["list", "add", "remove", "clear", "info", "auto"],
        help="Key Credentials action",
    )
    subparser.add_argument(
        "-account",
        action="store",
        metavar="target account",
        help="Account to target. If omitted, the user "
        "specified in the target will be used",
    )
    subparser.add_argument(
        "-device-id",
        action="store",
        help="Device ID of the Key Credential Link",
    )
    subparser.add_argument("-debug", action="store_true", help="Turn debug output on")

    group = subparser.add_argument_group("output options")
    group.add_argument("-out", action="store", metavar="output file name")

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
