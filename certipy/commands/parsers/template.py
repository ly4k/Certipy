NAME = "template"

import argparse
from typing import Callable, Tuple

from . import target


def entry(options: argparse.Namespace):
    from certipy.commands import template

    template.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(NAME, help="Manage certificate templates")

    subparser.add_argument(
        "-template", action="store", metavar="template name", required=True
    )
    subparser.add_argument("-debug", action="store_true", help="Turn debug output on")

    group = subparser.add_argument_group("configuration options")
    group.add_argument(
        "-configuration",
        action="store",
        metavar="configuration file",
        help="Configuration to apply to the certificate template. If omitted, a default vulnerable configuration (ESC1) will be applied. Useful for restoring an old configuration",
    )
    group.add_argument(
        "-save-old",
        action="store_true",
        help="Save the old configuration",
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
