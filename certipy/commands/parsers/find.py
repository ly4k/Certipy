NAME = "find"

import argparse
from typing import Callable, Tuple

from . import target


def entry(options: argparse.Namespace):
    from certipy.commands import find

    find.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(NAME, help="Enumerate AD CS")
    subparser.add_argument("-debug", action="store_true", help="Turn debug output on")

    group = subparser.add_argument_group("output options")
    group.add_argument(
        "-bloodhound",
        action="store_true",
        help="Output result as BloodHound data for the custom-built BloodHound version from @ly4k with PKI support",
    )
    group.add_argument(
        "-old-bloodhound",
        action="store_true",
        help="Output result as BloodHound data for the original BloodHound version from @BloodHoundAD without PKI support",
    )
    group.add_argument(
        "-text",
        action="store_true",
        help="Output result as text",
    )
    group.add_argument(
        "-stdout",
        action="store_true",
        help="Output result as text to stdout",
    )
    group.add_argument(
        "-json",
        action="store_true",
        help="Output result as JSON",
    )
    group.add_argument(
        "-output",
        action="store",
        metavar="prefix",
        help="Filename prefix for writing results to",
    )

    group = subparser.add_argument_group("find options")
    group.add_argument(
        "-enabled",
        action="store_true",
        help="Show only enabled certificate templates. Does not affect BloodHound output",
    )
    group.add_argument(
        "-dc-only",
        action="store_true",
        help="Collects data only from the domain controller. Will not try to retrieve CA security/configuration or check for Web Enrollment",
    )
    group.add_argument(
        "-vulnerable",
        action="store_true",
        help="Show only vulnerable certificate templates based on nested group memberships. Does not affect BloodHound output",
    )
    group.add_argument(
        "-oids",
        action="store_true",
        help="Show OIDs (Issuance Policies) and their properties.",
    )
    group.add_argument(
        "-hide-admins",
        action="store_true",
        help="Don't show administrator permissions for -text, -stdout, and -json. Does not affect BloodHound output",
    )
    group.add_argument(
        "-sid",
        action="store",
        metavar="object sid",
        help="SID of the user provided in the command line, useful for cross domain authentication.",
    )
    group.add_argument(
        "-dn",
        action="store",
        metavar="distinguished name",
        help="Distinguished name of the user provided in the command line, useful for cross domain authentication",
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
