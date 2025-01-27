NAME = "parse"

import argparse
from typing import Callable, Tuple

def entry(options: argparse.Namespace):
    from certipy.commands import parse

    parse.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(NAME, help="Offline enumerate AD CS based on registry data")
    subparser.add_argument("file", help="file to parse")
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

    group = subparser.add_argument_group("parse options")
    group.add_argument(
        "-format",
        help="Input format either req_query BOF output or Windows .reg file (default: bof)",
        choices=["bof", "reg"],
        default="bof"
    )
    group.add_argument(
        "-domain",
        help="Domain name, solely used for output (default: UNKNOWN)",
        type=lambda arg: arg.upper(),
        default="UNKNOWN"
    )
    group.add_argument(
        "-ca",
        help="CA name, solely used for output (default: UNKNOWN)",
        default="UNKNOWN"
    )
    group.add_argument(
        "-sids",
        help="Consider the comma separated list of SIDs as owned",
        type=lambda arg: list(map(str.strip, arg.split(','))),
        default=[]
    )
    group.add_argument(
        "-published",
        help="Consider the comma separated list of template names as published",
        type=lambda arg: list(map(str.strip, arg.split(','))),
        default=[]
    )
    group.add_argument(
        "-enabled",
        action="store_true",
        help="Show only enabled certificate templates. Does not affect BloodHound output",
    )
    group.add_argument(
        "-vulnerable",
        action="store_true",
        help="Show only vulnerable certificate templates based on nested group memberships. Does not affect BloodHound output",
    )
    group.add_argument(
        "-hide-admins",
        action="store_true",
        help="Don't show administrator permissions for -text, -stdout, and -json. Does not affect BloodHound output",
    )

    return NAME, entry
