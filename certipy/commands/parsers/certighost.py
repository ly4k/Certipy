"""Command-line parser for Certighost (CVE-2026-54121)."""

import argparse
from typing import Callable, Tuple

from . import target

NAME = "certighost"


def entry(options: argparse.Namespace) -> None:
    from certipy.commands import certighost

    certighost.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:  # type: ignore
    subparser = subparsers.add_parser(
        NAME,
        help="Exploit the Certighost AD CS chase vulnerability",
        description=(
            "Exploit CVE-2026-54121 by serving a controlled LSA/LDAP chase "
            "endpoint and requesting a certificate for a selected computer."
        ),
    )
    subparser.add_argument("-ca", help="Certificate Authority name")
    subparser.add_argument(
        "-template",
        default="Machine",
        help="Certificate template to request (default: Machine)",
    )
    subparser.add_argument(
        "-listener",
        help="IP address the CA can use to reach this host (default: auto-detect)",
    )
    subparser.add_argument(
        "-target-account",
        help="Computer to impersonate (default: discover a Domain Controller)",
    )
    subparser.add_argument(
        "-computer-name",
        help="Existing machine account to use instead of creating one",
    )
    machine_credentials = subparser.add_mutually_exclusive_group()
    machine_credentials.add_argument(
        "-computer-pass", help="Password for the existing machine account"
    )
    machine_credentials.add_argument(
        "-computer-hash", help="NT hash for the existing machine account"
    )
    subparser.add_argument(
        "-no-cleanup",
        action="store_true",
        help="Do not remove a machine account created by this command",
    )
    subparser.add_argument(
        "-out",
        help="Output filename for the issued PFX (without extension)",
    )
    target.add_argument_group(subparser)
    return NAME, entry
