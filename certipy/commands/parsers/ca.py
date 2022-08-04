NAME = "ca"

import argparse
from typing import Callable, Tuple

from . import target


def entry(options: argparse.Namespace):
    from certipy.commands import ca

    ca.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(NAME, help="Manage CA and certificates")

    subparser.add_argument("-ca", action="store", metavar="certificate authority name")
    subparser.add_argument("-debug", action="store_true", help="Turn debug output on")

    group = subparser.add_argument_group("certificate template options")
    group.add_argument(
        "-enable-template",
        action="store",
        metavar="template name",
        help="Enable a certificate template on the CA",
    )
    group.add_argument(
        "-disable-template",
        action="store",
        metavar="template name",
        help="Disable a certificate template on the CA",
    )
    group.add_argument(
        "-list-templates",
        action="store_true",
        help="List enabled certificate templates on the CA",
    )

    group = subparser.add_argument_group("certificate request options")
    group.add_argument(
        "-issue-request",
        action="store",
        metavar="request ID",
        help="Issue a pending or failed certificate request",
    )
    group.add_argument(
        "-deny-request",
        action="store",
        metavar="request ID",
        help="Deny a pending certificate request",
    )

    group = subparser.add_argument_group("officer options")
    group.add_argument(
        "-add-officer",
        action="store",
        metavar="officer",
        help="Add a new officer (Certificate Manager) to the CA",
    )
    group.add_argument(
        "-remove-officer",
        action="store",
        metavar="officer",
        help="Remove an existing officer (Certificate Manager) from the CA",
    )

    group = subparser.add_argument_group("manager options")
    group.add_argument(
        "-add-manager",
        action="store",
        metavar="manager",
        help="Add a new manager (CA Manager) to the CA",
    )
    group.add_argument(
        "-remove-manager",
        action="store",
        metavar="manager",
        help="Remove an existing manager (CA Manager) from the CA",
    )

    group = subparser.add_argument_group("backup options")
    group.add_argument(
        "-backup",
        action="store_true",
        help="Backup CA certificate and private key",
    )
    group.add_argument(
        "-config",
        action="store",
        metavar="Machine\\CA",
    )

    group = subparser.add_argument_group("connection options")
    group.add_argument(
        "-scheme",
        action="store",
        metavar="ldap scheme",
        choices=["ldap", "ldaps"],
        default="ldaps",
    )
    group.add_argument(
        "-dynamic-endpoint",
        action="store_true",
        help="Prefer dynamic TCP endpoint over named pipe",
    )
    group.add_argument(
        "-dc-host",
        action="store",
        metavar="hostname",
        help="Hostname of the domain controller to use. "
        "If ommited, the domain part (FQDN) "
        "specified in the account parameter will be used",
    )

    target.add_argument_group(subparser, connection_options=group)

    return NAME, entry
