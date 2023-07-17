NAME = "auth"

import argparse
from typing import Callable, Tuple

from . import target


def entry(options: argparse.Namespace):
    from certipy.commands import auth

    auth.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(NAME, help="Authenticate using certificates")

    subparser.add_argument(
        "-pfx",
        action="store",
        metavar="pfx/p12 file name",
        help="Path to certificate",
        required=True,
    )

    subparser.add_argument(
        "-no-save", action="store_true", help="Don't save TGT to file"
    )
    subparser.add_argument(
        "-no-hash", action="store_true", help="Don't request NT hash"
    )
    subparser.add_argument(
        "-ptt",
        action="store_true",
        help="Submit TGT for current logon session (Windows only)",
    )
    subparser.add_argument(
        "-print",
        action="store_true",
        help="Print TGT in Kirbi format",
    )
    subparser.add_argument(
        "-kirbi",
        action="store_true",
        help="Save TGT in Kirbi format",
    )
    subparser.add_argument("-debug", action="store_true", help="Turn debug output on")

    group = subparser.add_argument_group("connection options")

    group.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in "
        "the target parameter",
    )
    group.add_argument(
        "-ns",
        action="store",
        metavar="nameserver",
        help="Nameserver for DNS resolution",
    )
    group.add_argument(
        "-dns-tcp", action="store_true", help="Use TCP instead of UDP for DNS queries"
    )
    group.add_argument(
        "-timeout",
        action="store",
        metavar="seconds",
        help="Timeout for connections",
        default=5,
        type=int,
    )

    group = subparser.add_argument_group("authentication options")
    group.add_argument(
        "-username",
        action="store",
        metavar="username",
    )
    group.add_argument(
        "-domain",
        action="store",
        metavar="domain",
    )
    group.add_argument(
        "-ldap-shell",
        action="store_true",
        help="Authenticate with the certificate via Schannel against LDAP",
    )
    group = subparser.add_argument_group("ldap options")
    group.add_argument(
        "-ldap-port",
        action="store",
        help="LDAP port. Default: 636",
        metavar="port",
        default=0,
        type=int,
    )
    group.add_argument(
        "-ldap-scheme",
        action="store",
        metavar="ldap scheme",
        choices=["ldap", "ldaps"],
        default="ldaps",
    )
    group.add_argument(
        "-ldap-user-dn",
        action="store",
        metavar="dn",
        help="Distinguished Name of target account for LDAPS authentication",
    )

    return NAME, entry
