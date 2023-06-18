NAME = "forge"

import argparse
from typing import Callable, Tuple


def entry(options: argparse.Namespace):
    from certipy.commands import forge

    forge.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(NAME, help="Create Golden Certificates")

    subparser.add_argument(
        "-ca-pfx",
        action="store",
        metavar="pfx/p12 file name",
        help="Path to CA certificate",
        required=True,
    )
    subparser.add_argument("-upn", action="store", metavar="alternative UPN")
    subparser.add_argument("-dns", action="store", metavar="alternative DNS")
    subparser.add_argument("-sid", action="store", metavar="alternative Object SID")
    subparser.add_argument(
        "-template",
        action="store",
        metavar="pfx/p12 file name",
        help="Path to template certificate",
    )
    subparser.add_argument(
        "-subject",
        action="store",
        metavar="subject",
        help="Subject to include certificate",
    )
    subparser.add_argument(
        "-issuer",
        action="store",
        metavar="issuer",
        help="Issuer to include certificate. If not specified, the issuer from the CA cert will be used",
    )
    subparser.add_argument(
        "-crl",
        action="store",
        metavar="ldap path",
        help="ldap path to a CRL",
    )
    subparser.add_argument("-serial", action="store", metavar="serial number")
    subparser.add_argument(
        "-key-size",
        action="store",
        metavar="RSA key length",
        help="Length of RSA key. Default: 2048",
        default=2048,
        type=int,
    )
    subparser.add_argument("-debug", action="store_true", help="Turn debug output on")

    group = subparser.add_argument_group("output options")
    group.add_argument("-out", action="store", metavar="output file name")

    return NAME, entry
