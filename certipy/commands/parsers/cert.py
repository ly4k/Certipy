NAME = "cert"

import argparse
from typing import Callable, Tuple


def entry(options: argparse.Namespace):
    from certipy.commands import cert

    cert.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(NAME, help="Manage certificates and private keys")

    subparser.add_argument(
        "-pfx", action="store", metavar="infile", help="Load PFX from file"
    )

    subparser.add_argument(
        "-password", action="store", metavar="password", help="Set import password"
    )

    subparser.add_argument(
        "-key", action="store", metavar="infile", help="Load private key from file"
    )

    subparser.add_argument(
        "-cert", action="store", metavar="infile", help="Load certificate from file"
    )

    subparser.add_argument("-export", action="store_true", help="Output PFX file")

    subparser.add_argument(
        "-out", action="store", metavar="outfile", help="Output filename"
    )

    subparser.add_argument(
        "-nocert",
        action="store_true",
        help="Don't output certificate",
    )

    subparser.add_argument(
        "-nokey", action="store_true", help="Don't output private key"
    )

    subparser.add_argument("-debug", action="store_true", help="Turn debug output on")

    return NAME, entry
