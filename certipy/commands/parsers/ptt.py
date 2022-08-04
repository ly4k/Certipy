NAME = "ptt"

import argparse
from typing import Callable, Tuple

from . import target


def entry(options: argparse.Namespace):
    from certipy.commands import ptt

    ptt.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(NAME, help="Inject TGT for SSPI authentication")
    subparser.add_argument("-debug", action="store_true", help="Turn debug output on")

    group = subparser.add_argument_group("ticket options")
    group.add_argument("-ticket", action="store", metavar="base64 kirbi/ccache")
    group.add_argument(
        "-ticket-file",
        action="store",
        metavar="kirbi/ccache ticket file (optionally base64 encoded)",
    )
    group.add_argument("-req", action="store_true", help="Request new TGT")

    target.add_argument_group(subparser, connection_options=None)

    return NAME, entry
