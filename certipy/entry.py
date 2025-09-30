# PYTHON_ARGCOMPLETE_OK
import argparse
import logging
import sys

import argcomplete

from certipy import version
from certipy.commands.parsers import ENTRY_PARSERS
from certipy.lib import logger
from certipy.lib.errors import handle_error


def main() -> None:
    logger.init()

    print(version.BANNER, file=sys.stderr)

    if "-debug" in sys.argv or "--debug" in sys.argv:
        sys.argv = [arg for arg in sys.argv if arg not in ["-debug", "--debug"]]
        logger.logging.setLevel(logging.DEBUG)
        logger.set_verbose(True)
    else:
        logger.logging.setLevel(logging.INFO)

    for arg in sys.argv:
        if arg.lower() in ["--version", "-v", "-version"]:
            return

    parser = argparse.ArgumentParser(
        add_help=False,
        description="Active Directory Certificate Services enumeration and abuse",
    )

    _ = parser.add_argument(
        "-v",
        "--version",
        action="store_true",
        help="Show Certipy's version number and exit",
        default=argparse.SUPPRESS,
    )
    _ = parser.add_argument(
        "-h",
        "--help",
        action="help",
        default=argparse.SUPPRESS,
        help="Show this help message and exit",
    )

    subparsers = parser.add_subparsers(help="Action", dest="action", required=True)

    actions = {}

    for entry_parser in ENTRY_PARSERS:
        action, entry = entry_parser.add_subparser(subparsers)
        actions[action] = entry

    argcomplete.autocomplete(parser, always_complete_options=False)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    try:
        actions[options.action](options)
    except Exception as e:
        logger.logging.error(f"Got error: {e}")
        handle_error()


if __name__ == "__main__":
    main()
