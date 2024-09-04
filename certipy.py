import argparse
import logging
import sys
import traceback

from certipy import version
from certipy.commands.parsers import ENTRY_PARSERS
from certipy.lib import logger


def main() -> None:
    logger.init()

    print(version.BANNER, file=sys.stderr)

    for arg in sys.argv:
        if arg.lower() in ["--version", "-v", "-version"]:
            return

    parser = argparse.ArgumentParser(
        add_help=False,
        description="Active Directory Certificate Services enumeration and abuse",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="store_true",
        help="Show Certipy's version number and exit",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
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

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logger.logging.setLevel(logging.DEBUG)
    else:
        logger.logging.setLevel(logging.INFO)

    try:
        actions[options.action](options)
    except Exception as e:
        logger.logging.error("Got error: %s" % e)
        if options.debug:
            traceback.print_exc()
        else:
            logger.logging.error("Use -debug to print a stacktrace")


if __name__ == "__main__":
    main()
