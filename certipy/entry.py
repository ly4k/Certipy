import argparse
import logging
import sys
import traceback

from impacket.examples import logger

from certipy import (
    auth,
    ca,
    certificate,
    find,
    forge,
    relay,
    request,
    shadow,
    template,
    version,
)

ENTRY_PARSERS = [
    auth,
    ca,
    certificate,
    find,
    forge,
    relay,
    request,
    shadow,
    template,
]


def main() -> None:
    print(version.BANNER, file=sys.stderr)

    logger.init()

    for arg in sys.argv:
        if arg.lower() in ["--version", "-v", "-version"]:
            return

    parser = argparse.ArgumentParser(
        add_help=False,
        description="Active Directory Certificate Services enumeration and abuse ",
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
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    try:
        actions[options.action](options)
    except Exception as e:
        logging.error("Got error: %s" % e)
        if options.debug:
            traceback.print_exc()
        else:
            logging.error("Use -debug to print a stacktrace")
