# Certipy - Active Directory certificate abuse
#
# Description:
#   Entrypoint for Certipy
#
# Authors:
#   @ly4k (https://github.com/ly4k)
#

import argparse
import logging

from impacket.examples import logger

from certipy.auth import authenticate
from certipy.auto import auto
from certipy.find import find
from certipy.request import request


def main():
    logger.init()

    parser = argparse.ArgumentParser(
        description="Active Directory certificate abuse", add_help=True
    )

    parser.add_argument(
        "target",
        action="store",
        help="[[domain/]username[:password]@]<target name or address>",
    )

    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")

    # Connection options
    group = parser.add_argument_group("connection")
    group.add_argument(
        "-target-ip",
        action="store",
        metavar="ip address",
        help=(
            "IP Address of the target machine. If "
            "omitted it will use whatever was specified as target. This is useful when "
            "target is the NetBIOS "
            "name and you cannot resolve it"
        ),
    )

    group.add_argument(
        "-nameserver",
        action="store",
        metavar="nameserver",
        help="Nameserver for DNS resolution",
    )
    group.add_argument(
        "-dns-tcp", action="store_true", help="Use TCP instead of UDP for DNS queries"
    )

    # Authentication options
    group = parser.add_argument_group("authentication")
    group.add_argument(
        "-hashes",
        action="store",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes, format is LMHASH:NTHASH",
    )
    parser.add_argument(
        "-no-pass", action="store_true", help="don't ask for password (useful for -k)"
    )
    parser.add_argument(
        "-k",
        action="store_true",
        help="Use Kerberos authentication. Grabs credentials from ccache file "
        "(KRB5CCNAME) based on target parameters. If valid credentials "
        "cannot be found, it will use the ones specified in the command "
        "line",
    )
    parser.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help=(
            "IP Address of the domain controller. If omitted it will use the domain "
            "part (FQDN) specified in the target parameter"
        ),
    )

    subparsers = parser.add_subparsers(help="Action", dest="action", required=True)

    # Find options
    find_parser = subparsers.add_parser("find", help="Find certificate templates")

    find_parser.add_argument(
        "-scheme",
        action="store",
        metavar="ldap scheme",
        choices=["ldap", "ldaps", "gc"],
        default="ldaps",
    )

    find_parser.add_argument(
        "-user",
        action="store",
        metavar="user",
        help=(
            "Find certificate templates available for <user>. If omitted it will use"
            "the user specified in the target"
        ),
    )

    find_parser.add_argument(
        "-vulnerable",
        action="store_true",
        help="Show only vulnerable certificate templates",
    )
    find_parser.add_argument(
        "-json",
        action="store_true",
        help="Output result as json instead of text",
    )
    # Request options
    request_parser = subparsers.add_parser("req", help="Request a new certificate")

    request_parser.add_argument(
        "-template", action="store", metavar="template name", required=True
    )
    request_parser.add_argument("-subject", action="store", metavar="subject name")
    request_parser.add_argument(
        "-ca", action="store", metavar="certificate authority name", required=True
    )
    request_parser.add_argument("-alt", action="store", metavar="alternative UPN")

    # Authenticate options
    auth_parser = subparsers.add_parser("auth", help="Authenticate with a certificate")

    auth_parser.add_argument(
        "-cert", action="store", metavar="cert file", required=True
    )
    auth_parser.add_argument("-key", action="store", metavar="key file", required=True)

    # Auto options
    auto_parser = subparsers.add_parser(
        "auto",
        help="Automatically abuse certificate templates for privilege escalation",
    )

    auto_parser.add_argument(
        "-scheme",
        action="store",
        metavar="ldap scheme",
        choices=["ldap", "ldaps", "gc"],
        default="ldaps",
    )
    auto_parser.add_argument(
        "-user",
        action="store",
        metavar="principal",
        default="Administrator",
    )

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    if options.action == "find":
        find(options)
    elif options.action == "req":
        request(options)
    elif options.action == "auth":
        authenticate(options)
    elif options.action == "auto":
        auto(options)
    else:
        raise NotImplementedError("Action not implemented: %s" % options.action)


if __name__ == "__main__":
    main()
