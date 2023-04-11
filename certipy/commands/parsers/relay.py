NAME = "relay"

import argparse
from typing import Callable, Tuple


def entry(options: argparse.Namespace):
    from certipy.commands import relay

    relay.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(NAME, help="NTLM Relay to AD CS HTTP Endpoints")

    subparser.add_argument(
        "-ca",
        action="store",
        metavar="hostname",
        required=True,
        help="IP address or hostname of certificate authority",
    )
    subparser.add_argument("-debug", action="store_true", help="Turn debug output on")

    group = subparser.add_argument_group("certificate request options")
    group.add_argument(
        "-template",
        action="store",
        metavar="template name",
        help="If omitted, the template 'Machine' or 'User' is chosen by default depending on whether the relayed account name ends with '$'. Relaying a DC should require specifying the 'DomainController' template",
    )

    group.add_argument("-upn", action="store", metavar="alternative UPN")
    group.add_argument("-dns", action="store", metavar="alternative DNS")
    group.add_argument(
        "-retrieve",
        action="store",
        metavar="request ID",
        help="Retrieve an issued certificate specified by a request ID instead of requesting a new certificate",
        default=0,
        type=int,
    )
    
    group.add_argument(
        "-on-behalf-of",
        action="store",
        metavar="domain\\account",
        help="Use a Certificate Request Agent certificate to request on behalf of another user",
    )
    group.add_argument(
        "-pfx",
        action="store",
        metavar="pfx/p12 file name",
        help="Path to PFX for -on-behalf-of or -renew",
    )  
    
    group.add_argument(
        "-key-size",
        action="store",
        metavar="RSA key length",
        help="Length of RSA key. Default: 2048",
        default=2048,
        type=int,
    )

    group = subparser.add_argument_group("output options")
    group.add_argument("-out", action="store", metavar="output file name")

    group = subparser.add_argument_group("server options")
    group.add_argument(
        "-interface",
        action="store",
        metavar="ip address",
        help="IP Address of interface to listen on",
        default="0.0.0.0",
    )
    group.add_argument(
        "-port",
        action="store",
        help="Port to listen on",
        default=445,
        type=int,
    )

    group = subparser.add_argument_group("relay options")
    group.add_argument(
        "-forever",
        action="store_true",
        help="Don't stop the relay server after the first successful relay",
    )
    group.add_argument(
        "-no-skip",
        action="store_true",
        help="Don't skip previously attacked users. Use with -forever",
    )

    group = subparser.add_argument_group("connection options")
    group.add_argument(
        "-timeout",
        action="store",
        metavar="seconds",
        help="Timeout for connections",
        default=5,
        type=int,
    )

    return NAME, entry
