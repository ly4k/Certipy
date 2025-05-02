NAME = "req"

import argparse
from typing import Callable, Tuple

from . import target


def entry(options: argparse.Namespace):
    from certipy.commands import req

    req.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(NAME, help="Request certificates")
    subparser.add_argument("-debug", action="store_true", help="Turn debug output on")

    subparser.add_argument(
        "-ca", action="store", metavar="certificate authority name", required=True
    )

    group = subparser.add_argument_group("certificate request options")
    group.add_argument(
        "-template", action="store", metavar="template name", default="User"
    )
    group.add_argument("-upn", action="store", metavar="alternative UPN")
    group.add_argument("-dns", action="store", metavar="alternative DNS")
    group.add_argument("-sid", action="store", metavar="alternative Object SID")
    group.add_argument(
        "-subject",
        action="store",
        metavar="subject",
        help="Subject to include in certificate, e.g. CN=Administrator,CN=Users,DC=CORP,DC=LOCAL",
    )
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
    group.add_argument("-pfx-password", action="store", metavar="PFX file password")
    group.add_argument(
        "-key-size",
        action="store",
        metavar="RSA key length",
        help="Length of RSA key. Default: 2048",
        default=2048,
        type=int,
    )
    group.add_argument(
        "-archive-key",
        action="store_true",
        help="Send private key for Key Archival",
    )
    group.add_argument(
        "-cax-cert",
        action="store_true",
        help="Retrieve CAX Cert for relay with enabled Key Archival",
    )
    group.add_argument(
        "-renew",
        action="store_true",
        help="Create renewal request",
    )
    group.add_argument(
        "--application-policies",
        action="store",
        nargs="+",
        metavar="Application Policy",
        help="Specify application policies for the certificate request using OIDs (e.g., '1.3.6.1.4.1.311.10.3.4' or 'Client Authentication')",
    )
    group.add_argument(
        "-smime",
        action="store",
        help="Specify SMIME Extension that gets added to CSR eg: des, rc4, 3des, aes128, aes192, aes256",
    )
    group = subparser.add_argument_group("output options")
    group.add_argument("-out", action="store", metavar="output file name")

    connection_group = subparser.add_argument_group("connection options")
    connection_group.add_argument(
        "-web",
        action="store_true",
        help="Use Web Enrollment instead of RPC",
    )
    connection_group.add_argument(
        "-dcom",
        action="store_true",
        help="Use DCOM Enrollment instead of RPC",
    )

    group = subparser.add_argument_group("rpc connection options")
    group.add_argument(
        "-dynamic-endpoint",
        action="store_true",
        help="Prefer dynamic TCP endpoint over named pipe",
    )

    group = subparser.add_argument_group("http connection options")
    group.add_argument(
        "-scheme",
        action="store",
        metavar="http scheme",
        choices=["http", "https"],
        default="http",
    )
    group.add_argument(
        "-port",
        action="store",
        help="Web Enrollment port. If omitted, port 80 or 443 will be chosen by default depending on the scheme.",
        type=int,
    )

    target.add_argument_group(subparser, connection_options=connection_group)

    return NAME, entry
