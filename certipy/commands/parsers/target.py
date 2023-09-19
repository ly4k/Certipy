import argparse
from typing import Any


def add_argument_group(
    parser: argparse.ArgumentParser,
    connection_options: Any = None,
) -> None:
    if connection_options is not None:
        group = connection_options
    else:
        group = parser.add_argument_group("connection options")

    group.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in "
        "the target parameter",
    )
    group.add_argument(
        "-target-ip",
        action="store",
        metavar="ip address",
        help="IP Address of the target machine. If omitted it will use whatever was specified as target. "
        "This is useful when target is the NetBIOS name and you cannot resolve it",
    )
    group.add_argument(
        "-target",
        action="store",
        metavar="dns/ip address",
        help="DNS Name or IP Address of the target machine. Required for Kerberos or SSPI authentication",
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

    group = parser.add_argument_group("authentication options")
    group.add_argument(
        "-u",
        "-username",
        metavar="username@domain",
        dest="username",
        action="store",
        help="Username. Format: username@domain",
    )
    group.add_argument(
        "-p",
        "-password",
        metavar="password",
        dest="password",
        action="store",
        help="Password",
    )
    group.add_argument(
        "-hashes",
        action="store",
        metavar="[LMHASH:]NTHASH",
        help="NTLM hash, format is [LMHASH:]NTHASH",
    )
    group.add_argument(
        "-k",
        action="store_true",
        dest="do_kerberos",
        help="Use Kerberos authentication. Grabs credentials from ccache file "
        "(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the "
        "ones specified in the command line",
    )
    group.add_argument(
        "-sspi",
        dest="use_sspi",
        action="store_true",
        help="Use Windows Integrated Authentication (SSPI)",
    )
    group.add_argument(
        "-aes",
        action="store",
        metavar="hex key",
        help="AES key to use for Kerberos Authentication " "(128 or 256 bits)",
    )
    group.add_argument(
        "-no-pass",
        action="store_true",
        help="Don't ask for password (useful for -k and -sspi)",
    )

    group = parser.add_argument_group("ldap options")
    group.add_argument(
        "-ldap-channel-binding",
        action="store_true",
        help="Use LDAP channel binding for LDAP communication (LDAPS only)",
    )