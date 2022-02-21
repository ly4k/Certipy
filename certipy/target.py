import argparse
import logging
import socket
from typing import Any

from dns.resolver import Resolver
from impacket.examples.utils import parse_target


def is_ip(hostname: str) -> bool:
    try:
        # Check if hostname is an IP
        socket.inet_aton(hostname)
        return True
    except Exception:
        pass
    return False


class DnsResolver:
    def __init__(self):
        self.resolver = Resolver()

        self.mappings = {}

    @staticmethod
    def from_options(options, target) -> "DnsResolver":
        self = DnsResolver()

        # We can't put all possible nameservers in the list of nameservers, since
        # the resolver will fail if one of them fails
        nameserver = options.ns
        if nameserver is None:
            nameserver = target.dc_ip

        if nameserver is not None:
            self.resolver.nameservers = [nameserver]

        self.use_tcp = options.dns_tcp

        return self

    @staticmethod
    def create(
        target: "Target" = None, ns: str = None, dns_tcp: bool = False
    ) -> "DnsResolver":
        self = DnsResolver()

        # We can't put all possible nameservers in the list of nameservers, since
        # the resolver will fail if one of them fails
        nameserver = ns
        if nameserver is None:
            nameserver = target.dc_ip

        if nameserver is not None:
            self.resolver.nameservers = [nameserver]

        self.use_tcp = dns_tcp

        return self

    def resolve(self, hostname: str) -> str:
        # Try to resolve the hostname with DNS first, then try a local resolve
        if hostname in self.mappings:
            logging.debug(
                "Resolved %s from cache: %s" % (repr(hostname), self.mappings[hostname])
            )
            return self.mappings[hostname]

        if is_ip(hostname):
            return hostname

        ip_addr = None
        if self.resolver.nameservers[0] is None:
            logging.debug("Trying to resolve %s locally" % repr(hostname))
        else:
            logging.debug(
                "Trying to resolve %s at %s"
                % (repr(hostname), repr(self.resolver.nameservers[0]))
            )
        try:
            answers = self.resolver.resolve(hostname, tcp=self.use_tcp)
            if len(answers) == 0:
                raise Exception()

            ip_addr = answers[0].to_text()
        except Exception:
            pass

        if ip_addr is None:
            try:
                ip_addr = socket.gethostbyname(hostname)
            except Exception:
                ip_addr = None

        if ip_addr is None:
            logging.warning("Failed to resolve: %s" % hostname)
            return hostname

        self.mappings[hostname] = ip_addr
        return ip_addr


class Target:
    def __init__(self):
        self.domain: str = None
        self.username: str = None
        self.password: str = None
        self.remote_name: str = None
        self.hashes: str = None
        self.lmhash: str = None
        self.nthash: str = None
        self.do_kerberos: bool = False
        self.dc_ip: str = None
        self.target_ip: str = None
        self.timeout: int = 5
        self.resolver: Resolver = None

    @staticmethod
    def from_options(options, dc_as_target: bool = False) -> "Target":
        self = Target()

        domain, username, password, remote_name = parse_target(options.target)

        if domain is None:
            domain = ""

        if (
            password == ""
            and username != ""
            and options.hashes is None
            and options.no_pass is not True
        ):
            from getpass import getpass

            password = getpass("Password:")
        hashes = options.hashes
        if hashes is not None:
            hashes = hashes.split(":")
            if len(hashes) == 1:
                (nthash,) = hashes
                lmhash = nthash = nthash
            else:
                lmhash, nthash = hashes
                if len(lmhash) == 0:
                    lmhash = nthash
        else:
            lmhash = nthash = ""

        self.domain = domain
        self.username = username
        self.password = password
        self.remote_name = remote_name
        self.hashes = options.hashes
        self.lmhash = lmhash
        self.nthash = nthash
        self.do_kerberos = options.k
        self.dc_ip = options.dc_ip
        self.timeout = options.timeout

        if dc_as_target and options.dc_ip is None and is_ip(remote_name):
            self.dc_ip = remote_name

        if options.ns is None:
            options.ns = self.dc_ip

        if is_ip(remote_name):
            options.target_ip = remote_name

        self.resolver = DnsResolver.from_options(options, self)

        self.target_ip = options.target_ip
        if self.target_ip is None and remote_name is not None:
            self.target_ip = self.resolver.resolve(remote_name)

        return self

    @staticmethod
    def create(
        domain: str = None,
        username: str = None,
        password: str = None,
        hashes: str = None,
        target_ip: str = None,
        remote_name: str = None,
        no_pass: bool = False,
        do_kerberos: bool = False,
        dc_ip: str = None,
        ns: str = None,
        dns_tcp: bool = False,
        timeout: int = 5,
    ) -> "Target":
        self = Target()

        if domain is None:
            domain = ""

        if password == "" and username != "" and hashes is None and no_pass is not True:
            from getpass import getpass

            password = getpass("Password:")
        hashes = hashes
        if hashes is not None:
            hashes = hashes.split(":")
            if len(hashes) == 1:
                (nthash,) = hashes
                lmhash = nthash = nthash
            else:
                lmhash, nthash = hashes
        else:
            lmhash = nthash = ""

        self.domain = domain
        self.username = username
        self.password = password
        self.remote_name = remote_name
        self.hashes = hashes
        self.lmhash = lmhash
        self.nthash = nthash
        self.do_kerberos = do_kerberos
        self.dc_ip = dc_ip
        self.timeout = timeout

        if ns is None:
            ns = dc_ip

        if is_ip(remote_name):
            target_ip = remote_name

        self.resolver = DnsResolver.create(self, ns=ns, dns_tcp=dns_tcp)

        self.target_ip = target_ip
        if self.target_ip is None and remote_name is not None:
            self.target_ip = self.resolver.resolve(remote_name)

        return self

    def __repr__(self) -> str:
        return "<Target (%s)>" % repr(self.__dict__)


def add_argument_group(
    parser: argparse.ArgumentParser,
    connection_options: Any = None,
) -> None:
    parser.add_argument(
        "target",
        action="store",
        help="[[domain/]username[:password]@]<target name or address>",
    )

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
        "-hashes",
        action="store",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes, format is LMHASH:NTHASH",
    )
    group.add_argument(
        "-no-pass", action="store_true", help="Don't ask for password (useful for -k)"
    )
    group.add_argument(
        "-k",
        action="store_true",
        help="Use Kerberos authentication. Grabs credentials from ccache file "
        "(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the "
        "ones specified in the command line",
    )
