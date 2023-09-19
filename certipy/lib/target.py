import os
import platform
import socket

from certipy.lib.logger import logging
from dns.resolver import Resolver
from impacket.krb5.ccache import CCache


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
        self.use_tcp = False

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
        if len(self.resolver.nameservers) == 0 or self.resolver.nameservers[0] is None:
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


def get_logon_session():
    if platform.system().lower() != "windows":
        raise Exception("Cannot use SSPI on non-Windows platform")

    from certipy.lib.sspi import get_tgt
    from winacl.functions.highlevel import get_logon_info

    info = get_logon_info()

    logonserver = info["logonserver"]
    username = info["username"]
    domain = info["domain"]
    dnsdomainname = info["dnsdomainname"]

    dns_resolver = DnsResolver()
    dc_ip = dns_resolver.resolve(logonserver)
    dc_host = "%s.%s" % (logonserver, dnsdomainname)

    return username, domain, dc_ip, dc_host


def get_kerberos_principal():
    try:
        ccache = CCache.loadFile(os.getenv("KRB5CCNAME"))
    except:
        return None

    if ccache is None:
        return None
    # retrieve domain information from CCache file if needed
    domain = ccache.principal.realm["data"].decode("utf-8")
    logging.debug("Domain retrieved from CCache: %s" % domain)

    username = "/".join(map(lambda x: x["data"].decode(), ccache.principal.components))

    logging.debug("Username retrieved from CCache: %s" % username)

    return username, domain


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
        self.use_sspi: bool = False
        self.aes: str = None
        self.dc_ip: str = None
        self.target_ip: str = None
        self.timeout: int = 5
        self.resolver: Resolver = None
        self.ldap_channel_binding = None

    @staticmethod
    def from_options(
        options, dc_as_target: bool = False, ptt: bool = False
    ) -> "Target":
        self = Target()

        principal = options.username
        domain = ""
        if principal is not None:
            principal = principal.split("@")
            if len(principal) == 1:
                (username,) = principal
            else:
                username = "@".join(principal[:-1])
                domain = principal[-1]
                # username, domain = principal
        else:
            username = ""

        dc_ip = options.dc_ip
        dc_host = None

        if options.do_kerberos:
            principal = get_kerberos_principal()
            if principal:
                username, domain = principal

        if options.use_sspi:
            options.do_kerberos = True
            username, domain, dc_ip, dc_host = get_logon_session()

            logging.debug(
                "SSPI Context: %s@%s on %s (%s)" % (username, domain, dc_host, dc_ip)
            )

        if domain is None:
            domain = ""
        domain = domain.upper()
        username = username.upper()

        if len(username) == 0:
            logging.error("Username is not specified")

        password = options.password
        if (
            not password
            and username != ""
            and options.hashes is None
            and options.aes is None
            and options.no_pass is not True
            and options.do_kerberos is not True
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

        if options.aes is not None:
            options.do_kerberos = True

        remote_name = options.target
        if (
            (options.do_kerberos or options.use_sspi)
            and not remote_name
            and not ptt
            and not dc_as_target
        ):
            logging.warning(
                "Target name (-target) not specified and Kerberos or SSPI authentication is used. This might fail"
            )

        if remote_name is None:
            if options.target_ip:
                remote_name = options.target_ip
            elif dc_host:
                remote_name = dc_host
            elif dc_ip:
                remote_name = dc_ip
            elif domain:
                remote_name = domain
            else:
                raise Exception("Could not find a target in the specified options")

        self.domain = domain
        self.username = username
        self.password = password
        self.remote_name = remote_name
        self.hashes = hashes
        self.lmhash = lmhash
        self.nthash = nthash
        self.aes = options.aes
        self.do_kerberos = options.do_kerberos
        self.use_sspi = options.use_sspi
        self.dc_ip = dc_ip
        self.dc_host = dc_host
        self.timeout = options.timeout
        self.ldap_channel_binding = options.ldap_channel_binding

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

        if self.dc_ip is None:
            self.dc_ip = self.resolver.resolve(domain)

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
        use_sspi: bool = False,
        aes: str = None,
        dc_ip: str = None,
        ns: str = None,
        dns_tcp: bool = False,
        timeout: int = 5,
        ldap_channel_binding: bool = False,
    ) -> "Target":

        self = Target()

        if use_sspi:
            do_kerberos = True
            username, domain, dc_ip, dc_host = get_logon_session()

            logging.debug(
                "SSPI Context: %s@%s on %s (%s)" % (username, domain, dc_host, dc_ip)
            )

        if domain is None:
            domain = ""
        if username is None:
            username = ""

        domain = domain.upper()
        username = username.upper()

        if (
            not password
            and username != ""
            and hashes is None
            and aes is None
            and no_pass is not True
        ):
            from getpass import getpass

            password = getpass("Password:")

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

        if aes is not None:
            do_kerberos = True

        self.domain = domain
        self.username = username
        self.password = password
        self.remote_name = remote_name
        self.hashes = hashes
        self.lmhash = lmhash
        self.nthash = nthash
        self.aes = aes
        self.do_kerberos = do_kerberos
        self.use_sspi = use_sspi
        self.dc_ip = dc_ip
        self.timeout = timeout
        self.ldap_channel_binding = ldap_channel_binding

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
