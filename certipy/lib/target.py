import argparse
import os
import platform
import socket
from typing import Optional, Tuple, Dict

from dns.resolver import Resolver
from impacket.krb5.ccache import CCache

from certipy.lib.logger import logging


class Target:
    """
    Class representing an authentication target with all necessary connection details.
    """

    def __init__(self) -> None:
        """Initialize a Target with default values."""
        self.domain: Optional[str] = None
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.remote_name: Optional[str] = None
        self.hashes: Optional[str] = None
        self.lmhash: Optional[str] = None
        self.nthash: Optional[str] = None
        self.do_kerberos: bool = False
        self.do_simple: bool = False
        self.use_sspi: bool = False
        self.aes: Optional[str] = None
        self.dc_ip: Optional[str] = None
        self.dc_host: Optional[str] = None
        self.target_ip: Optional[str] = None
        self.timeout: int = 5
        self.resolver: Optional[DnsResolver] = None
        self.ldap_channel_binding: Optional[bool] = None
        self.ldap_port: Optional[int] = None

    @staticmethod
    def from_options(
        options: argparse.Namespace, dc_as_target: bool = False, ptt: bool = False
    ) -> "Target":
        """
        Create a Target from command line options.

        Args:
            options: Command line options
            dc_as_target: Whether to use DC as target
            ptt: Pass-the-ticket mode

        Returns:
            Target: Configured target object

        Raises:
            Exception: If no target can be determined
        """
        self = Target()

        # Parse username and domain from principal format (user@DOMAIN)
        principal = options.username
        domain = ""
        if principal is not None:
            parts = principal.split("@")
            if len(parts) == 1:
                username = parts[0]
            else:
                username = "@".join(parts[:-1])
                domain = parts[-1]
        else:
            username = ""

        dc_ip = options.dc_ip
        dc_host = None

        # Handle Kerberos authentication
        if options.do_kerberos:
            principal = get_kerberos_principal()
            if principal:
                username, domain = principal

        # Handle SSPI authentication (Windows only)
        if options.use_sspi:
            options.do_kerberos = True
            username, domain, dc_ip, dc_host = get_logon_session()
            logging.debug(f"SSPI Context: {username}@{domain} on {dc_host} ({dc_ip})")

        # Normalize domain and username
        if domain is None:
            domain = ""
        domain = domain.upper()
        username = username.upper()

        if len(username) == 0:
            logging.error("Username is not specified")

        # Handle password input
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

        # Parse hashes if provided
        lmhash = nthash = ""
        if options.hashes is not None:
            hashes = options.hashes.split(":")
            if len(hashes) == 1:
                nthash = hashes[0]
                lmhash = nthash
            else:
                lmhash, nthash = hashes
                if len(lmhash) == 0:
                    lmhash = nthash
        else:
            hashes = None

        # AES key implies Kerberos
        if options.aes is not None:
            options.do_kerberos = True

        # Determine remote target name
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

        # Configure LDAP port
        ldap_port = options.ldap_port if hasattr(options, "ldap_port") else None

        # Set object properties
        self.domain = domain
        self.username = username
        self.password = password
        self.remote_name = remote_name
        self.hashes = hashes
        self.lmhash = lmhash
        self.nthash = nthash
        self.aes = options.aes
        self.do_kerberos = options.do_kerberos
        self.do_simple = options.do_simple
        self.use_sspi = options.use_sspi
        self.dc_ip = dc_ip
        self.dc_host = dc_host
        self.timeout = options.timeout
        self.ldap_channel_binding = options.ldap_channel_binding
        self.ldap_port = ldap_port

        # Adjust DC IP if needed
        if dc_as_target and options.dc_ip is None and is_ip(remote_name):
            self.dc_ip = remote_name

        # Set up DNS resolver
        ns = options.ns if hasattr(options, "ns") else self.dc_ip
        dns_tcp = options.dns_tcp if hasattr(options, "dns_tcp") else False

        # Handle target IP
        target_ip = options.target_ip if hasattr(options, "target_ip") else None
        if is_ip(remote_name):
            target_ip = remote_name

        self.resolver = DnsResolver.create(self, ns=ns, dns_tcp=dns_tcp)

        self.target_ip = target_ip
        if self.target_ip is None and remote_name is not None:
            self.target_ip = self.resolver.resolve(remote_name)

        # Ensure DC IP is resolved
        if self.dc_ip is None and domain:
            self.dc_ip = self.resolver.resolve(domain)

        return self

    @staticmethod
    def create(
        domain: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        target_ip: Optional[str] = None,
        remote_name: Optional[str] = None,
        no_pass: bool = False,
        do_kerberos: bool = False,
        do_simple: bool = False,
        use_sspi: bool = False,
        aes: Optional[str] = None,
        dc_ip: Optional[str] = None,
        ns: Optional[str] = None,
        dns_tcp: bool = False,
        timeout: int = 5,
        ldap_channel_binding: bool = False,
        ldap_port: Optional[int] = None,
    ) -> "Target":
        """
        Create a Target with the specified parameters.

        Returns:
            Target: Configured target object
        """
        self = Target()

        # Handle SSPI authentication (Windows only)
        if use_sspi:
            do_kerberos = True
            username, domain, dc_ip, dc_host = get_logon_session()
            logging.debug(f"SSPI Context: {username}@{domain} on {dc_host} ({dc_ip})")

        # Normalize domain and username
        if domain is None:
            domain = ""
        if username is None:
            username = ""

        domain = domain.upper()
        username = username.upper()

        # Handle password input
        if (
            not password
            and username != ""
            and hashes is None
            and aes is None
            and no_pass is not True
        ):
            from getpass import getpass

            password = getpass("Password:")

        # Parse hashes if provided
        lmhash = nthash = ""
        if hashes is not None:
            sub_hashes = hashes.split(":")
            if len(sub_hashes) == 1:
                nthash = sub_hashes[0]
                lmhash = nthash
            else:
                lmhash, nthash = sub_hashes
                if len(lmhash) == 0:
                    lmhash = nthash

        # AES key implies Kerberos
        if aes is not None:
            do_kerberos = True

        # Set object properties
        self.domain = domain
        self.username = username
        self.password = password
        self.remote_name = remote_name
        self.hashes = hashes
        self.lmhash = lmhash
        self.nthash = nthash
        self.aes = aes
        self.do_kerberos = do_kerberos
        self.do_simple = do_simple
        self.use_sspi = use_sspi
        self.dc_ip = dc_ip
        self.timeout = timeout
        self.ldap_channel_binding = ldap_channel_binding
        self.ldap_port = ldap_port

        # Handle DNS and target IP configuration
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
        """String representation of the Target object."""
        return f"<Target ({self.__dict__!r})>"


class DnsResolver:
    """
    DNS resolver for hostname resolution with caching capabilities.
    """

    def __init__(self) -> None:
        self.resolver: Resolver = Resolver()
        self.use_tcp: bool = False
        self.mappings: Dict[str, str] = {}

    @staticmethod
    def from_options(options: argparse.Namespace, target: "Target") -> "DnsResolver":
        """
        Create a DnsResolver from command line options.

        Args:
            options: The command line options
            target: The Target object

        Returns:
            DnsResolver: A configured DNS resolver
        """
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
        target: Optional["Target"] = None,
        ns: Optional[str] = None,
        dns_tcp: bool = False,
    ) -> "DnsResolver":
        """
        Create a DnsResolver with specified parameters.

        Args:
            target: Target object which may contain DC IP information
            ns: Nameserver to use
            dns_tcp: Whether to use TCP for DNS queries

        Returns:
            DnsResolver: A configured DNS resolver
        """
        self = DnsResolver()

        # We can't put all possible nameservers in the list of nameservers, since
        # the resolver will fail if one of them fails
        nameserver = ns
        if nameserver is None and target is not None:
            nameserver = target.dc_ip

        if nameserver is not None:
            self.resolver.nameservers = [nameserver]

        self.use_tcp = dns_tcp

        return self

    def resolve(self, hostname: str) -> str:
        """
        Resolve hostname to IP address using DNS or local resolution.
        Uses cache for previously resolved hostnames.

        Args:
            hostname: The hostname to resolve

        Returns:
            str: The resolved IP address or the original hostname if resolution fails
        """
        # Try to resolve the hostname with DNS first, then try a local resolve
        if hostname in self.mappings:
            logging.debug(
                f"Resolved {hostname!r} from cache: {self.mappings[hostname]}"
            )
            return self.mappings[hostname]

        if is_ip(hostname):
            return hostname

        ip_addr = None
        if not self.resolver.nameservers:
            logging.debug(f"Trying to resolve {hostname!r} locally")
        else:
            logging.debug(
                f"Trying to resolve {hostname!r} at {self.resolver.nameservers[0]!r}"
            )

        # Try DNS resolution first
        try:
            answers = self.resolver.resolve(hostname, tcp=self.use_tcp)
            if answers:
                ip_addr = str(answers[0])
        except Exception:
            pass

        # Fall back to socket resolution
        if ip_addr is None:
            try:
                ip_addr = socket.gethostbyname(hostname)
            except Exception:
                ip_addr = None

        if ip_addr is None:
            logging.warning(f"Failed to resolve: {hostname}")
            return hostname

        self.mappings[hostname] = ip_addr
        return ip_addr


def is_ip(hostname: Optional[str]) -> bool:
    """
    Check if the given hostname is an IP address.

    Args:
        hostname: The hostname to check

    Returns:
        bool: True if the hostname is an IP address, False otherwise
    """
    if hostname is None:
        return False

    try:
        _ = socket.inet_aton(hostname)
        return True
    except Exception:
        return False


def get_logon_session() -> Tuple[str, str, str, str]:
    """
    Get Windows logon session information using SSPI.

    Returns:
        Tuple containing (username, domain, dc_ip, dc_host)

    Raises:
        Exception: If not running on a Windows platform
    """
    if platform.system().lower() != "windows":
        raise Exception("Cannot use SSPI on non-Windows platform")

    from winacl.functions.highlevel import get_logon_info  # type: ignore

    info = get_logon_info()

    logonserver = info["logonserver"]
    username = info["username"]
    domain = info["domain"]
    dnsdomainname = info["dnsdomainname"]

    dns_resolver = DnsResolver()
    dc_ip = dns_resolver.resolve(logonserver)
    dc_host = f"{logonserver}.{dnsdomainname}"

    return username, domain, dc_ip, dc_host


def get_kerberos_principal() -> Optional[Tuple[str, str]]:
    """
    Get Kerberos principal information from the KRB5CCNAME environment variable.

    Returns:
        Tuple containing (username, domain) or None if not available
    """
    krb5ccname = os.getenv("KRB5CCNAME")
    if krb5ccname is None:
        logging.error("KRB5CCNAME environment variable not set")
        return None

    try:
        ccache = CCache.loadFile(krb5ccname)
    except Exception:
        return None

    if ccache is None:
        return None

    if ccache.principal is None:
        logging.error("No principal found in CCache file")
        return None

    if ccache.principal.realm is None:
        logging.error("No realm/domain found in CCache file")
        return None

    domain = ccache.principal.realm["data"].decode("utf-8")
    logging.debug(f"Domain retrieved from CCache: {domain}")

    username = "/".join(map(lambda x: x["data"].decode(), ccache.principal.components))
    logging.debug(f"Username retrieved from CCache: {username}")

    return username, domain
