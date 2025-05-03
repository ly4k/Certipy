"""
Target management module for Certipy.

This module provides functionality for creating and managing target objects
that represent authentication endpoints. It handles:

- Authentication parameters (username, password, hashes, Kerberos tickets)
- Target name resolution (DNS, local resolution, IP address validation)
- Connection settings (timeouts, ports, protocol options)
- Windows-specific authentication methods (SSPI)
- Domain controller discovery
- Kerberos ticket cache integration

The primary class is Target, which encapsulates all connection parameters
needed to authenticate to and interact with Windows/Active Directory services.
Helper classes like DnsResolver provide supporting functionality.

Usage:
    target = Target.from_options(options)  # Create from command-line arguments
    target = Target.create(username="user@domain.com", password="secret")  # Create programmatically
"""
import argparse
import os
import platform
import socket
from typing import Dict, Optional, Tuple

from dns.resolver import Resolver
from impacket.krb5.ccache import CCache

from certipy.lib.logger import logging


class Target:
    """
    Class representing an authentication target with all necessary connection details.
    """

    def __init__(
        self, 
        domain: str = "",
        username: str = "",
        password: Optional[str] = None,
        remote_name: str = "",
        hashes: Optional[str] = None,
        lmhash: str = "",
        nthash: str = "",
        do_kerberos: bool = False,
        do_simple: bool = False,
        use_sspi: bool = False,
        aes: Optional[str] = None,
        dc_ip: Optional[str] = None,
        dc_host: Optional[str] = None,
        target_ip: Optional[str] = None,
        timeout: int = 5,
        ldap_channel_binding: bool = False,
        ldap_port: Optional[int] = None,
    ) -> None:
        """
        Initialize a Target with the specified connection parameters.
        
        Args:
            domain: Domain name (empty string if not specified)
            username: Username (empty string if not specified)
            password: Password (None if not specified)
            remote_name: Remote target name (empty string if not specified)
            hashes: NTLM hashes in format LM:NT
            lmhash: LM hash
            nthash: NT hash
            do_kerberos: Use Kerberos authentication
            do_simple: Use simple authentication
            use_sspi: Use SSPI authentication (Windows only)
            aes: AES key for Kerberos authentication
            dc_ip: Domain controller IP
            dc_host: Domain controller hostname
            target_ip: Target IP address
            timeout: Connection timeout in seconds
            ldap_channel_binding: Use LDAP channel binding
            ldap_port: LDAP port to use
        """
        self.domain: str = domain
        self.username: str = username
        self.password: Optional[str] = password
        self.remote_name: str = remote_name
        self.hashes: Optional[str] = hashes
        self.lmhash: str = lmhash
        self.nthash: str = nthash
        self.do_kerberos: bool = do_kerberos
        self.do_simple: bool = do_simple
        self.use_sspi: bool = use_sspi
        self.aes: Optional[str] = aes
        self.dc_ip: Optional[str] = dc_ip
        self.dc_host: Optional[str] = dc_host
        self.target_ip: Optional[str] = target_ip
        self.timeout: int = timeout
        self.ldap_channel_binding: bool = ldap_channel_binding
        self.ldap_port: Optional[int] = ldap_port
        self.resolver: Optional[DnsResolver] = None

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
        # Parse username and domain from principal format (user@DOMAIN)
        principal = options.username
        domain = ""
        username = ""
        
        if principal is not None:
            parts = principal.split("@")
            if len(parts) == 1:
                username = parts[0]
            else:
                username = "@".join(parts[:-1])
                domain = parts[-1]

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
        lmhash = ""
        nthash = ""
        hashes = options.hashes
        if hashes is not None:
            hash_parts = hashes.split(":")
            if len(hash_parts) == 1:
                nthash = hash_parts[0]
                lmhash = nthash
            else:
                lmhash, nthash = hash_parts
                if len(lmhash) == 0:
                    lmhash = nthash

        # AES key implies Kerberos
        if options.aes is not None:
            options.do_kerberos = True

        # Determine remote target name
        remote_name = options.target or ""
        if (
            (options.do_kerberos or options.use_sspi)
            and not remote_name
            and not ptt
            and not dc_as_target
        ):
            logging.warning(
                "Target name (-target) not specified and Kerberos or SSPI authentication is used. This might fail"
            )

        if not remote_name:
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
        ldap_channel_binding = options.ldap_channel_binding if hasattr(options, "ldap_channel_binding") else False

        # Create target instance
        target = Target(
            domain=domain,
            username=username,
            password=password,
            remote_name=remote_name,
            hashes=hashes,
            lmhash=lmhash,
            nthash=nthash,
            aes=options.aes,
            do_kerberos=options.do_kerberos,
            do_simple=options.do_simple,
            use_sspi=options.use_sspi,
            dc_ip=dc_ip,
            dc_host=dc_host,
            timeout=options.timeout,
            ldap_channel_binding=ldap_channel_binding,
            ldap_port=ldap_port,
        )

        # Adjust DC IP if needed
        if dc_as_target and options.dc_ip is None and is_ip(remote_name):
            target.dc_ip = remote_name

        # Set up DNS resolver
        ns = options.ns if hasattr(options, "ns") else target.dc_ip
        dns_tcp = options.dns_tcp if hasattr(options, "dns_tcp") else False

        # Handle target IP
        target_ip = options.target_ip if hasattr(options, "target_ip") else None
        if is_ip(remote_name):
            target_ip = remote_name

        target.resolver = DnsResolver.create(target, ns=ns, dns_tcp=dns_tcp)

        target.target_ip = target_ip
        if target.target_ip is None:
            target.target_ip = target.resolver.resolve(remote_name)

        # Ensure DC IP is resolved
        if target.dc_ip is None and domain:
            target.dc_ip = target.resolver.resolve(domain)

        return target

    @staticmethod
    def create(
        domain: str = "",
        username: str = "",
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
        # Handle SSPI authentication (Windows only)
        if use_sspi:
            do_kerberos = True
            username, domain, dc_ip, dc_host = get_logon_session()
            logging.debug(f"SSPI Context: {username}@{domain} on {dc_host} ({dc_ip})")
        else:
            dc_host = None

        # Normalize domain and username
        domain = domain.upper() if domain else ""
        username = username.upper() if username else ""

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
        lmhash = ""
        nthash = ""
        if hashes is not None:
            hash_parts = hashes.split(":")
            if len(hash_parts) == 1:
                nthash = hash_parts[0]
                lmhash = nthash
            else:
                lmhash, nthash = hash_parts
                if len(lmhash) == 0:
                    lmhash = nthash

        # AES key implies Kerberos
        if aes is not None:
            do_kerberos = True

        # Ensure remote_name has a value
        if remote_name is None:
            if target_ip:
                remote_name = target_ip
            elif domain:
                remote_name = domain
            else:
                remote_name = ""

        # Create target instance
        target = Target(
            domain=domain,
            username=username,
            password=password,
            remote_name=remote_name,
            hashes=hashes,
            lmhash=lmhash,
            nthash=nthash,
            aes=aes,
            do_kerberos=do_kerberos,
            do_simple=do_simple,
            use_sspi=use_sspi,
            dc_ip=dc_ip,
            dc_host=dc_host,
            target_ip=target_ip,
            timeout=timeout,
            ldap_channel_binding=ldap_channel_binding,
            ldap_port=ldap_port,
        )

        # Handle DNS and target IP configuration
        if ns is None:
            ns = dc_ip

        if is_ip(remote_name):
            target.target_ip = remote_name

        target.resolver = DnsResolver.create(target, ns=ns, dns_tcp=dns_tcp)

        if target.target_ip is None:
            target.target_ip = target.resolver.resolve(remote_name)

        return target

    def resolve_hostname(self, hostname: str) -> str:
        """
        Resolve a hostname to IP address using the configured resolver.
        
        Args:
            hostname: The hostname to resolve
            
        Returns:
            The resolved IP address or the original hostname if resolution fails
        """
        if self.resolver is None:
            self.resolver = DnsResolver.create(self)
            
        return self.resolver.resolve(hostname)

    def __repr__(self) -> str:
        """String representation of the Target object."""
        return f"<Target ({self.__dict__!r})>"


class DnsResolver:
    """
    DNS resolver for hostname resolution with caching capabilities.
    """

    def __init__(self) -> None:
        """Initialize a new DNS resolver with default settings."""
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
        resolver = DnsResolver()

        # We can't put all possible nameservers in the list of nameservers, since
        # the resolver will fail if one of them fails
        nameserver = options.ns
        if nameserver is None:
            nameserver = target.dc_ip

        if nameserver is not None:
            resolver.resolver.nameservers = [nameserver]

        resolver.use_tcp = options.dns_tcp

        return resolver

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
        resolver = DnsResolver()

        # We can't put all possible nameservers in the list of nameservers, since
        # the resolver will fail if one of them fails
        nameserver = ns
        if nameserver is None and target is not None:
            nameserver = target.dc_ip

        if nameserver is not None:
            resolver.resolver.nameservers = [nameserver]

        resolver.use_tcp = dns_tcp

        return resolver

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