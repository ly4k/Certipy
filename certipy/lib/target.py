"""
Target management module for Certipy.

This module provides functionality for creating and managing target objects
that represent authentication endpoints. It handles:

- Authentication parameters (username, password, hashes, Kerberos tickets)
- Target name resolution (DNS, local resolution, IP address validation)
- Connection settings (timeouts, ports, protocol options)
- Domain controller discovery
- Kerberos ticket cache integration

The primary class is Target, which encapsulates all connection parameters
needed to authenticate to and interact with Windows/Active Directory services.
Helper classes like DnsResolver provide supporting functionality.
"""

import argparse
import os
import socket
from typing import Dict, Optional, Tuple

from dns.resolver import Resolver
from impacket.krb5.ccache import CCache

from certipy.lib.errors import handle_error
from certipy.lib.logger import logging


class Target:
    """
    Class representing an authentication target with all necessary connection details.
    """

    def __init__(
        self,
        resolver: "DnsResolver",
        domain: str = "",
        username: str = "",
        password: Optional[str] = None,
        remote_name: str = "",
        hashes: Optional[str] = None,
        lmhash: str = "",
        nthash: str = "",
        do_kerberos: bool = False,
        do_simple: bool = False,
        aes: Optional[str] = None,
        dc_ip: Optional[str] = None,
        dc_host: Optional[str] = None,
        target_ip: Optional[str] = None,
        timeout: int = 5,
        ldap_scheme: str = "ldaps",
        ldap_port: Optional[int] = None,
        ldap_channel_binding: bool = True,
        ldap_signing: bool = True,
        ldap_user_dn: Optional[str] = None,
    ) -> None:
        """
        Initialize a Target with the specified connection parameters.

        Args:
            resolver: DNS resolver for hostname resolution
            domain: Domain name (empty string if not specified)
            username: Username (empty string if not specified)
            password: Password (None if not specified)
            remote_name: Remote target name (empty string if not specified)
            hashes: NTLM hashes in format LM:NT
            lmhash: LM hash
            nthash: NT hash
            do_kerberos: Use Kerberos authentication
            do_simple: Use simple authentication
            aes: AES key for Kerberos authentication
            dc_ip: Domain controller IP
            dc_host: Domain controller hostname
            target_ip: Target IP address
            timeout: Connection timeout in seconds
            ldap_scheme: LDAP scheme (default is ldaps)
            ldap_port: LDAP port to use
            ldap_channel_binding: Use LDAP channel binding
            ldap_signing: Use LDAP signing
            ldap_user_dn: LDAP user distinguished name
        """
        self.resolver = resolver

        self.domain: str = domain
        self.username: str = username
        self.password: Optional[str] = password
        self.remote_name: str = remote_name
        self.hashes: Optional[str] = hashes
        self.lmhash: str = lmhash
        self.nthash: str = nthash
        self.do_kerberos: bool = do_kerberos
        self.do_simple: bool = do_simple
        self.aes: Optional[str] = aes
        self.dc_ip: Optional[str] = dc_ip
        self.dc_host: Optional[str] = dc_host
        self.target_ip: Optional[str] = target_ip
        self.timeout: int = timeout
        self.ldap_scheme: str = ldap_scheme
        self.ldap_port: Optional[int] = ldap_port
        self.ldap_channel_binding: bool = ldap_channel_binding
        self.ldap_signing: bool = ldap_signing
        self.ldap_user_dn: Optional[str] = ldap_user_dn

    @staticmethod
    def from_options(
        options: argparse.Namespace,
        dc_as_target: bool = False,
        require_username: bool = True,
    ) -> "Target":
        """
        Create a Target from command line options.

        Args:
            options: Command line options
            dc_as_target: Whether to use DC as target

        Returns:
            Target: Configured target object

        Raises:
            Exception: If no target can be determined
        """
        # Domain controller options
        dc_ip = options.dc_ip if hasattr(options, "dc_ip") else None
        dc_host = options.dc_host if hasattr(options, "dc_host") else None

        # Target machine options
        target_ip = options.target_ip if hasattr(options, "target_ip") else None
        target = options.target if hasattr(options, "target") else None

        # DNS options
        ns = options.ns if hasattr(options, "ns") else dc_ip
        dns_tcp = options.dns_tcp if hasattr(options, "dns_tcp") else False

        # Connection options
        timeout = options.timeout if hasattr(options, "timeout") else 10

        # Authentication options
        principal = options.username if hasattr(options, "username") else None
        password = options.password if hasattr(options, "password") else None
        hashes = options.hashes if hasattr(options, "hashes") else None

        do_kerberos = options.do_kerberos if hasattr(options, "do_kerberos") else False
        do_simple = options.do_simple if hasattr(options, "do_simple") else False
        aes = options.aes if hasattr(options, "aes") else None
        no_pass = options.no_pass if hasattr(options, "no_pass") else False

        # LDAP options
        ldap_scheme = (
            options.ldap_scheme if hasattr(options, "ldap_scheme") else "ldaps"
        )
        ldap_port = options.ldap_port if hasattr(options, "ldap_port") else None
        no_ldap_channel_binding = (
            options.no_ldap_channel_binding
            if hasattr(options, "no_ldap_channel_binding")
            else False
        )
        no_ldap_signing = (
            options.no_ldap_signing if hasattr(options, "no_ldap_signing") else False
        )
        ldap_user_dn = (
            options.ldap_user_dn if hasattr(options, "ldap_user_dn") else None
        )

        # Parse username and domain from principal format (user@DOMAIN)
        domain = ""
        username = ""

        if principal is not None:
            parts = principal.split("@")
            if len(parts) == 1:
                username = parts[0]
            else:
                username = "@".join(parts[:-1])
                domain = parts[-1]

        # Handle Kerberos authentication
        if do_kerberos:
            principal = get_kerberos_principal()
            if principal:
                username, domain = principal

        # Normalize domain and username
        domain = domain.upper()
        username = username.upper()

        if require_username and len(username) == 0:
            logging.error("Username is not specified")

        # Handle password input
        if (
            not password
            and username != ""
            and hashes is None
            and aes is None
            and no_pass is not True
            and do_kerberos is not True
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

        # Determine remote target name
        remote_name = target or ""
        if do_kerberos and not remote_name:
            logging.warning(
                "Target name (-target) not specified and Kerberos authentication is used. This might fail"
            )

        if dc_as_target:
            if not remote_name and dc_host:
                remote_name = dc_host

            if not remote_name:
                logging.debug(
                    f"Target name (-target) and DC host (-dc-host) not specified. Using domain {domain!r} as target name. This might fail for cross-realm operations"
                )
                remote_name = domain

            if not target_ip and dc_ip:
                target_ip = dc_ip

            if not dc_host:
                dc_host = remote_name
        else:
            if not dc_host and domain:
                if do_kerberos:
                    logging.warning(
                        "DC host (-dc-host) not specified and Kerberos authentication is used. This might fail"
                    )
                logging.debug(
                    "DC host (-dc-host) not specified. Using domain as DC host"
                )
                dc_host = domain

        if not remote_name:
            if target_ip:
                remote_name = target_ip
            elif dc_host:
                remote_name = dc_host
            elif dc_ip:
                remote_name = dc_ip
            elif domain:
                remote_name = domain
            else:
                raise Exception("Could not find a target in the specified options")

        # Configure LDAP optinos
        if ldap_port is None:
            if ldap_scheme == "ldap":
                ldap_port = 389
            else:
                ldap_port = 636

        # Adjust DC IP if needed
        if dc_as_target and dc_ip is None and is_ip(remote_name):
            dc_ip = remote_name

        # Handle target IP
        if is_ip(remote_name):
            target_ip = remote_name

        ns = ns or dc_ip

        logging.debug(f"Nameserver: {ns!r}")
        logging.debug(f"DC IP: {dc_ip!r}")
        logging.debug(f"DC Host: {dc_host!r}")
        logging.debug(f"Target IP: {target_ip!r}")
        logging.debug(f"Remote Name: {remote_name!r}")
        logging.debug(f"Domain: {domain!r}")
        logging.debug(f"Username: {username!r}")

        resolver = DnsResolver.create(ns=ns, dc_ip=dc_ip, dns_tcp=dns_tcp)

        if target_ip is None:
            target_ip = resolver.resolve(remote_name)

        # Ensure DC IP is resolved
        if dc_ip is None and dc_host:
            dc_ip = resolver.resolve(dc_host)

        # Create target instance
        target = Target(
            resolver,
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
            dc_ip=dc_ip,
            dc_host=dc_host,
            target_ip=target_ip,
            timeout=timeout,
            ldap_scheme=ldap_scheme,
            ldap_channel_binding=not no_ldap_channel_binding,
            ldap_signing=not no_ldap_signing,
            ldap_port=ldap_port,
            ldap_user_dn=ldap_user_dn,
        )

        return target

    def resolve_hostname(self, hostname: str) -> str:
        """
        Resolve a hostname to IP address using the configured resolver.

        Args:
            hostname: The hostname to resolve

        Returns:
            The resolved IP address or the original hostname if resolution fails
        """
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
        ns: Optional[str] = None,
        dc_ip: Optional[str] = None,
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
        nameserver = ns or dc_ip

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
        except Exception as e:
            logging.warning(f"DNS resolution failed: {e}")
            handle_error(True)
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


def get_kerberos_principal() -> Optional[Tuple[str, str]]:
    """
    Get Kerberos principal information from the KRB5CCNAME environment variable.

    Returns:
        Tuple containing (username, domain) or None if not available
    """
    krb5ccname = os.getenv("KRB5CCNAME")
    if krb5ccname is None:
        logging.warning("KRB5CCNAME environment variable not set")
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
