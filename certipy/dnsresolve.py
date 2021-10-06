import argparse
import logging
import socket

from dns.resolver import Resolver

from certipy.target import Target


class DnsResolver:
    def __init__(self, options: argparse.Namespace, target: Target):
        self.resolver = Resolver()

        # We can't put all possible nameservers in the list of nameservers, since
        # the resolver will fail if one of them fails
        nameserver = options.nameserver
        if nameserver is None:
            nameserver = target.dc_ip
        if nameserver is None:
            nameserver = target.target_ip

        self.resolver.nameservers = [nameserver]
        self.use_tcp = options.dns_tcp

    def resolve(self, hostname: str) -> str:
        # Try to resolve the hostname with DNS first, then try a local resolve
        try:
            # Check if hostname is an IP
            socket.inet_aton(hostname)
            return hostname
        except Exception:
            pass

        ip_addr = None
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

        return ip_addr
