# Certipy - Active Directory certificate abuse
#
# Description:
#   Target parsing from command line
#
# Authors:
#   @ly4k (https://github.com/ly4k)
#

import traceback

from impacket.examples.utils import parse_target


class Target:
    def __init__(self, options):
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
        else:
            lmhash = nthash = ""

        self.domain = domain
        self.username = username
        self.password = password
        self.remote_name = remote_name
        self.lmhash = lmhash
        self.nthash = nthash
        self.do_kerberos = options.k
        self.dc_ip = options.dc_ip

        if options.target_ip is None:
            self.target_ip = remote_name

            from certipy.dnsresolve import DnsResolver

            resolver = DnsResolver(options, self)
            options.target_ip = resolver.resolve(remote_name)

        self.target_ip = options.target_ip

    def __repr__(self) -> str:
        return "<Target (%s)>" % repr(self.__dict__)
