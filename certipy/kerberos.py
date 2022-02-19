import datetime
import logging
import os
from typing import Tuple

from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ, TGS_REP, Authenticator, seq_set
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key
from impacket.krb5.kerberosv5 import KerberosError, getKerberosTGS, getKerberosTGT
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from pyasn1.codec.ber import decoder, encoder
from pyasn1.type.univ import noValue


def get_TGS(
    username: str = "",
    password: str = "",
    domain: str = "",
    lmhash: str = "",
    nthash: str = "",
    aes_key: str = "",
    TGT: dict = None,
    TGS: dict = None,
    target_name: str = "",
    service: str = "host",
    kdc_host: str = None,
    use_cache: bool = True,
) -> Tuple[bytes, type, Key]:
    # Modified version of impacket.krb5.kerberosv5.getKerberosType1 to just return the tgs

    # Convert to binary form, just in case we're receiving strings
    if isinstance(lmhash, str):
        try:
            lmhash = bytes.fromhex(lmhash)
        except TypeError:
            pass
    if isinstance(nthash, str):
        try:
            nthash = bytes.fromhex(nthash)
        except TypeError:
            pass
    if isinstance(aes_key, str):
        try:
            aes_key = bytes.fromhex(aes_key)
        except TypeError:
            pass

    if TGT is None and TGS is None:
        if use_cache is True:
            try:
                ccache = CCache.loadFile(os.getenv("KRB5CCNAME"))
            except Exception:
                # No cache present
                pass
            else:
                # retrieve domain information from CCache file if needed
                ccache_domain = ccache.principal.realm["data"].decode("utf-8")

                if domain == "":
                    domain = ccache_domain
                    logging.debug("Domain retrieved from CCache: %s" % domain)

                ccache_username = "/".join(
                    map(lambda x: x["data"].decode(), ccache.principal.components)
                )

                logging.debug("Using Kerberos Cache: %s" % os.getenv("KRB5CCNAME"))
                principal = "%s/%s@%s" % (service, target_name.upper(), domain.upper())
                creds = ccache.getCredential(principal, anySPN=False)
                if creds is None:
                    # Let's try for the TGT and go from there
                    principal = "krbtgt/%s@%s" % (domain.upper(), domain.upper())
                    creds = ccache.getCredential(principal)
                    if creds is not None:
                        TGT = creds.toTGT()
                        logging.debug("Using TGT from cache")
                    else:
                        logging.debug("No valid credentials found in cache. ")
                else:
                    TGS = creds.toTGS(principal)

                # retrieve user information from CCache file if needed
                if creds is not None:
                    ccache_username = (
                        creds["client"].prettyPrint().split(b"@")[0].decode("utf-8")
                    )
                    logging.debug(
                        "Username retrieved from CCache: %s" % ccache_username
                    )
                elif len(ccache.principal.components) > 0:
                    ccache_username = ccache.principal.components[0]["data"].decode(
                        "utf-8"
                    )
                    logging.debug(
                        "Username retrieved from CCache: %s" % ccache_username
                    )

                if ccache_username.lower() != username.lower():
                    logging.warning(
                        "Username %s does not match username in CCache %s"
                        % (repr(username), repr(ccache_username))
                    )
                    TGT = None
                    TGS = None
                else:
                    username = ccache_username

                if ccache_domain.lower() != domain.lower():
                    logging.warning(
                        "Domain %s does not match domain in CCache %s"
                        % (repr(domain), repr(ccache_domain))
                    )

    # First of all, we need to get a TGT for the user
    username = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    while True:
        if TGT is None:
            if TGS is None:
                try:
                    logging.debug(
                        "Getting TGT for %s" % repr("%s@%s" % (username, domain))
                    )
                    tgt, cipher, _, session_key = getKerberosTGT(
                        username, password, domain, lmhash, nthash, aes_key, kdc_host
                    )
                    logging.debug("Got TGT for %s" % repr("%s@%s" % (username, domain)))
                except KerberosError as e:
                    if (
                        e.getErrorCode()
                        == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value
                    ):
                        # We might face this if the target does not support AES
                        # So, if that's the case we'll force using RC4 by converting
                        # the password to lm/nt hashes and hope for the best. If that's already
                        # done, byebye.
                        if (
                            lmhash == b""
                            and nthash == b""
                            and (aes_key == b"" or aes_key is None)
                            and TGT is None
                            and TGS is None
                        ):
                            from impacket.ntlm import compute_lmhash, compute_nthash

                            logging.debug("Got KDC_ERR_ETYPE_NOSUPP, fallback to RC4")
                            lmhash = compute_lmhash(password)
                            nthash = compute_nthash(password)
                            continue
                        else:
                            raise
                    else:
                        raise

        else:
            tgt = TGT["KDC_REP"]
            cipher = TGT["cipher"]
            session_key = TGT["sessionKey"]

        # Now that we have the TGT, we should ask for a TGS for cifs

        if TGS is None:
            server_name = Principal(
                "%s/%s" % (service, target_name),
                type=constants.PrincipalNameType.NT_SRV_INST.value,
            )
            try:
                logging.debug(
                    "Getting TGS for %s" % repr("%s/%s" % (service, target_name))
                )
                tgs, cipher, _, session_key = getKerberosTGS(
                    server_name, domain, kdc_host, tgt, cipher, session_key
                )
                logging.debug("Got TGS for %s" % repr("%s/%s" % (service, target_name)))
            except KerberosError as e:
                if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                    # We might face this if the target does not support AES
                    # So, if that's the case we'll force using RC4 by converting
                    # the password to lm/nt hashes and hope for the best. If that's already
                    # done, byebye.
                    if (
                        lmhash == b""
                        and nthash == b""
                        and (aes_key == b"" or aes_key is None)
                        and TGT is None
                        and TGS is None
                    ):
                        from impacket.ntlm import compute_lmhash, compute_nthash

                        logging.debug("Got KDC_ERR_ETYPE_NOSUPP, fallback to RC4")
                        lmhash = compute_lmhash(password)
                        nthash = compute_nthash(password)
                    else:
                        raise
                else:
                    raise
            else:
                break
        else:
            tgs = TGS["KDC_REP"]
            cipher = TGS["cipher"]
            session_key = TGS["sessionKey"]
            break

    return tgs, cipher, session_key


def get_kerberos_type1(
    username: str = "",
    password: str = "",
    domain: str = "",
    lmhash: str = "",
    nthash: str = "",
    aes_key: str = "",
    TGT: dict = None,
    TGS: dict = None,
    target_name: str = "",
    service: str = "host",
    kdc_host: str = None,
    use_cache: bool = True,
) -> Tuple[type, Key, bytes]:
    tgs, cipher, session_key = get_TGS(
        username,
        password,
        domain,
        lmhash,
        nthash,
        aes_key,
        TGT,
        TGS,
        target_name,
        service,
        kdc_host,
        use_cache,
    )

    username = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    blob = SPNEGO_NegTokenInit()

    blob["MechTypes"] = [TypesMech["MS KRB5 - Microsoft Kerberos 5"]]

    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs["ticket"])

    ap_req = AP_REQ()
    ap_req["pvno"] = 5
    ap_req["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = []
    ap_req["ap-options"] = constants.encodeFlags(opts)
    seq_set(ap_req, "ticket", ticket.to_asn1)

    authenticator = Authenticator()
    authenticator["authenticator-vno"] = 5
    authenticator["crealm"] = domain
    seq_set(authenticator, "cname", username.components_to_asn1)
    now = datetime.datetime.utcnow()

    authenticator["cusec"] = now.microsecond
    authenticator["ctime"] = KerberosTime.to_asn1(now)

    encoded_authenticator = encoder.encode(authenticator)

    encrypted_encoded_authenticator = cipher.encrypt(
        session_key, 11, encoded_authenticator, None
    )

    ap_req["authenticator"] = noValue
    ap_req["authenticator"]["etype"] = cipher.enctype
    ap_req["authenticator"]["cipher"] = encrypted_encoded_authenticator

    blob["MechToken"] = encoder.encode(ap_req)

    return cipher, session_key, blob.getData()
