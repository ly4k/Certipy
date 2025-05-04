"""
Kerberos authentication module for Certipy.

This module provides functionality to obtain Kerberos tickets and authenticate to services
using Kerberos. It supports:
- Obtaining TGT (Ticket Granting Ticket) and TGS (Ticket Granting Service) tickets
- Kerberos authentication for HTTP requests
"""

import base64
import datetime
import os
from typing import Optional, Tuple

import httpx
from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ, TGS_REP, Authenticator, seq_set
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key
from impacket.krb5.kerberosv5 import KerberosError, getKerberosTGS, getKerberosTGT
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from pyasn1.codec.ber import decoder, encoder
from pyasn1.type.univ import noValue

from certipy.lib.logger import logging
from certipy.lib.target import Target
from certipy.lib.structs import e2i


def _convert_to_binary(data: Optional[str]) -> Optional[bytes]:
    """
    Convert string hex representation to bytes if needed.

    Args:
        data: String hex representation or bytes

    Returns:
        Bytes representation or None if input was None or empty
    """
    if data is None:
        return None

    if len(data) == 0:
        return None

    return bytes.fromhex(data)


def get_TGS(
    target: Target,
    target_name: str,
    service: str = "host",
) -> Tuple[bytes, type, Key, str, str]:
    """
    Get a Ticket Granting Service (TGS) ticket for accessing a specific service.

    This function tries multiple strategies to obtain a TGS:
    1. Using an existing Kerberos ticket cache
    2. Requesting a new TGT and then a TGS

    Args:
        target: Target object containing authentication details
        target_name: Name of the target server
        service: Service type (default: "host")

    Returns:
        Tuple containing:
        - TGS data
        - Cipher object
        - Session key
        - Username
        - Domain

    Raises:
        KerberosError: If authentication fails
        Exception: On various errors such as missing credentials or unsupported encryption types
    """
    username = target.username
    password = target.password
    domain = target.domain
    lmhash = _convert_to_binary(target.lmhash)
    nthash = _convert_to_binary(target.nthash)
    aes_key = _convert_to_binary(target.aes)
    kdc_host = target.dc_ip

    TGT: Optional[dict] = None
    TGS: Optional[dict] = None

    # Try to use existing ticket cache
    try:
        ccache = CCache.loadFile(os.getenv("KRB5CCNAME"))
    except Exception:
        ccache = None

    if ccache:
        # Validate cache data
        if ccache.principal is None:
            raise Exception("No principal found in CCache file")
        if ccache.principal.realm is None:
            raise Exception("No realm/domain found in CCache file")

        # Extract domain from cache if needed
        # TODO: Support unicode domain names
        ccache_domain = ccache.principal.realm["data"].decode("utf-8")
        if not domain:
            domain = ccache_domain
            logging.debug(f"Domain retrieved from CCache: {domain}")

        # Extract username from cache
        ccache_username = "/".join(
            map(lambda x: x["data"].decode(), ccache.principal.components)
        )

        logging.debug(f"Using Kerberos Cache: {os.getenv('KRB5CCNAME')}")

        # Try to find appropriate credentials in cache
        principal = f"{service}/{target_name.upper()}@{domain.upper()}"
        creds = ccache.getCredential(principal)

        if creds is None:
            # Look for TGT if service ticket not found
            principal = f"krbtgt/{domain.upper()}@{domain.upper()}"
            creds = ccache.getCredential(principal)
            if creds is not None:
                TGT = creds.toTGT()
                logging.debug("Using TGT from cache")
            else:
                logging.debug("No valid credentials found in cache.")
        else:
            TGS = creds.toTGS(principal)

        # Validate user information
        if creds is not None:
            ccache_username = (
                creds["client"].prettyPrint().split(b"@")[0].decode("utf-8")
            )
            logging.debug(f"Username retrieved from CCache: {ccache_username}")
        elif ccache.principal.components:
            ccache_username = ccache.principal.components[0]["data"].decode("utf-8")
            logging.debug(f"Username retrieved from CCache: {ccache_username}")

        # Validate username in cache against requested username
        if ccache_username.lower() != username.lower() and username:
            logging.warning(
                f"Username {username!r} does not match username in CCache {ccache_username!r}"
            )
            TGT = None
            TGS = None
        else:
            username = ccache_username

        # Validate domain
        if ccache_domain.lower() != domain.lower() and domain:
            logging.warning(
                f"Domain {domain!r} does not match domain in CCache {ccache_domain!r}"
            )

    # Create principal object for the user
    user_principal = Principal(username, type=e2i(constants.PrincipalNameType.NT_PRINCIPAL))

    while True:
        if TGT is None:
            if TGS is None:
                try:
                    # Request new TGT
                    logging.debug(f"Getting TGT for {username!r}@{domain!r}")
                    tgt, cipher, _, session_key = getKerberosTGT(
                        user_principal, password, domain, lmhash, nthash, aes_key, kdc_host  # type: ignore
                    )
                    logging.debug(f"Got TGT for {username!r}@{domain!r}")
                except KerberosError as e:
                    # Handle encryption type not supported error
                    if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP:
                        # Fall back to RC4 if AES not supported and we're using password auth
                        if (
                            not lmhash
                            and not nthash
                            and (not aes_key or aes_key == b"")
                            and not TGT
                            and not TGS
                            and password
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
            # Use existing TGT
            tgt = TGT["KDC_REP"]
            cipher = TGT["cipher"]
            session_key = TGT["sessionKey"]

        # Request TGS using the TGT if we don't already have one
        if TGS is None:
            server_principal = Principal(
                f"{service}/{target_name}",
                type=e2i(constants.PrincipalNameType.NT_SRV_INST),
            )
            try:
                logging.debug(f"Getting TGS for {service}/{target_name!r}")
                tgs, cipher, _, session_key = getKerberosTGS(
                    server_principal, domain, kdc_host, tgt, cipher, session_key
                )
                logging.debug(f"Got TGS for {service}/{target_name!r}")
                break
            except KerberosError as e:
                # Handle encryption type not supported error
                if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP:
                    # Fall back to RC4 if AES not supported and we're using password auth
                    if (
                        not lmhash
                        and not nthash
                        and (not aes_key or aes_key == b"")
                        and not TGT
                        and not TGS
                        and password
                    ):
                        from impacket.ntlm import compute_lmhash, compute_nthash

                        logging.debug("Got KDC_ERR_ETYPE_NOSUPP, fallback to RC4")
                        lmhash = compute_lmhash(password)
                        nthash = compute_nthash(password)
                        # Start over with the new hashes
                        TGT = None
                    else:
                        raise
                else:
                    raise
        else:
            # Use existing TGS
            tgs = TGS["KDC_REP"]
            cipher = TGS["cipher"]
            session_key = TGS["sessionKey"]
            break

    # Extract client information from ticket
    ticket = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    client_name = Principal()
    client_name = client_name.from_asn1(ticket, "crealm", "cname")

    username = "@".join(str(client_name).split("@")[:-1])
    domain = client_name.realm or ""

    return tgs, cipher, session_key, username, domain


def get_kerberos_type1(
    target: Target,
    target_name: str = "",
    service: str = "host",
) -> Tuple[type, Key, bytes, str]:
    """
    Generate a Kerberos Type 1 authentication message (AP_REQ).

    This function creates a SPNEGO token containing Kerberos authentication data
    that can be used in HTTP or other protocol authentication.

    Args:
        target: Target object containing authentication details
        target_name: Name of the target server (default: empty string)
        service: Service type (default: "host")

    Returns:
        Tuple containing:
        - Cipher object
        - Session key
        - SPNEGO token blob
        - Username
    """
    tgs, cipher, session_key, username, domain = get_TGS(target, target_name, service)

    # Create principal for the client
    principal = Principal(username, type=e2i(constants.PrincipalNameType.NT_PRINCIPAL))

    # Build SPNEGO init token
    blob = SPNEGO_NegTokenInit()
    blob["MechTypes"] = [TypesMech["MS KRB5 - Microsoft Kerberos 5"]]

    # Extract ticket from TGS response
    tgs_rep: TGS_REP = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    _ = ticket.from_asn1(tgs_rep["ticket"])

    # Build AP_REQ message
    ap_req = AP_REQ()
    ap_req["pvno"] = 5
    ap_req["msg-type"] = e2i(constants.ApplicationTagNumbers.AP_REQ)
    ap_req["ap-options"] = constants.encodeFlags([])  # No options
    seq_set(ap_req, "ticket", ticket.to_asn1)

    # Create authenticator
    authenticator = Authenticator()
    authenticator["authenticator-vno"] = 5
    authenticator["crealm"] = domain
    seq_set(authenticator, "cname", principal.components_to_asn1)

    # Add timestamp
    now = datetime.datetime.now(datetime.timezone.utc)
    authenticator["cusec"] = now.microsecond
    authenticator["ctime"] = KerberosTime.to_asn1(now)

    # Encode and encrypt the authenticator
    encoded_authenticator = encoder.encode(authenticator)
    encrypted_encoded_authenticator = cipher.encrypt(
        session_key, 11, encoded_authenticator, None
    )

    # Add the encrypted authenticator to the AP_REQ
    ap_req["authenticator"] = noValue
    ap_req["authenticator"]["etype"] = cipher.enctype
    ap_req["authenticator"]["cipher"] = encrypted_encoded_authenticator

    # Add the AP_REQ to the SPNEGO token
    blob["MechToken"] = encoder.encode(ap_req)

    return cipher, session_key, blob.getData(), username


class HttpxImpacketKerberosAuth(httpx.Auth):
    """
    HTTPX authentication class for Kerberos authentication.

    This class enables Kerberos authentication for HTTPX requests by
    implementing the auth_flow protocol required by HTTPX.
    """

    def __init__(self, target: Target, service: str = "HTTP"):
        """
        Initialize the Kerberos authentication handler.

        Args:
            target: Target object containing connection and authentication details
            service: Service principal name prefix to use (default: "HTTP")
        """
        self.target = target
        self.service = service

    def auth_flow(self, request: httpx.Request):
        """
        Implement the authentication flow for HTTPX.

        This method adds a Kerberos authentication header to the request.

        Args:
            request: The HTTPX request to modify

        Yields:
            The modified request
        """
        _, _, spnego_blob, _ = get_kerberos_type1(
            self.target, self.target.remote_name, self.service
        )

        auth_header = f"Negotiate {base64.b64encode(spnego_blob).decode()}"
        request.headers["Authorization"] = auth_header

        # Yield the modified request to be sent
        yield request
