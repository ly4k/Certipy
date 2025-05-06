"""
Kerberos authentication module for Certipy.

This module provides functionality for Kerberos-based authentication and ticket management,
supporting both credential-based and ticket-based operations against Windows services.

Key features:
- TGT (Ticket Granting Ticket) acquisition and caching
- TGS (Ticket Granting Service) ticket acquisition and caching
- Kerberos authentication for HTTP requests
- Support for channel binding with EPA (Extended Protection for Authentication)
"""

import base64
import datetime
import os
import struct
from typing import Any, Dict, Generator, Optional, Tuple, cast

import httpx
from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ, TGS_REP, Authenticator, seq_set
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key
from impacket.krb5.gssapi import GSS_C_CONF_FLAG, GSS_C_INTEG_FLAG, CheckSumField
from impacket.krb5.kerberosv5 import KerberosError, getKerberosTGS, getKerberosTGT
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from pyasn1.codec.ber import decoder, encoder
from pyasn1.type.univ import noValue

from certipy.lib.channel_binding import get_channel_binding_data_from_response
from certipy.lib.logger import logging
from certipy.lib.structs import e2i
from certipy.lib.target import Target

# Constants
KERB_AP_OPTIONS_CBT = 0x4000  # Channel Binding token flag
KRB_CLOCK_SKEW = 300  # 5 minutes in seconds
AUTH_DATA_AP_OPTIONS = 143  # AD-AUTH-DATA-AP-OPTIONS type

# Cache for TGT and TGS tickets to avoid redundant authentication
TGT_CACHE: Dict[
    Tuple[str, str, bytes, bytes, bytes, str | None], Tuple[bytes, type, Key]
] = {}
TGS_CACHE: Dict[
    Tuple[str, str, str | None, bytes | Any, type | Any, Key | Any],
    Tuple[bytes, type, Key],
] = {}


def _convert_to_binary(data: Optional[str]) -> Optional[bytes]:
    """
    Convert string hex representation to binary bytes.

    Args:
        data: String hex representation or None

    Returns:
        Bytes representation or None if input was None or empty
    """
    if not data:
        return None

    return bytes.fromhex(data)


def get_TGS(
    target: Target,
    target_name: str,
    service: str = "HOST",
) -> Tuple[bytes, type, Key, str, str]:
    """
    Obtain a Ticket Granting Service (TGS) ticket for the specified service.

    This function implements a multi-step strategy for acquiring a TGS:
    1. Try to use credentials from an existing Kerberos ticket cache (KRB5CCNAME)
    2. Request a new TGT using provided credentials if needed
    3. Use the TGT to request a service ticket (TGS)
    4. Handle encryption type fallbacks for compatibility with different KDCs

    Args:
        target: Target object with authentication details (username, domain, etc.)
        target_name: Hostname of the target server
        service: Service type (e.g., "HTTP", "HOST", "LDAP")

    Returns:
        Tuple containing:
        - TGS data (bytes)
        - Cipher object for encryption operations
        - Session key for subsequent communications
        - Authenticated username
        - Authenticated domain

    Raises:
        KerberosError: For Kerberos protocol errors (bad credentials, expired tickets, etc.)
        Exception: For general errors (missing cache files, misconfiguration)
    """
    # Extract authentication details from target
    username = target.username
    password = target.password
    domain = target.domain
    lmhash = _convert_to_binary(target.lmhash) or b""
    nthash = _convert_to_binary(target.nthash) or b""
    aes_key = _convert_to_binary(target.aes) or b""
    kdc_host = target.dc_ip

    tgt: Optional[Dict[str, Any]] = None
    tgs: Optional[Dict[str, Any]] = None

    # Step 1: Try to use existing ticket cache if available
    logging.debug("Checking for Kerberos ticket cache")
    try:
        ccache = (
            CCache.loadFile(os.getenv("KRB5CCNAME"))
            if os.getenv("KRB5CCNAME")
            else None
        )
    except Exception as e:
        logging.debug(f"Failed to load Kerberos cache: {e}")
        ccache = None

    if ccache:
        # Validate and extract information from cache
        if not ccache.principal:
            raise Exception("No principal found in CCache file")
        if not ccache.principal.realm:
            raise Exception("No realm/domain found in CCache file")

        # Extract domain from cache if needed
        ccache_domain = ccache.principal.realm["data"].decode("utf-8")
        if not domain:
            domain = ccache_domain
            logging.debug(f"Domain retrieved from CCache: {domain}")

        # Extract username from cache components
        ccache_username = "/".join(
            map(lambda x: x["data"].decode(), ccache.principal.components)
        )

        logging.debug(f"Using Kerberos Cache: {os.getenv('KRB5CCNAME')}")

        # Try to find appropriate credentials in cache
        # First look for the specific service ticket
        principal = f"{service}/{target_name.upper()}@{domain.upper()}"
        creds = ccache.getCredential(principal)

        if creds is None:
            # If service ticket not found, look for TGT
            principal = f"krbtgt/{domain.upper()}@{domain.upper()}"
            creds = ccache.getCredential(principal)
            if creds is not None:
                tgt = creds.toTGT()
                logging.debug("Using TGT from cache")
            else:
                logging.debug("No valid credentials found in cache")
        else:
            tgs = creds.toTGS(principal)
            logging.debug(f"Using {service} ticket from cache")

        # Validate username from credentials or cache
        if creds is not None:
            ccache_username = (
                creds["client"].prettyPrint().split(b"@")[0].decode("utf-8")
            )
            logging.debug(
                f"Username retrieved from CCache credential: {ccache_username}"
            )
        elif ccache.principal.components:
            ccache_username = ccache.principal.components[0]["data"].decode("utf-8")
            logging.debug(
                f"Username retrieved from CCache principal: {ccache_username}"
            )

        # Verify username matches if specified
        if username and ccache_username.lower() != username.lower():
            logging.warning(
                f"Username {username!r} does not match username in CCache {ccache_username!r}"
            )
            tgt = None
            tgs = None
        else:
            username = ccache_username

        # Verify domain matches if specified
        if domain and ccache_domain.lower() != domain.lower():
            logging.warning(
                f"Domain {domain!r} does not match domain in CCache {ccache_domain!r}"
            )

    # Step 2: Set up the client principal
    user_principal = Principal(
        username, type=e2i(constants.PrincipalNameType.NT_PRINCIPAL)
    )

    kdc_rep = bytes()
    cipher: Optional[type] = None
    session_key: Optional[Key] = None

    # Step 3: Authentication flow - try to get TGT then TGS
    while True:
        # Step 3.1: Get or use TGT
        if tgt is None:
            if tgs is None:
                try:
                    # Request new TGT if we don't have one
                    logging.debug(f"Getting TGT for {username!r}@{domain!r}")

                    # Check if we have a cached TGT
                    cache_key = (username, domain, lmhash, nthash, aes_key, kdc_host)

                    if cache_key in TGT_CACHE:
                        logging.debug(f"Using cached TGT for {username!r}@{domain!r}")
                        kdc_rep, cipher, session_key = TGT_CACHE[cache_key]
                    else:
                        # Request new TGT
                        kdc_rep, cipher, _, session_key = getKerberosTGT(
                            user_principal, password, domain, lmhash, nthash, aes_key, kdc_host  # type: ignore
                        )

                        # Cache the TGT for future use
                        TGT_CACHE[cache_key] = (
                            cast(bytes, kdc_rep),
                            cast(type, cipher),
                            cast(Key, session_key),
                        )

                    logging.debug(f"Got TGT for {username!r}@{domain!r}")

                except KerberosError as e:
                    # Handle encryption type incompatibility
                    if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP:
                        # Fall back to RC4 if using password auth without explicit hashes
                        if (
                            not lmhash
                            and not nthash
                            and not aes_key
                            and password
                            and not tgt
                            and not tgs
                        ):
                            from impacket.ntlm import compute_lmhash, compute_nthash

                            logging.debug(
                                "AES encryption not supported by KDC, falling back to RC4"
                            )
                            lmhash = compute_lmhash(password)
                            nthash = compute_nthash(password)
                            continue
                        else:
                            raise
                    else:
                        raise
            else:
                # If we already have a TGS, no need for TGT
                break
        else:
            # Use existing TGT
            kdc_rep = tgt["KDC_REP"]
            cipher = tgt["cipher"]
            session_key = tgt["sessionKey"]

        # Step 3.2: Get or use TGS
        if tgs is None:
            # Format the Service Principal Name (SPN)
            spn = f"{service}/{target_name}"
            server_principal = Principal(
                spn,
                type=e2i(constants.PrincipalNameType.NT_SRV_INST),
            )

            try:
                logging.debug(f"Getting TGS for {spn!r}")

                # Check if we have a cached TGS
                cache_key = (spn, domain, kdc_host, kdc_rep, cipher, session_key)

                if cache_key in TGS_CACHE:
                    logging.debug(f"Using cached TGS for {spn!r}")
                    kdc_rep, cipher, session_key = TGS_CACHE[cache_key]
                else:
                    # Request new TGS
                    kdc_rep, cipher, _, session_key = getKerberosTGS(
                        server_principal, domain, kdc_host, kdc_rep, cipher, session_key
                    )

                    # Cache the TGS for future use
                    TGS_CACHE[cache_key] = (kdc_rep, cipher, session_key)

                logging.debug(f"Got TGS for {spn!r}")
                break

            except KerberosError as e:
                # Handle encryption type incompatibility
                if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP:
                    # Fall back to RC4 if using password auth without explicit hashes
                    if (
                        not lmhash
                        and not nthash
                        and not aes_key
                        and password
                        and not tgt
                        and not tgs
                    ):
                        from impacket.ntlm import compute_lmhash, compute_nthash

                        logging.debug(
                            "AES encryption not supported by KDC, falling back to RC4"
                        )
                        lmhash = compute_lmhash(password)
                        nthash = compute_nthash(password)
                        # Start over with the new hashes
                        tgt = None
                    else:
                        raise
                else:
                    raise
        else:
            # Use existing TGS
            kdc_rep = tgs["KDC_REP"]
            cipher = tgs["cipher"]
            session_key = tgs["sessionKey"]
            break

    # Step 4: Extract client information from ticket
    ticket = decoder.decode(kdc_rep, asn1Spec=TGS_REP())[0]
    client_name = Principal()
    client_name = client_name.from_asn1(ticket, "crealm", "cname")

    # Extract the username and domain from the client name
    username = "@".join(str(client_name).split("@")[:-1])
    domain = client_name.realm or ""

    return kdc_rep, cast(type, cipher), cast(Key, session_key), username, domain


def get_kerberos_type1(
    target: Target,
    target_name: str = "",
    service: str = "HOST",
    channel_binding_data: Optional[bytes] = None,
) -> Tuple[type, Key, bytes, str]:
    """
    Generate a Kerberos Type 1 authentication message (AP_REQ).

    Creates a SPNEGO token containing Kerberos AP_REQ that can be used for HTTP
    or other protocol authentication. Supports channel binding for EPA.

    Args:
        target: Target object containing authentication details
        target_name: Name of the target server
        service: Service type (e.g., "HTTP", "HOST")
        channel_binding_data: 16-byte MD5 hash of TLS channel info for EPA

    Returns:
        Tuple containing:
        - Cipher object for encryption
        - Session key for future operations
        - SPNEGO token as bytes
        - Authenticated username
    """
    # Get TGS ticket for the service
    tgs, cipher, session_key, username, domain = get_TGS(target, target_name, service)

    # Create principal for the client
    principal = Principal(username, type=e2i(constants.PrincipalNameType.NT_PRINCIPAL))

    # Create SPNEGO token
    blob = SPNEGO_NegTokenInit()
    blob["MechTypes"] = [TypesMech["MS KRB5 - Microsoft Kerberos 5"]]

    # Extract ticket from TGS response
    tgs_rep: TGS_REP = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    _ = ticket.from_asn1(tgs_rep["ticket"])

    # Build AP_REQ message
    ap_req = AP_REQ()
    ap_req["pvno"] = 5  # Protocol version number
    ap_req["msg-type"] = e2i(constants.ApplicationTagNumbers.AP_REQ)
    ap_req["ap-options"] = constants.encodeFlags([])  # No options by default
    seq_set(ap_req, "ticket", ticket.to_asn1)

    # Create authenticator
    authenticator = Authenticator()
    authenticator["authenticator-vno"] = 5  # Version number
    authenticator["crealm"] = domain
    seq_set(authenticator, "cname", principal.components_to_asn1)

    # Add timestamp
    now = datetime.datetime.now(datetime.timezone.utc)
    authenticator["cusec"] = now.microsecond
    authenticator["ctime"] = KerberosTime.to_asn1(now)

    # Add channel binding if provided
    if channel_binding_data:
        # Set up the GSS-API checksum with channel binding data
        authenticator["cksum"] = noValue
        authenticator["cksum"]["cksumtype"] = 0x8003  # GSS API checksum type

        # Create checksum field with channel binding data
        chkField = CheckSumField()
        chkField["Lgth"] = 16  # MD5 hash is 16 bytes
        chkField["Bnd"] = channel_binding_data
        chkField["Flags"] = GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG
        authenticator["cksum"]["checksum"] = chkField.getData()

        # Add authorization data for channel binding
        authenticator["authorization-data"] = noValue
        authenticator["authorization-data"][0] = noValue
        authenticator["authorization-data"][0]["ad-type"] = AUTH_DATA_AP_OPTIONS
        authenticator["authorization-data"][0]["ad-data"] = struct.pack(
            "<I", KERB_AP_OPTIONS_CBT
        )

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


class HttpxKerberosAuth(httpx.Auth):
    """
    HTTPX authentication class for Kerberos authentication.

    This class implements the Kerberos authentication flow for HTTPX requests,
    supporting both standard Kerberos and EPA (Extended Protection for Authentication)
    with channel binding.
    """

    def __init__(
        self, target: Target, service: str = "HTTP", channel_binding: bool = True
    ):
        """
        Initialize the Kerberos authentication handler.

        Args:
            target: Target object containing connection and authentication details
            service: Service principal name prefix (default: "HTTP")
            channel_binding: Whether to use channel binding for EPA compliance
        """
        self.target = target
        self.service = service
        self.channel_binding = channel_binding

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        """
        Implement the authentication flow for HTTPX.

        This generator handles the first request and delegates to retry_with_auth
        if authentication is required.

        Args:
            request: The HTTPX request to authenticate

        Yields:
            Modified requests with appropriate authentication headers
        """
        # Set connection to keep-alive to maintain the authentication state
        request.headers["Connection"] = "Keep-Alive"

        # Send the initial request
        response = yield request

        # If server requires authentication, proceed with Kerberos auth
        if response.status_code in (401, 407):
            yield from self.retry_with_auth(request, response)

    def retry_with_auth(
        self, request: httpx.Request, response: httpx.Response
    ) -> Generator[httpx.Request, httpx.Response, None]:
        """
        Retry the request with Kerberos authentication.

        This method adds Kerberos SPNEGO authentication header to the request.

        Args:
            request: The original HTTPX request
            response: The HTTPX response requiring authentication

        Yields:
            Modified request with Kerberos authentication header

        Raises:
            ValueError: If server doesn't provide an authentication challenge
        """
        # Determine header names based on status code (proxy vs direct)
        is_proxy = response.status_code == 407
        authenticate_header_name = (
            "Proxy-Authenticate" if is_proxy else "WWW-Authenticate"
        )
        authorization_header_name = (
            "Proxy-Authorization" if is_proxy else "Authorization"
        )

        # Check if server sent authentication challenge
        authenticate_header = response.headers.get(authenticate_header_name)
        if authenticate_header is None:
            raise ValueError(
                f"No {authenticate_header_name} header found in server response"
            )

        # Get channel binding data if enabled
        channel_binding_data = None
        if self.channel_binding:
            channel_binding_data = get_channel_binding_data_from_response(response)
            if channel_binding_data:
                logging.debug("Using channel binding for Kerberos authentication")
            else:
                logging.debug("Channel binding data not available for this connection")

        # Generate Kerberos token
        _, _, spnego_blob, _ = get_kerberos_type1(
            self.target, self.target.remote_name, self.service, channel_binding_data
        )

        # Add token to request header
        auth_header = f"Negotiate {base64.b64encode(spnego_blob).decode()}"
        request.headers[authorization_header_name] = auth_header

        # Return the authenticated request
        yield request
