"""
Kerberos authentication module for Certipy.

This module provides functionality for Kerberos-based authentication and ticket management,
supporting both credential-based and ticket-based operations against Windows services.

Key features:
- TGT (Ticket Granting Ticket) acquisition and caching
- TGS (Ticket Granting Service) ticket acquisition and caching
- Kerberos authentication for HTTP requests
- Support for channel binding with EPA (Extended Protection for Authentication)
- Encryption and decryption using various Kerberos ciphers
"""

import base64
import datetime
import os
import random
import string
import struct
from typing import Any, Dict, Generator, Optional, Tuple, cast

import httpx
from Cryptodome.Cipher import ARC4
from Cryptodome.Hash import HMAC, MD5
from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ, TGS_REP, Authenticator, seq_set
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key
from impacket.krb5.gssapi import (
    GSS_C_CONF_FLAG,
    GSS_C_INTEG_FLAG,
    GSS_C_REPLAY_FLAG,
    GSS_C_SEQUENCE_FLAG,
    GSS_HMAC,
    GSS_RC4,
)
from impacket.krb5.gssapi import GSSAPI as create_kerberos_cipher  # noqa: N811
from impacket.krb5.gssapi import (
    GSSAPI_RC4,
    KG_USAGE_ACCEPTOR_SEAL,
    KG_USAGE_INITIATOR_SEAL,
    CheckSumField,
)
from impacket.krb5.kerberosv5 import KerberosError, getKerberosTGS, getKerberosTGT
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from pyasn1.codec.ber import decoder, encoder
from pyasn1.type.univ import noValue

from certipy.lib.channel_binding import get_channel_binding_data_from_response
from certipy.lib.logger import logging
from certipy.lib.structs import e2i
from certipy.lib.target import Target

# Try to use a secure random number generator, fallback to standard if not available
try:
    rand = random.SystemRandom()
except NotImplementedError:
    logging.warning(
        "System RNG not available, falling back to less secure random generator"
    )
    rand = random

# Constants
KERB_AP_OPTIONS_CBT = 0x4000  # Channel Binding token flag
KRB_CLOCK_SKEW = 300  # 5 minutes in seconds
AUTH_DATA_AP_OPTIONS = 143  # AD-AUTH-DATA-AP-OPTIONS type
KRB_OID = b"\x06\t*\x86H\x86\xf7\x12\x01\x02\x02"  # Kerberos OID: 1.2.840.113554.1.2.2

# Cache for TGT and TGS tickets to avoid redundant authentication
# Keys: (username, domain, lmhash, nthash, aeskey, kdc_host)
TGT_CACHE: Dict[
    Tuple[str, str, bytes, bytes, bytes, Optional[str]], Tuple[bytes, type, Key]
] = {}

# Keys: (spn, domain, kdc_host, kdc_rep, cipher, session_key)
TGS_CACHE: Dict[
    Tuple[str, str, Optional[str], Any, Optional[type], Any], Tuple[bytes, type, Key]
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


class MechIndepToken:
    """
    Mechanism Independent Token implementation for Kerberos authentication.

    This class handles the encoding and decoding of GSS-API tokens with
    embedded mechanism identifiers (OIDs) for Kerberos.
    """

    def __init__(self, data: bytes, oid: bytes):
        """
        Initialize a mechanism independent token.

        Args:
            data: Token data
            oid: Object identifier for the authentication mechanism
        """
        self.data = data
        self.token_oid = oid

    @staticmethod
    def from_bytes(data: bytes) -> "MechIndepToken":
        """
        Parse a mechanism independent token from its binary representation.

        Args:
            data: Binary data to parse

        Returns:
            Parsed MechIndepToken object

        Raises:
            Exception: If the data format is invalid
        """
        if data[0:1] != b"\x60":
            raise Exception("Incorrect token data format (expected 0x60)")

        data = data[1:]
        length, data = MechIndepToken._get_length(data)
        token_data = data[0:length]

        if token_data[0:1] != b"\x06":
            raise Exception("Incorrect OID tag in token data")

        oid_length, _ = MechIndepToken._get_length(token_data[1:])
        token_oid = token_data[0 : oid_length + 2]
        data = token_data[oid_length + 2 :]
        return MechIndepToken(data, token_oid)

    @staticmethod
    def _get_length(data: bytes) -> Tuple[int, bytes]:
        """
        Extract ASN.1 length from the given data.

        Args:
            data: Binary data containing ASN.1 length

        Returns:
            Tuple of (length, remaining_data)
        """
        if data[0] < 128:
            # Short form - length is in the first byte
            return data[0], data[1:]
        else:
            # Long form - first byte (minus 128) indicates number of length bytes
            bytes_count = data[0] - 128
            length = int.from_bytes(
                data[1 : 1 + bytes_count], byteorder="big", signed=False
            )
            return length, data[1 + bytes_count :]

    @staticmethod
    def _encode_length(length: int) -> bytes:
        """
        Encode a length value in ASN.1 format.

        Args:
            length: Length value to encode

        Returns:
            ASN.1 encoded length bytes
        """
        if length < 128:
            # Short form - single byte
            return length.to_bytes(1, byteorder="big", signed=False)
        else:
            # Long form - multiple bytes
            length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
            return (128 + len(length_bytes)).to_bytes(
                1, byteorder="big", signed=False
            ) + length_bytes

    def to_bytes(self) -> Tuple[bytes, bytes]:
        """
        Convert the token to its binary representation.

        Returns:
            Tuple of (header_bytes, data_bytes)
        """
        complete_token = self.token_oid + self.data

        # Create the ASN.1 structure
        token_bytes = (
            b"\x60" + self._encode_length(len(complete_token)) + complete_token
        )

        # Return the header and data portions separately
        header_end = len(token_bytes) - len(self.data)
        return token_bytes[:header_end], self.data


class KerberosCipher:
    """
    Implements encryption and decryption for Kerberos GSS-API messages.

    This class supports both RC4 and AES ciphers for securing GSSAPI
    communications in Kerberos authentication.
    """

    def __init__(self, cipher: type, session_key: Key):
        """
        Initialize the KerberosCipher object.

        Args:
            cipher: Cipher class for encryption/decryption
            session_key: Session key for encryption/decryption
        """
        self.cipher = create_kerberos_cipher(cipher)
        self.session_key = session_key

    def encrypt(self, data: bytes, sequence_number: int) -> Tuple[bytes, bytes]:
        """
        Encrypt data using the appropriate Kerberos cipher.

        Automatically selects between RC4 and AES encryption based on the
        cipher type.

        Args:
            data: Plaintext data to encrypt
            sequence_number: Message sequence number for integrity

        Returns:
            Tuple of (cipher_text, signature)
        """
        if isinstance(self.cipher, GSSAPI_RC4):
            return self._encrypt_rc4(data, sequence_number)
        else:
            return self._encrypt_aes(data, sequence_number)

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt data using the appropriate Kerberos cipher.

        Automatically selects between RC4 and AES decryption based on the
        cipher type.

        Args:
            data: Encrypted data to decrypt

        Returns:
            Decrypted plaintext
        """
        if isinstance(self.cipher, GSSAPI_RC4):
            return self._decrypt_rc4(data)
        else:
            return self._decrypt_aes(data)

    def _encrypt_aes(self, data: bytes, sequence_number: int) -> Tuple[bytes, bytes]:
        """
        Encrypt data using AES cipher.

        Args:
            data: Plaintext data to encrypt
            sequence_number: Message sequence number for integrity

        Returns:
            Tuple of (cipher_text, signature)

        Raises:
            ValueError: If RC4 cipher is provided for AES encryption
        """
        if isinstance(self.cipher, GSSAPI_RC4):
            raise ValueError("RC4 cipher cannot be used for AES encryption")

        # Create token structure
        token = self.cipher.WRAP()
        cipher = self.cipher.cipherType

        # Set RRC (Required Role Check) for in-place encryption
        rrc = 28

        # Set token flags
        token["Flags"] = 6  # Privacy and Integrity
        token["EC"] = 0  # Extra Count
        token["RRC"] = 0  # Initially zero
        token["SND_SEQ"] = struct.pack(">Q", sequence_number)  # Sequence number

        # Encrypt the data with the token
        cipher_text = cipher.encrypt(
            self.session_key, KG_USAGE_INITIATOR_SEAL, data + token.getData(), None
        )

        # Update RRC in token
        token["RRC"] = rrc

        # Apply rotation based on RRC and EC
        cipher_text = self.cipher.rotate(cipher_text, token["RRC"] + token["EC"])

        return cipher_text, token.getData()

    def _decrypt_aes(self, data: bytes) -> bytes:
        """
        Decrypt data using AES cipher.

        Args:
            data: Encrypted data to decrypt

        Returns:
            Decrypted plaintext

        Raises:
            ValueError: If RC4 cipher is provided for AES decryption
        """
        if isinstance(self.cipher, GSSAPI_RC4):
            raise ValueError("RC4 cipher cannot be used for AES decryption")

        # Extract token and cipher text
        token = self.cipher.WRAP(data[:16])
        rotated_data = data[16:]

        # Create cipher instance
        cipher = self.cipher.cipherType()

        # Unrotate the cipher text
        cipher_text = self.cipher.unrotate(rotated_data, token["RRC"] + token["EC"])

        # Decrypt the data
        plain_text = cipher.decrypt(
            self.session_key, KG_USAGE_ACCEPTOR_SEAL, cipher_text
        )

        # Remove token data from the end
        return plain_text[: -(token["EC"] + 16)]

    def _encrypt_rc4(self, data: bytes, sequence_number: int) -> Tuple[bytes, bytes]:
        """
        Encrypt data using RC4 cipher.

        Args:
            data: Plaintext data to encrypt
            sequence_number: Message sequence number for integrity

        Returns:
            Tuple of (cipher_text, signature)

        Raises:
            ValueError: If AES cipher is provided for RC4 encryption
        """
        if not isinstance(self.cipher, GSSAPI_RC4):
            raise ValueError("AES cipher cannot be used for RC4 encryption")

        # Add encryption flag byte
        data_with_flag = data + b"\x01"

        # Create token structure
        token = self.cipher.WRAP()
        token["SGN_ALG"] = GSS_HMAC
        token["SEAL_ALG"] = GSS_RC4

        # Set sequence number
        token["SND_SEQ"] = struct.pack(">L", sequence_number) + b"\x00" * 4

        # Generate random confounding bytes
        token["Confounder"] = "".join(
            [rand.choice(string.ascii_letters) for _ in range(8)]
        ).encode()

        # Generate signing key
        k_sign = HMAC.new(self.session_key.contents, b"signaturekey\0", MD5).digest()

        # Generate checksum
        sgn_cksum = MD5.new(
            struct.pack("<L", 13)
            + token.getData()[:8]
            + token["Confounder"]
            + data_with_flag
        ).digest()

        sgn_cksum = HMAC.new(k_sign, sgn_cksum, MD5).digest()
        token["SGN_CKSUM"] = sgn_cksum[:8]

        # Generate key material
        k_local = bytearray()
        for n in bytes(self.session_key.contents):
            k_local.append(n ^ 0xF0)

        # Generate encryption key
        k_crypt = HMAC.new(k_local, struct.pack("<L", 0), MD5).digest()
        k_crypt = HMAC.new(k_crypt, struct.pack(">L", sequence_number), MD5).digest()

        # Generate sequence key
        k_seq = HMAC.new(self.session_key.contents, struct.pack("<L", 0), MD5).digest()
        k_seq = HMAC.new(k_seq, token["SGN_CKSUM"], MD5).digest()

        # Encrypt sequence number
        token["SND_SEQ"] = ARC4.new(k_seq).encrypt(token["SND_SEQ"])

        # Encrypt confounder and data
        rc4 = ARC4.new(k_crypt)
        token["Confounder"] = rc4.encrypt(token["Confounder"])
        encrypted_data = rc4.encrypt(data_with_flag)

        # Wrap in mechanism independent token
        token_data = token.getData() + encrypted_data

        final_header, final_data = MechIndepToken(token_data, KRB_OID).to_bytes()

        return final_data, final_header

    def _decrypt_rc4(self, data: bytes) -> bytes:
        """
        Decrypt data using RC4 cipher.

        Args:
            data: Encrypted data to decrypt

        Returns:
            Decrypted plaintext

        Raises:
            ValueError: If AES cipher is provided for RC4 decryption
            Exception: If data format is invalid
        """
        if not isinstance(self.cipher, GSSAPI_RC4):
            raise ValueError("AES cipher cannot be used for RC4 decryption")

        try:
            # Parse mechanism independent token
            token = MechIndepToken.from_bytes(data)

            # Extract WRAP token from first 32 bytes
            wrap = self.cipher.WRAP(token.data[:32])
            encrypted_data = token.data[32:]

            # Generate sequence key
            k_seq = HMAC.new(
                self.session_key.contents, struct.pack("<L", 0), MD5
            ).digest()
            k_seq = HMAC.new(k_seq, wrap["SGN_CKSUM"], MD5).digest()

            # Decrypt sequence number
            snd_seq = ARC4.new(k_seq).decrypt(wrap["SND_SEQ"])

            # Generate encryption key
            k_local = bytearray()
            for n in bytes(self.session_key.contents):
                k_local.append(n ^ 0xF0)

            k_crypt = HMAC.new(k_local, struct.pack("<L", 0), MD5).digest()
            k_crypt = HMAC.new(k_crypt, snd_seq[:4], MD5).digest()

            # Decrypt data
            rc4 = ARC4.new(k_crypt)
            plaintext_with_confounder = rc4.decrypt(wrap["Confounder"] + encrypted_data)

            # Skip 8-byte confounder and remove trailing flag byte
            return plaintext_with_confounder[8:-1]

        except Exception as e:
            logging.error(f"Error during RC4 decryption: {e}")
            raise Exception(f"Failed to decrypt RC4 data: {e}")


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


def get_kerberos_type1(
    target: Target,
    target_name: str = "",
    service: str = "HOST",
    channel_binding_data: Optional[bytes] = None,
    signing: bool = False,
) -> Tuple[type, Key, bytes, str]:
    """
    Generate a Kerberos Type 1 authentication message (AP_REQ).

    Creates a SPNEGO token containing Kerberos AP_REQ that can be used for HTTP
    or other protocol authentication. Supports channel binding for EPA.

    Args:
        target: Target object containing authentication details
        target_name: Name of the target server
        service: Service type (e.g., "HTTP", "HOST")
        channel_binding_data: Optional channel binding token data for EPA
        signing: Whether to enable signing and encryption flags

    Returns:
        Tuple containing:
        - Cipher object for encryption
        - Session key for future operations
        - SPNEGO token as bytes
        - Authenticated username
    """
    # Get TGS ticket for the service
    tgs, cipher, session_key, username, domain = get_tgs(target, target_name, service)

    # Create principal for the client
    principal = Principal(username, type=e2i(constants.PrincipalNameType.NT_PRINCIPAL))

    # Create SPNEGO token
    blob = SPNEGO_NegTokenInit()
    blob["MechTypes"] = [TypesMech["MS KRB5 - Microsoft Kerberos 5"]]

    # Extract ticket from TGS response
    tgs_rep = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
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

    # Set up the GSS-API checksum
    authenticator["cksum"] = noValue
    authenticator["cksum"]["cksumtype"] = 0x8003  # GSS API checksum type

    checksum = CheckSumField()
    checksum["Lgth"] = 16

    # Set flags for message protection
    flags = GSS_C_SEQUENCE_FLAG | GSS_C_REPLAY_FLAG
    if signing:
        flags |= GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG

    checksum["Flags"] = flags

    # Add channel binding data if provided
    if channel_binding_data:
        checksum["Bnd"] = channel_binding_data

    authenticator["cksum"]["checksum"] = checksum.getData()

    # Add authorization data for channel binding
    if channel_binding_data:
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


def get_tgs(
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
    ccache = None

    krb5ccname = os.getenv("KRB5CCNAME")
    if krb5ccname:
        try:
            ccache = CCache.loadFile(krb5ccname)
            logging.debug(f"Loaded Kerberos cache from {krb5ccname}")
        except Exception as e:
            logging.debug(f"Failed to load Kerberos cache: {e}")

    if ccache:
        # Validate cache and extract information
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
    rc4_fallback_attempted = False

    # Step 3: Authentication flow - try to get TGT then TGS
    while True:
        try:
            # Step 3.1: Get or use TGT
            if tgt is None:
                if tgs is None:
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
            else:
                # Use existing TGS
                kdc_rep = tgs["KDC_REP"]
                cipher = tgs["cipher"]
                session_key = tgs["sessionKey"]
                break

        except KerberosError as e:
            # Handle encryption type incompatibility
            if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP:
                # Fall back to RC4 if using password auth without explicit hashes
                if (
                    not rc4_fallback_attempted
                    and not lmhash
                    and not nthash
                    and not aes_key
                    and password
                    and not tgt
                    and not tgs
                ):
                    from impacket.ntlm import compute_lmhash, compute_nthash

                    logging.warning(
                        "AES encryption not supported by KDC, falling back to RC4"
                    )
                    lmhash = compute_lmhash(password)
                    nthash = compute_nthash(password)
                    rc4_fallback_attempted = True
                    # Clear cache entries that might have used AES
                    tgt = None
                    continue
                else:
                    logging.error(
                        f"KDC doesn't support the requested encryption type: {e}"
                    )
                    raise
            else:
                logging.error(f"Kerberos error: {e} (Error code: {e.getErrorCode()})")
                raise
        except Exception as e:
            # Handle other exceptions with more detailed error messages
            logging.error(f"Error during Kerberos authentication: {e}")
            raise

    # Step 4: Extract client information from ticket
    ticket = decoder.decode(kdc_rep, asn1Spec=TGS_REP())[0]
    client_name = Principal()
    client_name = client_name.from_asn1(ticket, "crealm", "cname")

    # Extract the username and domain from the client name
    username = "@".join(str(client_name).split("@")[:-1])
    domain = client_name.realm or ""

    return kdc_rep, cast(type, cipher), cast(Key, session_key), username, domain
