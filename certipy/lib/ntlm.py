import base64
import calendar
import random
import string
import struct
import time
from typing import Generator, Optional, Tuple, cast

import httpx
from Cryptodome.Cipher import ARC4
from impacket.ntlm import (
    AV_PAIRS,
    KXKEY,
    MAC,
    NTLMSSP_AV_DNS_HOSTNAME,
    NTLMSSP_AV_TARGET_NAME,
    NTLMSSP_AV_TIME,
    NTLMSSP_NEGOTIATE_56,
    NTLMSSP_NEGOTIATE_128,
    NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
    NTLMSSP_NEGOTIATE_KEY_EXCH,
    NTLMSSP_NEGOTIATE_NTLM,
    NTLMSSP_NEGOTIATE_SEAL,
    NTLMSSP_NEGOTIATE_SIGN,
    NTLMSSP_NEGOTIATE_TARGET_INFO,
    NTLMSSP_NEGOTIATE_UNICODE,
    NTLMSSP_NEGOTIATE_VERSION,
    NTLMSSP_REQUEST_TARGET,
    SEAL,
    SEALKEY,
    SIGNKEY,
    NTLMAuthChallenge,
    NTLMAuthChallengeResponse,
    NTLMAuthNegotiate,
    NTLMMessageSignature,
    NTOWFv2,
    generateEncryptedSessionKey,
    hmac_md5,
)
from impacket.spnego import SPNEGO_NegTokenResp

from certipy.lib.channel_binding import get_channel_binding_data_from_response
from certipy.lib.http import get_authentication_method
from certipy.lib.target import Target

# Constants
NTLMSSP_AV_CHANNEL_BINDINGS = 0x0A
DEFAULT_USER_AGENT = "Certipy"
DEFAULT_SERVICE = "HTTP"


def compute_response(
    server_challenge: bytes,
    client_challenge: bytes,
    target_info: bytes,
    domain: str,
    user: str,
    password: str,
    nt_hash: str = "",
    channel_binding_data: Optional[bytes] = None,
    service: str = "HOST",
) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    Compute NTLMv2 response based on the provided parameters.

    Args:
        server_challenge: Challenge received from the server
        client_challenge: Client-generated random challenge
        target_info: Target information provided by the server
        domain: Domain name for authentication
        user: Username for authentication
        password: Password for authentication
        nt_hash: NT hash if available, otherwise password will be used
        channel_binding_data: Channel binding data for EPA compliance
        service: Service name for the SPN

    Returns:
        Tuple containing:
        - NT challenge response
        - LM challenge response
        - Session base key
        - Target hostname

    Raises:
        ValueError: If target information is missing DNS hostname
    """
    # Generate response key
    response_key_nt = NTOWFv2(user, password, domain, bytes.fromhex(nt_hash) if nt_hash else "")  # type: ignore
    av_pairs = AV_PAIRS(target_info)

    # Add SPN (target name)
    if av_pairs[NTLMSSP_AV_DNS_HOSTNAME] is None:
        raise ValueError("NTLMSSP_AV_DNS_HOSTNAME not found in target info")

    hostname = cast(Tuple[int, bytes], av_pairs[NTLMSSP_AV_DNS_HOSTNAME])[1]
    spn = f"{service}/".encode("utf-16le") + hostname
    av_pairs[NTLMSSP_AV_TARGET_NAME] = spn

    # Add timestamp if not already present
    if av_pairs[NTLMSSP_AV_TIME] is None:
        timestamp = struct.pack(
            "<q", (116444736000000000 + calendar.timegm(time.gmtime()) * 10000000)
        )
        av_pairs[NTLMSSP_AV_TIME] = timestamp

    # Add channel bindings if provided
    if channel_binding_data:
        av_pairs[NTLMSSP_AV_CHANNEL_BINDINGS] = channel_binding_data

    # Construct temp data for NT proof calculation
    temp = (
        b"\x01"  # RespType
        + b"\x01"  # HiRespType
        + b"\x00" * 2  # Reserved1
        + b"\x00" * 4  # Reserved2
        + cast(Tuple[int, bytes], av_pairs[NTLMSSP_AV_TIME])[1]  # Timestamp
        + client_challenge  # ChallengeFromClient
        + b"\x00" * 4  # Reserved
        + av_pairs.getData()  # AvPairs
    )

    # Calculate response components
    nt_proof_str = hmac_md5(response_key_nt, server_challenge + temp)
    nt_challenge_response = nt_proof_str + temp
    lm_challenge_response = (
        hmac_md5(response_key_nt, server_challenge + client_challenge)
        + client_challenge
    )
    session_base_key = hmac_md5(response_key_nt, nt_proof_str)

    # Handle anonymous authentication
    if not user and not password:
        nt_challenge_response = b""
        lm_challenge_response = b""

    return nt_challenge_response, lm_challenge_response, session_base_key, hostname


def ntlm_negotiate(
    signing_required: bool = False,
    use_ntlmv2: bool = True,
    version: Optional[bytes] = None,
) -> NTLMAuthNegotiate:
    """
    Generate an NTLMSSP Type 1 negotiation message.

    Args:
        signing_required: Whether signing is required for the connection
        use_ntlmv2: Whether to use NTLMv2 (should be True for modern systems)
        version: OS version to include in the message

    Returns:
        NTLMAuthNegotiate object representing the Type 1 message
    """
    # Create base negotiate message with standard flags
    auth = NTLMAuthNegotiate()
    auth["flags"] = (
        NTLMSSP_NEGOTIATE_NTLM
        | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_REQUEST_TARGET
        | NTLMSSP_NEGOTIATE_128
        | NTLMSSP_NEGOTIATE_56
    )

    # Add security flags if signing is required
    if signing_required:
        auth["flags"] |= (
            NTLMSSP_NEGOTIATE_KEY_EXCH
            | NTLMSSP_NEGOTIATE_SIGN
            | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            | NTLMSSP_NEGOTIATE_SEAL
        )

    # Add NTLMv2 target info flag
    if use_ntlmv2:
        auth["flags"] |= NTLMSSP_NEGOTIATE_TARGET_INFO

    # Add version if specified
    if version:
        auth["flags"] |= NTLMSSP_NEGOTIATE_VERSION
        auth["os_version"] = version

    return auth


def ntlm_authenticate(
    type1: NTLMAuthNegotiate,
    challenge: NTLMAuthChallenge,
    user: str,
    password: str,
    domain: str,
    nt_hash: str = "",
    channel_binding_data: Optional[bytes] = None,
    service: str = "HOST",
    version: Optional[bytes] = None,
) -> Tuple[NTLMAuthChallengeResponse, bytes, int]:
    """
    Generate an NTLMSSP Type 3 authentication message in response to a server challenge.

    Args:
        type1: The Type 1 negotiate message that was sent
        challenge: The Type 2 challenge message received from the server
        user: Username for authentication
        password: Password for authentication
        domain: Domain name for authentication
        nt_hash: NT hash if available, otherwise password will be used
        channel_binding_data: Channel binding data for EPA compliance
        service: Service name for the SPN
        version: OS version to include in the message

    Returns:
        Tuple containing:
        - NTLMAuthChallengeResponse object (Type 3 message)
        - Exported session key for further operations
        - Negotiated flags
    """
    # Get response flags from the initial negotiate message
    response_flags = type1["flags"]

    # Generate client challenge (8 random bytes)
    client_challenge = struct.pack("<Q", random.getrandbits(64))

    # Extract target info from the challenge
    target_info = challenge["TargetInfoFields"]

    # Compute the NTLM response components
    nt_response, lm_response, session_base_key, hostname = compute_response(
        challenge["challenge"],
        client_challenge,
        target_info,
        domain,
        user,
        password,
        nt_hash,
        channel_binding_data,
        service,
    )

    # Adjust response flags based on server capabilities
    security_flags = [
        NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
        NTLMSSP_NEGOTIATE_128,
        NTLMSSP_NEGOTIATE_KEY_EXCH,
        NTLMSSP_NEGOTIATE_SEAL,
        NTLMSSP_NEGOTIATE_SIGN,
        NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
    ]

    for flag in security_flags:
        if not (challenge["flags"] & flag):
            response_flags &= ~flag

    # Calculate the key exchange key
    key_exchange_key = KXKEY(
        challenge["flags"],
        session_base_key,
        lm_response,
        challenge["challenge"],
        password,
        "",
        nt_hash,
        True,
    )

    # Handle key exchange if required
    if challenge["flags"] & NTLMSSP_NEGOTIATE_KEY_EXCH:
        # Generate random session key
        exported_session_key = "".join(
            random.choices(string.ascii_letters + string.digits, k=16)
        ).encode()
        encrypted_random_session_key = generateEncryptedSessionKey(
            key_exchange_key, exported_session_key
        )
    else:
        encrypted_random_session_key = None
        exported_session_key = key_exchange_key

    # Create and populate the challenge response
    challenge_response = NTLMAuthChallengeResponse(
        user, password, challenge["challenge"]
    )
    challenge_response["flags"] = response_flags
    challenge_response["domain_name"] = domain.encode("utf-16le")
    challenge_response["host_name"] = hostname
    challenge_response["lanman"] = lm_response if lm_response else b"\x00"
    challenge_response["ntlm"] = nt_response

    # Add version if specified
    if version:
        challenge_response["Version"] = version

    # Add session key if key exchange is enabled
    if encrypted_random_session_key:
        challenge_response["session_key"] = encrypted_random_session_key

    return challenge_response, exported_session_key, response_flags


class HttpxNtlmAuth(httpx.Auth):
    """
    HTTPX authentication class for NTLM authentication.

    This class implements the NTLM authentication protocol for HTTPX requests by
    handling the negotiation, challenge, and authentication message flow.
    """

    def __init__(
        self,
        target: Target,
        service: str = DEFAULT_SERVICE,
        channel_binding: bool = False,
    ):
        """
        Initialize the NTLM authentication handler.

        Args:
            target: Target object containing connection and authentication details
            service: Service principal name prefix to use (default: "HTTP")
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

        This generator handles the NTLM authentication protocol flow by:
        1. Sending the initial request
        2. If authentication is required, starting the NTLM flow
        3. Completing the NTLM handshake

        Args:
            request: The HTTPX request to authenticate

        Yields:
            Modified requests with appropriate authentication headers

        Raises:
            ValueError: If authentication fails or server responses are invalid
        """
        # Set connection to keep-alive to maintain the authentication state
        request.headers["Connection"] = "Keep-Alive"

        # Send the initial request
        response = yield request

        # If server requires authentication, proceed with the NTLM flow
        if response.status_code in (401, 407):
            yield from self.retry_with_auth(request, response)

    def retry_with_auth(
        self, request: httpx.Request, response: httpx.Response
    ) -> Generator[httpx.Request, httpx.Response, None]:
        """
        Retry the request with NTLM authentication.

        Implements the complete NTLM authentication flow:
        1. Send Type 1 (Negotiate) message
        2. Process Type 2 (Challenge) message from server
        3. Send Type 3 (Authenticate) message

        Args:
            request: The original HTTPX request
            response: The HTTPX response requiring authentication

        Yields:
            Modified requests with appropriate authentication headers

        Raises:
            ValueError: If authentication fails or server responses are invalid
        """
        # Determine header names based on status code (proxy vs direct)
        is_proxy_auth = response.status_code == 407
        authenticate_header_name = (
            "Proxy-Authenticate" if is_proxy_auth else "WWW-Authenticate"
        )
        authorization_header_name = (
            "Proxy-Authorization" if is_proxy_auth else "Authorization"
        )

        # Check if server sent authentication challenge
        authenticate_header = response.headers.get(authenticate_header_name)
        if authenticate_header is None:
            raise ValueError("No authentication challenge returned from server")

        # Step 1: Generate Type 1 (Negotiate) message
        type1 = ntlm_negotiate()

        # Get the authentication method (NTLM, Negotiate, etc.)
        authentication_method = get_authentication_method(authenticate_header)

        # Encode Type 1 message
        auth = base64.b64encode(type1.getData()).decode()

        # Add Type 1 message to request header
        request.headers[authorization_header_name] = f"{authentication_method} {auth}"

        # Send request with Type 1 message
        response = yield request

        # Handle cookies if present
        if response.headers.get("Set-Cookie") is not None:
            request.headers["Cookie"] = response.headers["Set-Cookie"]

        # Get Type 2 (Challenge) message from server
        authenticate_header = response.headers.get(authenticate_header_name)
        if authenticate_header is None:
            raise ValueError("No authentication challenge returned from server")

        # Extract the server challenge from the authentication header
        try:
            # Find the challenge portion of the header
            server_challenge_base64 = next(
                s.strip()[len(authentication_method) :]
                for s in (val.lstrip() for val in authenticate_header.split(","))
                if s.startswith(authentication_method)
            ).strip()
        except Exception:
            raise ValueError(
                f"Failed to parse authentication header: {authenticate_header}"
            )

        # Decode the challenge
        try:
            server_challenge = base64.b64decode(server_challenge_base64)
        except Exception as e:
            raise ValueError(
                f"Failed to decode server challenge: {authenticate_header} - {e}"
            )

        # Check if challenge is wrapped in SPNEGO
        if (
            server_challenge
            and struct.unpack("B", server_challenge[:1])[0]
            == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP
        ):
            resp = SPNEGO_NegTokenResp(server_challenge)
            type2 = resp["ResponseToken"]
        else:
            type2 = server_challenge

        # Parse Type 2 message
        challenge = NTLMAuthChallenge()
        try:
            challenge.fromString(type2)
        except Exception as e:
            raise ValueError(
                f"Failed to parse server challenge: {authenticate_header} - {e}"
            )

        # Get channel binding data if enabled
        channel_binding_data: Optional[bytes] = None
        if self.channel_binding:
            channel_binding_data = get_channel_binding_data_from_response(response)

        # Step 3: Generate Type 3 (Authentication) message
        type3, _, _ = ntlm_authenticate(
            type1,
            challenge,
            self.target.username,
            self.target.password or "",
            self.target.domain,
            self.target.nthash,
            channel_binding_data=channel_binding_data,
            service=self.service,
        )

        # Encode and add Type 3 message to request
        auth = base64.b64encode(type3.getData()).decode()
        request.headers[authorization_header_name] = f"{authentication_method} {auth}"

        # Send authenticated request
        yield request


class NTLMCipher:
    def __init__(self, flags: int, session_key: bytes):
        self.flags = flags

        # Same key for everything
        self.client_sign_key = session_key
        self.server_sign_key = session_key
        self.client_seal_key = session_key
        self.client_seal_key = session_key
        cipher = ARC4.new(self.client_sign_key)
        self.client_seal = cipher.encrypt
        self.server_seal = cipher.encrypt

        if self.flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
            self.client_sign_key = cast(bytes, SIGNKEY(self.flags, session_key))
            self.server_sign_key = cast(
                bytes, SIGNKEY(self.flags, session_key, "Server")
            )
            self.client_seal_key = SEALKEY(self.flags, session_key)
            self.server_seal_key = SEALKEY(self.flags, session_key, "Server")

            client_cipher = ARC4.new(self.client_seal_key)
            self.client_seal = client_cipher.encrypt
            server_cipher = ARC4.new(self.server_seal_key)
            self.server_seal = server_cipher.encrypt

        self.sequence = 0

    def encrypt(self, plain_data: bytes) -> Tuple[NTLMMessageSignature, bytes]:
        message, signature = SEAL(
            self.flags,
            self.client_sign_key,
            self.client_seal_key,
            plain_data,
            plain_data,
            self.sequence,
            self.client_seal,
        )

        self.sequence += 1

        return signature, message

    def decrypt(self, answer: bytes) -> Tuple[NTLMMessageSignature, bytes]:
        answer, signature = SEAL(
            self.flags,
            self.server_sign_key,
            self.server_seal_key,
            answer[:16],
            answer[16:],
            self.sequence,
            self.server_seal,
        )

        return signature, answer

    def sign(self, data: bytes, seq: int = 0, reset_cipher: bool = False):
        signature = MAC(self.flags, self.client_seal, self.client_sign_key, seq, data)
        if reset_cipher:
            if self.flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                client_cipher = ARC4.new(self.client_seal_key)
                self.client_seal = client_cipher.encrypt
                server_cipher = ARC4.new(self.server_seal_key)
                self.server_seal = server_cipher.encrypt
            else:
                cipher = ARC4.new(self.client_sign_key)
                self.client_seal = cipher.encrypt
                self.server_seal = cipher.encrypt
        self.sequence += 1
        return signature
