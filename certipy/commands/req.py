"""
Certificate request module for Certipy.

This module provides functionality for:
- Requesting certificates from Active Directory Certificate Services (AD CS)
- Retrieving pending or issued certificates
- Supporting various request methods (RPC, DCOM, Web Enrollment)
- Handling certificate templates and custom attributes
- Supporting certificate renewal, key archival, and on-behalf-of requests

Key components:
- Request: Main class for certificate operations
- RequestInterface: Abstract base class for different request protocols
- RPCRequestInterface: Certificate requests via MS-ICPR
- DCOMRequestInterface: Certificate requests via DCOM
- WebRequestInterface: Certificate requests via Web Enrollment
"""

import argparse
import re
from typing import Any, Dict, List, Optional, Protocol, Tuple, Union

import httpx
from httpx_ntlm import HttpNtlmAuth
from impacket.dcerpc.v5 import rpcrt
from impacket.dcerpc.v5.dcom.oaut import string_to_bin
from impacket.dcerpc.v5.dcomrt import DCOMANSWER, DCOMCALL, DCOMConnection
from impacket.dcerpc.v5.dtypes import DWORD, LPWSTR, NULL, PBYTE, ULONG
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.nrpc import checkNullString
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.uuid import uuidtup_to_bin

from certipy.commands.ca import CA, ICertCustom
from certipy.lib.certificate import (
    cert_id_to_parts,
    cert_to_der,
    cert_to_pem,
    create_csr,
    create_key_archival,
    create_on_behalf_of,
    create_pfx,
    create_renewal,
    csr_to_der,
    der_to_cert,
    der_to_csr,
    der_to_pem,
    get_identifications_from_certificate,
    get_object_sid_from_certificate,
    key_to_pem,
    load_pfx,
    pem_to_cert,
    pem_to_key,
    rsa,
    x509,
)
from certipy.lib.constants import OID_TO_STR_MAP, USER_AGENT
from certipy.lib.errors import translate_error_code
from certipy.lib.formatting import print_certificate_identifications
from certipy.lib.kerberos import HttpxImpacketKerberosAuth
from certipy.lib.logger import logging
from certipy.lib.rpc import get_dce_rpc, get_dcom_connection
from certipy.lib.target import Target

# =========================================================================
# Constants and protocol UUIDs
# =========================================================================

# MS-ICPR protocol UUID
MSRPC_UUID_ICPR = uuidtup_to_bin(("91ae6020-9e3c-11cf-8d7c-00aa00c091be", "0.0"))

# DCOM interface identifiers
CLSID_ICertRequest = string_to_bin("D99E6E74-FC88-11D0-B498-00A0C90312F3")
IID_ICertRequestD = uuidtup_to_bin(("D99E6E70-FC88-11D0-B498-00A0C90312F3", "0.0"))

# Certificate disposition codes
DISPOSITION_SUCCESS = 3
DISPOSITION_PENDING = 5

# =========================================================================
# Protocol Structures for MS-WCCE and MS-ICPR
# =========================================================================


class CERTTRANSBLOB(NDRSTRUCT):
    """
    ASN.1 structure for certificate data transfer.

    Defined in [MS-WCCE] section 2.2.2.2
    """

    structure = (
        ("cb", ULONG),  # Size of the pb field
        ("pb", PBYTE),  # Certificate data
    )


class CertServerRequest(NDRCALL):
    """
    RPC interface for certificate requests.

    Defined in [MS-ICPR] section 3.1.4.1
    """

    opnum = 0
    structure = (
        ("dwFlags", DWORD),  # Request flags
        ("pwszAuthority", LPWSTR),  # CA name
        ("pdwRequestId", DWORD),  # Request ID
        ("pctbAttribs", CERTTRANSBLOB),  # Request attributes
        ("pctbRequest", CERTTRANSBLOB),  # Certificate request data
    )


class CertServerRequestD(DCOMCALL):
    """
    DCOM interface for certificate requests.

    Defined in [MS-WCCE] section 3.1.1.4.3
    """

    opnum = 3
    structure = (
        ("dwFlags", DWORD),  # Request flags
        ("pwszAuthority", LPWSTR),  # CA name
        ("pdwRequestId", DWORD),  # Request ID
        ("pwszAttributes", LPWSTR),  # Request attributes
        ("pctbRequest", CERTTRANSBLOB),  # Certificate request data
    )


class CertServerRequestResponse(NDRCALL):
    """
    RPC response structure for certificate requests.

    Defined in [MS-ICPR] section 3.1.4.1
    """

    structure = (
        ("pdwRequestId", DWORD),  # Request ID
        ("pdwDisposition", ULONG),  # Request status
        ("pctbCert", CERTTRANSBLOB),  # Certificate data
        ("pctbEncodedCert", CERTTRANSBLOB),  # DER-encoded certificate
        ("pctbDispositionMessage", CERTTRANSBLOB),  # Error message if applicable
    )


class CertServerRequestDResponse(DCOMANSWER):
    """
    DCOM response structure for certificate requests.

    Defined in [MS-WCCE] section 3.1.1.4.3
    """

    structure = (
        ("pdwRequestId", DWORD),  # Request ID
        ("pdwDisposition", ULONG),  # Request status
        ("pctbCertChain", CERTTRANSBLOB),  # Certificate chain data
        ("pctbEncodedCert", CERTTRANSBLOB),  # DER-encoded certificate
        ("pctbDispositionMessage", CERTTRANSBLOB),  # Error message if applicable
    )


class ICertRequestD(ICertCustom):
    """
    ICertRequestD DCOM interface implementation.
    """

    def __init__(self, interface):
        super().__init__(interface)
        self._iid = IID_ICertRequestD


class DCERPCSessionError(rpcrt.DCERPCException):
    """
    Custom exception for handling certificate request errors.
    """

    def __init__(self, error_string=None, error_code=None, packet=None):
        rpcrt.DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self) -> str:
        """Format the error message with translated error code."""
        self.error_code &= 0xFFFFFFFF  # type: ignore
        error_msg = translate_error_code(self.error_code)
        return f"RequestSessionError: {error_msg}"


# =========================================================================
# Request Interface Protocol
# =========================================================================


class RequestInterface(Protocol):
    """
    Protocol defining the interface for certificate request operations.

    This is the base class for different request methods (RPC, DCOM, Web).
    """

    parent: "Request"

    def __init__(self, parent: "Request"):
        """
        Initialize the request interface.

        Args:
            parent: The parent Request object
        """
        self.parent = parent

    def retrieve(self, request_id: int) -> Union[x509.Certificate, None]:
        """
        Retrieve a certificate by request ID.

        Args:
            request_id: The request ID to retrieve

        Returns:
            Certificate object if successful, None on failure
        """
        ...

    def request(
        self, csr: bytes, attributes_list: List[str]
    ) -> Union[x509.Certificate, None]:
        """
        Submit a certificate request.

        Args:
            csr: Certificate signing request data
            attributes_list: List of certificate attributes

        Returns:
            Certificate object if successful, None on failure
        """
        ...


# =========================================================================
# Request Interface Implementations
# =========================================================================


class DCOMRequestInterface:
    """
    Request interface for DCOM communication with Certificate Services.
    """

    def __init__(self, parent: "Request"):
        """
        Initialize the DCOM request interface.

        Args:
            parent: The parent Request object
        """
        self.parent = parent
        self._dcom: Optional[DCOMConnection] = None

    @property
    def dcom(self) -> DCOMConnection:
        """
        Get or establish a DCOM connection to the certificate authority.

        Returns:
            Active DCOM connection

        Raises:
            Exception: If target is not set or connection fails
        """
        if self._dcom is not None:
            return self._dcom

        if self.parent.target is None:
            raise Exception("Target is not set")

        self._dcom = get_dcom_connection(self.parent.target)
        return self._dcom

    def retrieve(self, request_id: int) -> Optional[x509.Certificate]:
        """
        Retrieve a certificate by request ID via DCOM.

        Args:
            request_id: The request ID to retrieve

        Returns:
            Certificate object if successful, None on failure
        """
        # Prepare empty blob for request
        empty = CERTTRANSBLOB()
        empty["cb"] = 0
        empty["pb"] = NULL

        # Build the request structure
        request = CertServerRequestD()
        request["dwFlags"] = 0
        request["pwszAuthority"] = checkNullString(self.parent.ca)
        request["pdwRequestId"] = request_id
        request["pwszAttributes"] = empty
        request["pctbRequest"] = empty

        logging.info(f"Retrieving certificate with ID {request_id}")

        # Create and configure the DCOM interface
        i_cert_req = self.dcom.CoCreateInstanceEx(CLSID_ICertRequest, IID_ICertRequestD)
        i_cert_req.get_cinstance().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)  # type: ignore

        # Submit the request
        cert_req_d = ICertRequestD(i_cert_req)
        response = cert_req_d.request(request)

        # Process the response
        error_code = response["pdwDisposition"]

        if error_code == DISPOSITION_SUCCESS:
            logging.info("Successfully retrieved certificate")
            # Convert the returned certificate data
            cert = der_to_cert(b"".join(response["pctbEncodedCert"]["pb"]))
            return cert

        elif error_code == DISPOSITION_PENDING:
            logging.warning("Certificate request is still pending approval")
        else:
            # Handle error case
            error_msg = translate_error_code(error_code)
            if "unknown error code" in error_msg:
                logging.error(
                    f"Got unknown error while trying to retrieve certificate: ({error_msg}): "
                    f"{b''.join(response['pctbDispositionMessage']['pb']).decode('utf-16le')}"
                )
            else:
                logging.error(
                    f"Got error while trying to retrieve certificate: {error_msg}"
                )

        return None

    def request(
        self, csr: bytes, attributes_list: List[str]
    ) -> Optional[x509.Certificate]:
        """
        Submit a certificate request via DCOM.

        Args:
            csr: Certificate signing request data
            attributes_list: List of certificate attributes

        Returns:
            Certificate object if successful, None on failure
        """
        # Format attributes
        attributes = checkNullString("\n".join(attributes_list))

        # Prepare the certificate request data
        pctb_request = CERTTRANSBLOB()
        pctb_request["cb"] = len(csr)
        pctb_request["pb"] = csr

        # Build the request structure
        request = CertServerRequestD()
        request["dwFlags"] = 0
        request["pwszAuthority"] = checkNullString(self.parent.ca)
        request["pdwRequestId"] = self.parent.request_id or 0
        request["pwszAttributes"] = attributes
        request["pctbRequest"] = pctb_request

        logging.info("Requesting certificate via DCOM")

        # Create and configure the DCOM interface
        i_cert_req = self.dcom.CoCreateInstanceEx(CLSID_ICertRequest, IID_ICertRequestD)
        i_cert_req.get_cinstance().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)  # type: ignore

        # Submit the request
        cert_req_d = ICertRequestD(i_cert_req)
        response = cert_req_d.request(request)

        # Process the response
        error_code = response["pdwDisposition"]
        request_id = response["pdwRequestId"]

        if error_code == DISPOSITION_SUCCESS:
            logging.info("Successfully requested certificate")
            cert = der_to_cert(b"".join(response["pctbEncodedCert"]["pb"]))
            logging.info(f"Request ID is {request_id}")
            return cert

        # Handle non-successful responses
        if error_code == DISPOSITION_PENDING:
            logging.warning("Certificate request is pending approval")
        else:
            error_msg = translate_error_code(error_code)
            if "unknown error code" in error_msg:
                logging.error(
                    f"Got unknown error while trying to request certificate: ({error_msg}): "
                    f"{b''.join(response['pctbDispositionMessage']['pb']).decode('utf-16le')}"
                )
            else:
                logging.error(
                    f"Got error while trying to request certificate: {error_msg}"
                )

        logging.info(f"Request ID is {request_id}")

        # Ask if the user wants to save the private key for pending requests
        self._handle_pending_key_save(request_id)

        return None

    def _handle_pending_key_save(self, request_id: int) -> None:
        """
        Handle saving the private key for pending requests.

        Args:
            request_id: The certificate request ID
        """
        should_save = input("Would you like to save the private key? (y/N) ").rstrip(
            "\n"
        )

        if should_save.lower() == "y":
            out = self.parent.out if self.parent.out is not None else str(request_id)

            try:
                with open(f"{out}.key", "wb") as f:
                    if self.parent.key is None:
                        logging.error("No private key found")
                        return

                    _ = f.write(key_to_pem(self.parent.key))

                logging.info(f"Saved private key to {out}.key")
            except Exception as e:
                logging.error(f"Failed to save private key: {str(e)}")


class RPCRequestInterface:
    """
    Request interface for RPC communication with Certificate Services.
    """

    def __init__(self, parent: "Request"):
        """
        Initialize the RPC request interface.

        Args:
            parent: The parent Request object
        """
        self.parent = parent
        self._dce = None

    @property
    def dce(self) -> Optional[rpcrt.DCERPC_v5]:
        """
        Get or establish an RPC connection to the certificate authority.

        Returns:
            Active RPC connection

        Raises:
            Exception: If target is not set or connection fails
        """
        if self._dce is not None:
            return self._dce

        if not MSRPC_UUID_ICPR:
            # Should never happen
            raise Exception("Failed to get MSRPC UUID for ICertRequest")

        if self.parent.target is None:
            raise Exception("Target is not set")

        self._dce = get_dce_rpc(
            MSRPC_UUID_ICPR,
            "\\pipe\\cert",
            self.parent.target,
            timeout=self.parent.target.timeout,
            dynamic=self.parent.dynamic,
            verbose=self.parent.verbose,
        )

        return self._dce

    def dce_request(self, request: NDRCALL) -> Dict[str, Any]:
        """
        Send a DCE RPC request and handle the response.

        This wrapper method properly handles the DCE RPC request to ensure static
        code analysis tools correctly understand the return value. The underlying
        impacket.dcerpc.v5.rpcrt.DCERPC_v5.request method has type annotation
        issues that cause some analyzers to think it never returns.

        Args:
            request: The RPC request structure to send

        Returns:
            Dict containing the parsed response

        Raises:
            Exception: If the DCE RPC connection isn't established or request fails
        """
        if self.dce is None:
            raise Exception("Failed to get DCE RPC connection")

        # Call the underlying request method with error checking disabled
        # We manually handle errors to provide better error messages
        return self.dce.request(request, checkError=False)

    def retrieve(self, request_id: int) -> Optional[x509.Certificate]:
        """
        Retrieve a certificate by request ID via RPC.

        Args:
            request_id: The request ID to retrieve

        Returns:
            Certificate object if successful, False on failure
        """
        # Prepare empty blob for request
        empty = CERTTRANSBLOB()
        empty["cb"] = 0
        empty["pb"] = NULL

        # Build the request structure
        request = CertServerRequest()
        request["dwFlags"] = 0
        request["pwszAuthority"] = checkNullString(self.parent.ca)
        request["pdwRequestId"] = request_id
        request["pctbAttribs"] = empty
        request["pctbRequest"] = empty

        logging.info(f"Retrieving certificate with ID {request_id}")

        # Submit the request
        response = self.dce_request(request)

        # Process the response
        error_code = response["pdwDisposition"]

        if error_code == DISPOSITION_SUCCESS:
            logging.info("Successfully retrieved certificate")
            cert = der_to_cert(b"".join(response["pctbEncodedCert"]["pb"]))
            return cert

        elif error_code == DISPOSITION_PENDING:
            logging.warning("Certificate request is still pending approval")
        else:
            # Handle error case
            error_msg = translate_error_code(error_code)
            if "unknown error code" in error_msg:
                logging.error(
                    f"Got unknown error while trying to retrieve certificate: ({error_msg}): "
                    f"{b''.join(response['pctbDispositionMessage']['pb']).decode('utf-16le')}"
                )
            else:
                logging.error(
                    f"Got error while trying to retrieve certificate: {error_msg}"
                )

        return None

    def request(
        self, csr: bytes, attributes_list: List[str]
    ) -> Optional[x509.Certificate]:
        """
        Submit a certificate request via RPC.

        Args:
            csr: Certificate signing request data
            attributes_list: List of certificate attributes

        Returns:
            Certificate object if successful, False on failure
        """
        # Format attributes
        attributes = checkNullString("\n".join(attributes_list)).encode("utf-16le")

        # Prepare attribute blob
        pctb_attribs = CERTTRANSBLOB()
        pctb_attribs["cb"] = len(attributes)
        pctb_attribs["pb"] = attributes

        # Prepare request blob
        pctb_request = CERTTRANSBLOB()
        pctb_request["cb"] = len(csr)
        pctb_request["pb"] = csr

        # Build the request structure
        request = CertServerRequest()
        request["dwFlags"] = 0
        request["pwszAuthority"] = checkNullString(self.parent.ca)
        request["pdwRequestId"] = self.parent.request_id or 0
        request["pctbAttribs"] = pctb_attribs
        request["pctbRequest"] = pctb_request

        logging.info("Requesting certificate via RPC")

        if self.dce is None:
            raise Exception("Failed to get DCE RPC connection")

        # Submit the request
        response = self.dce_request(request)

        # Process the response
        error_code = response["pdwDisposition"]
        request_id = response["pdwRequestId"]

        if error_code == DISPOSITION_SUCCESS:
            logging.info("Successfully requested certificate")
            cert = der_to_cert(b"".join(response["pctbEncodedCert"]["pb"]))
            logging.info(f"Request ID is {request_id}")
            return cert

        # Handle non-successful responses
        if error_code == DISPOSITION_PENDING:
            logging.warning("Certificate request is pending approval")
        else:
            error_msg = translate_error_code(error_code)
            if "unknown error code" in error_msg:
                logging.error(
                    f"Got unknown error while trying to request certificate: ({error_msg}): "
                    f"{b''.join(response['pctbDispositionMessage']['pb']).decode('utf-16le')}"
                )
            else:
                logging.error(
                    f"Got error while trying to request certificate: {error_msg}"
                )

        logging.info(f"Request ID is {request_id}")

        # Ask if the user wants to save the private key for pending requests
        should_save = input("Would you like to save the private key? (y/N) ").rstrip(
            "\n"
        )

        if should_save.lower() == "y":
            out = self.parent.out if self.parent.out is not None else str(request_id)
            with open(f"{out}.key", "wb") as f:
                if self.parent.key is None:
                    logging.error("No private key found")
                    return None
                _ = f.write(key_to_pem(self.parent.key))

            logging.info(f"Saved private key to {out}.key")

        return None


class WebRequestInterface:
    """
    Request interface for Web Enrollment communication with Certificate Services.
    """

    def __init__(self, parent: "Request"):
        """
        Initialize the Web Enrollment request interface.

        Args:
            parent: The parent Request object
        """
        self.parent = parent
        self.target = self.parent.target
        self._session = None
        self.base_url = ""

    @property
    def session(self) -> Optional[httpx.Client]:
        """
        Get or establish an HTTP session to the certificate authority.

        Returns:
            Active HTTP session, or None if connection failed

        Raises:
            Exception: If target is not set or connection fails
        """
        if self._session is not None:
            return self._session

        # Create a session with httpx with appropriate authentication
        if self.target.do_kerberos:
            session = httpx.Client(
                auth=HttpxImpacketKerberosAuth(self.target),
                timeout=self.target.timeout,
                verify=False,
            )
        else:
            # NTLM authentication
            password = self.target.password
            if self.target.nthash:
                password = f"{self.target.nthash}:{self.target.nthash}"

            principal = f"{self.target.domain}\\{self.target.username}"
            session = httpx.Client(
                auth=HttpNtlmAuth(principal, password),
                timeout=self.target.timeout,
                verify=False,
            )

        # Try the specified scheme and port first
        scheme = self.parent.http_scheme or "https"
        port = self.parent.port or (443 if scheme == "https" else 80)

        base_url = f"{scheme}://{self.target.target_ip}:{port}"
        logging.info(f"Checking for Web Enrollment on {repr(base_url)}")

        success = self._try_connection(session, base_url)

        # If the first attempt fails, try the alternative scheme
        if not success:
            alt_scheme = "http" if scheme == "https" else "https"
            alt_port = 80 if alt_scheme == "http" else 443

            base_url = f"{alt_scheme}://{self.target.target_ip}:{alt_port}"
            logging.info(
                f"Trying to connect to Web Enrollment interface {repr(base_url)}"
            )

            success = self._try_connection(session, base_url)

        if not success:
            logging.error("Could not connect to Web Enrollment")
            return None

        self.base_url = base_url
        self._session = session
        return self._session

    def _try_connection(self, session: httpx.Client, base_url: str) -> bool:
        """
        Try to connect to the Web Enrollment interface.

        Args:
            session: HTTP session to use
            base_url: Base URL to connect to

        Returns:
            True if connection was successful, False otherwise
        """
        headers = {
            "User-Agent": USER_AGENT,
        }
        host_value = self.target.remote_name or self.target.target_ip
        if host_value:
            headers["Host"] = host_value

        try:
            res = session.get(
                f"{base_url}/certsrv/",
                headers=headers,
                timeout=self.target.timeout,
                follow_redirects=False,
            )

            if res.status_code == 200:
                return True
            elif res.status_code == 401:
                logging.error(f"Unauthorized for Web Enrollment at {repr(base_url)}")
            else:
                logging.warning(
                    f"Failed to authenticate to Web Enrollment at {repr(base_url)}"
                )
                logging.debug(f"Got status code: {repr(res.status_code)}")
                logging.debug(f"HTML Response:\n{repr(res.content)}")

        except Exception as e:
            logging.warning(f"Failed to connect to Web Enrollment interface: {e}")

        return False

    def retrieve(self, request_id: int) -> Optional[x509.Certificate]:
        """
        Retrieve a certificate by request ID via Web Enrollment.

        Args:
            request_id: The request ID to retrieve

        Returns:
            Certificate object if successful, None on failure
        """
        logging.info(f"Retrieving certificate for request ID: {request_id}")

        if self.session is None:
            raise Exception("Failed to get HTTP session")

        # Request the certificate
        res = self.session.get(
            f"{self.base_url}/certsrv/certnew.cer", params={"ReqID": request_id}
        )

        if res.status_code != 200:
            if self.parent.verbose:
                logging.error("Got error while trying to retrieve certificate:")
                print(res.text)
            else:
                logging.error(
                    "Got error while trying to retrieve certificate. Use -debug to print the response"
                )
            return None

        # Handle PEM and DER format responses
        if b"BEGIN CERTIFICATE" in res.content:
            # Certificate in PEM format
            cert = pem_to_cert(res.content)
            return cert
        else:
            # Not a certificate - process the error
            content = res.text
            if "Taken Under Submission" in content:
                logging.warning("Certificate request is pending approval")
            elif "The requested property value is empty" in content:
                logging.warning(f"Unknown request ID {request_id}")
            else:
                # Try to extract error code
                error_code = re.findall(r" (0x[0-9a-fA-F]+) \(", content)
                try:
                    error_code_int = int(error_code[0], 16)
                    msg = translate_error_code(error_code_int)
                    logging.warning(f"Got error from AD CS: {msg}")
                except Exception:
                    if self.parent.verbose:
                        logging.warning("Got unknown error from AD CS:")
                        print(content)
                    else:
                        logging.warning(
                            "Got unknown error from AD CS. Use -debug to print the response"
                        )
            return None

    def request(
        self, csr: bytes, attributes_list: List[str]
    ) -> Optional[x509.Certificate]:
        """
        Submit a certificate request via Web Enrollment.

        Args:
            csr_bytes: Certificate signing request data
            attributes_list: List of certificate attributes

        Returns:
            Certificate object if successful, None on failure
        """
        if self.session is None:
            raise Exception("Failed to get HTTP session")

        # Convert CSR from DER to PEM format
        csr_pem = der_to_pem(csr, "CERTIFICATE REQUEST")

        # Join attributes
        attributes = "\n".join(attributes_list)

        # Prepare request parameters
        params = {
            "Mode": "newreq",
            "CertAttrib": attributes,
            "CertRequest": csr_pem,
            "TargetStoreFlags": "0",
            "SaveCert": "yes",
            "ThumbPrint": "",
        }

        logging.info("Requesting certificate via Web Enrollment")

        # Submit the request
        res = self.session.post(f"{self.base_url}/certsrv/certfnsh.asp", data=params)
        content = res.text

        if res.status_code != 200:
            logging.error("Got error while trying to request certificate: ")
            if self.parent.verbose:
                print(content)
            else:
                logging.warning("Use -debug to print the response")
            return None

        # Try to extract the request ID
        request_id_matches = re.findall(r"certnew.cer\?ReqID=([0-9]+)&", content)

        # If request ID found, certificate was issued immediately
        if request_id_matches:
            request_id = int(request_id_matches[0])
            logging.info(f"Request ID is {request_id}")
            return self.retrieve(request_id)

        # Handle pending or failed requests
        request_id = None

        # Check for pending requests
        if "template that is not supported" in content:
            logging.error(
                f"Template {repr(self.parent.template)} is not supported by AD CS"
            )
        else:
            # Try to find request ID in other format
            request_id_matches = re.findall(r"Your Request Id is ([0-9]+)", content)
            if request_id_matches:
                request_id = int(request_id_matches[0])
                logging.info(f"Request ID is {request_id}")

                # Check for different error conditions
                if "Certificate Pending" in content:
                    logging.warning("Certificate request is pending approval")
                elif '"Denied by Policy Module"' in content:
                    self._handle_policy_denial(request_id)
                else:
                    self._handle_other_errors(content)

        # Save private key if there's a request ID
        if request_id is not None:
            self._handle_pending_key_save(request_id)

        return None

    def _handle_policy_denial(self, request_id: int) -> None:
        """
        Handle certificate request denied by policy.

        Args:
            request_id: The certificate request ID
        """
        if self.session is None:
            raise Exception("Failed to get HTTP session")

        res = self.session.get(
            f"{self.base_url}/certsrv/certnew.cer", params={"ReqID": request_id}
        )

        try:
            error_codes = re.findall(
                r"(0x[a-zA-Z0-9]+) \([-]?[0-9]+ ",
                res.text,
                flags=re.MULTILINE,
            )

            error_msg = translate_error_code(int(error_codes[0], 16))
            logging.error(f"Got error while trying to request certificate: {error_msg}")
        except Exception:
            logging.warning("Got unknown error from AD CS:")
            if self.parent.verbose:
                print(res.text)
            else:
                logging.warning("Use -debug to print the response")

    def _handle_other_errors(self, content: str) -> None:
        """
        Handle other certificate request errors.

        Args:
            content: Response content
        """
        error_code_matches = re.findall(
            r"Denied by Policy Module  (0x[0-9a-fA-F]+),", content
        )

        try:
            error_code = int(error_code_matches[0], 16)
            msg = translate_error_code(error_code)
            logging.warning(f"Got error from AD CS: {msg}")
        except Exception:
            logging.warning("Got unknown error from AD CS:")
            if self.parent.verbose:
                print(content)
            else:
                logging.warning("Use -debug to print the response")

    def _handle_pending_key_save(self, request_id: int) -> None:
        """
        Handle saving the private key for pending requests.

        Args:
            request_id: The certificate request ID
        """
        should_save = input("Would you like to save the private key? (y/N) ").rstrip(
            "\n"
        )

        if should_save.lower() == "y":
            out = self.parent.out if self.parent.out is not None else str(request_id)

            try:
                with open(f"{out}.key", "wb") as f:
                    if self.parent.key is None:
                        logging.error("No private key found")
                        return

                    _ = f.write(key_to_pem(self.parent.key))

                logging.info(f"Saved private key to {out}.key")
            except Exception as e:
                logging.error(f"Failed to save private key: {str(e)}")


# =========================================================================
# Main Request class
# =========================================================================


class Request:
    """
    Main class for certificate operations with AD CS.

    This class provides functionality for requesting, retrieving, and managing
    certificates from Active Directory Certificate Services.
    """

    def __init__(
        self,
        target: Target,
        ca: Optional[str] = None,
        template: Optional[str] = None,
        upn: Optional[str] = None,
        dns: Optional[str] = None,
        sid: Optional[str] = None,
        subject: Optional[str] = None,
        retrieve: Optional[int] = None,
        on_behalf_of: Optional[str] = None,
        pfx: Optional[str] = None,
        pfx_password: Optional[str] = None,
        key_size: int = 2048,
        archive_key: bool = False,
        cax_cert: bool = False,
        renew: bool = False,
        out: Optional[str] = None,
        key: Optional[rsa.RSAPrivateKey] = None,
        web: bool = False,
        dcom: bool = False,
        port: Optional[int] = None,
        http_scheme: Optional[str] = None,
        dynamic_endpoint: bool = False,
        debug: bool = False,
        application_policies: Optional[List[str]] = None,
        smime: Optional[str] = None,
        **kwargs,
    ):
        """
        Initialize a certificate request object.

        Args:
            target: Target information including host and authentication
            ca: Certificate Authority name
            template: Certificate template name
            upn: Alternative UPN (User Principal Name)
            dns: Alternative DNS name
            sid: Alternative SID (Security Identifier)
            subject: Certificate subject name
            retrieve: Request ID to retrieve
            on_behalf_of: Username to request on behalf of
            pfx: Path to PKCS#12/PFX file
            pfx_password: Password for PFX file
            key_size: RSA key size in bits
            archive_key: Whether to archive the private key
            cax_cert: Whether to retrieve the CAX certificate
            renew: Whether to renew an existing certificate
            out: Output file path
            key: Pre-generated RSA key
            web: Use Web Enrollment instead of RPC
            dcom: Use DCOM instead of RPC
            port: Port for Web Enrollment
            scheme: Scheme for Web Enrollment (http/https)
            dynamic_endpoint: Use dynamic RPC endpoint
            debug: Enable verbose debug output
            application_policies: List of application policy OIDs
            smime: SMIME capability identifier
        """
        # Core parameters
        self.target = target
        self.ca = ca
        self.template = template
        self.alt_upn = upn
        self.alt_dns = dns
        self.alt_sid = sid
        self.subject = subject
        self.request_id = int(retrieve) if retrieve else None
        self.on_behalf_of = on_behalf_of
        self.pfx = pfx
        self.pfx_password = pfx_password
        self.key_size = key_size
        self.archive_key = archive_key
        self.cax_cert = cax_cert
        self.renew = renew
        self.out = out
        self.key = key

        # Convert application policy names to OIDs
        self.application_policies = [
            OID_TO_STR_MAP.get(policy, policy)
            for policy in (application_policies or [])
        ]
        self.smime = smime

        # Connection parameters
        self.web = web
        self.dcom = dcom
        self.port = port
        self.http_scheme = http_scheme

        # Handle default ports based on scheme
        if not self.port and self.http_scheme:
            if self.http_scheme == "http":
                self.port = 80
            elif self.http_scheme == "https":
                self.port = 443

        # Debug options
        self.dynamic = dynamic_endpoint
        self.verbose = debug
        self.kwargs = kwargs

        # Interface is initialized on demand
        self._interface = None

    @property
    def interface(self) -> RequestInterface:
        """
        Get the appropriate request interface based on configuration.

        Returns:
            Configured request interface instance
        """
        if self._interface is not None:
            return self._interface

        # Select interface based on configuration
        if self.web:
            self._interface = WebRequestInterface(self)
        elif self.dcom:
            self._interface = DCOMRequestInterface(self)
        else:
            self._interface = RPCRequestInterface(self)

        return self._interface

    def retrieve(self) -> bool:
        """
        Retrieve a certificate by request ID.

        Returns:
            True if successful, False otherwise
        """
        if self.request_id is None:
            logging.error("No request ID specified")
            return False

        request_id = int(self.request_id)

        # Retrieve the certificate using the appropriate interface
        cert = self.interface.retrieve(request_id)
        if cert is False or cert is None:
            logging.error("Failed to retrieve certificate")
            return False

        # Extract and display certificate information
        identifications = get_identifications_from_certificate(cert)
        print_certificate_identifications(identifications)

        # Check for object SID
        object_sid = get_object_sid_from_certificate(cert)
        if object_sid is not None:
            logging.info(f"Certificate object SID is {repr(object_sid)}")
        else:
            logging.info("Certificate has no object SID")

        # Determine output filename
        out = self.out
        if out is None:
            out, _ = cert_id_to_parts(identifications)  # type: ignore
            if out is None:
                if not self.target is None and not self.target.username is None:
                    out = self.target.username
                else:
                    out = f"{request_id}"

            out = out.rstrip("$").lower()

        # Try to find matching private key
        try:
            with open(f"{request_id}.key", "rb") as f:
                key = pem_to_key(f.read())

            # If key found, save as PFX
            logging.info(f"Loaded private key from {repr(f'{request_id}.key')}")
            pfx = create_pfx(key, cert, self.pfx_password)

            with open(f"{out}.pfx", "wb") as f:
                _ = f.write(pfx)

            logging.info(f"Saved certificate and private key to {repr(f'{out}.pfx')}")

        except Exception:
            # If no key found, save just the certificate
            logging.warning(
                "Could not find matching private key. Saving certificate as PEM"
            )

            with open(f"{out}.crt", "wb") as f:
                _ = f.write(cert_to_pem(cert))

            logging.info(f"Saved certificate to {repr(f'{out}.crt')}")

        return True

    def request(self) -> Union[bool, Tuple[bytes, str]]:
        """
        Request a new certificate from AD CS.

        Returns:
            PFX data and filename if successful, False otherwise
        """
        if self.target is None:
            logging.error("No target specified")
            return False

        if self.target.username is None:
            logging.error("No username specified")
            return False

        # Determine username for certificate
        username = self.target.username

        # Validate request options
        if sum(map(bool, [self.archive_key, self.on_behalf_of, self.renew])) > 1:
            logging.error(
                "Combinations of -renew, -on-behalf-of, and -archive-key are currently not supported"
            )
            return False

        # Handle on-behalf-of requests
        if self.on_behalf_of:
            username = self.on_behalf_of
            if self.on_behalf_of.count("\\") > 0:
                parts = username.split("\\")
                username = "\\".join(parts[1:])
                domain = parts[0]
                if "." in domain:
                    logging.warning(
                        "Domain part of '-on-behalf-of' should not be a FQDN"
                    )

        # Handle certificate renewal
        renewal_cert = None
        renewal_key = None
        if self.renew:
            if self.pfx is None:
                logging.error(
                    "A certificate and private key (-pfx) is required for renewal"
                )
                return False

            with open(self.pfx, "rb") as f:
                renewal_key, renewal_cert = load_pfx(f.read())
                if not renewal_key or not renewal_cert:
                    logging.error("Failed to load certificate and private key from PFX")
                    return False

        # Convert application policy names to OIDs
        converted_policies = []
        for policy in self.application_policies or []:
            oid = next(
                (k for k, v in OID_TO_STR_MAP.items() if v.lower() == policy.lower()),
                policy,
            )
            converted_policies.append(oid)

        self.application_policies = converted_policies

        # Create the CSR
        csr, key = create_csr(
            username,
            alt_dns=self.alt_dns,
            alt_upn=self.alt_upn,
            alt_sid=self.alt_sid,
            key=self.key,
            key_size=self.key_size,
            subject=self.subject,
            renewal_cert=renewal_cert,
            application_policies=self.application_policies,
            smime=self.smime,
        )
        self.key = key

        # Convert CSR to DER format
        csr_der = csr_to_der(csr)

        # Handle key archival
        if self.archive_key:
            ca = CA(self.target, self.ca)
            logging.info("Trying to retrieve CAX certificate")
            cax_cert = ca.get_exchange_certificate()
            logging.info("Retrieved CAX certificate")

            if not isinstance(self.key, rsa.RSAPrivateKey):
                logging.error("Currently only RSA keys are supported for key archival")
                return False

            csr_der = create_key_archival(der_to_csr(csr_der), self.key, cax_cert)

        # Handle certificate renewal
        if self.renew:
            if not renewal_cert or not renewal_key:
                logging.error(
                    "A certificate and private key (-pfx) is required for renewal"
                )
                return False

            if not isinstance(renewal_key, rsa.RSAPrivateKey):
                logging.error("Currently only RSA keys are supported for renewal")
                return False

            csr_der = create_renewal(csr_der, renewal_cert, renewal_key)

        # Handle on-behalf-of requests
        if self.on_behalf_of:
            if self.pfx is None:
                logging.error(
                    "A certificate and private key (-pfx) is required for on-behalf-of requests"
                )
                return False

            with open(self.pfx, "rb") as f:
                agent_key, agent_cert = load_pfx(f.read())

            if agent_key is None or agent_cert is None:
                logging.error(
                    f"Failed to load certificate and private key from {self.pfx}"
                )
                return False

            if not isinstance(agent_key, rsa.RSAPrivateKey):
                logging.error(
                    "Currently only RSA keys are supported for on-behalf-of requests"
                )
                return False

            csr_der = create_on_behalf_of(
                csr_der, self.on_behalf_of, agent_cert, agent_key
            )

        # Construct attributes list
        attributes = [f"CertificateTemplate:{self.template}"]

        if self.alt_upn is not None or self.alt_dns is not None:
            san = []
            if self.alt_dns:
                san.append(f"dns={self.alt_dns}")
            if self.alt_upn:
                san.append(f"upn={self.alt_upn}")

            attributes.append(f"SAN:{'&'.join(san)}")

        if self.application_policies:
            policy_string = "&".join(self.application_policies)
            attributes.append(f"ApplicationPolicies:{policy_string}")

        # Submit the certificate request
        cert = self.interface.request(csr_der, attributes)

        if cert is False or cert is None:
            logging.error("Failed to request certificate")
            return False

        # Log subject info
        if self.subject:
            subject = ",".join(map(lambda x: x.rfc4514_string(), cert.subject.rdns))
            logging.info(f"Got certificate with subject: {subject}")

        # Extract and display certificate information
        identifications = get_identifications_from_certificate(cert)
        print_certificate_identifications(identifications)

        # Check for object SID
        object_sid = get_object_sid_from_certificate(cert)
        if object_sid is not None:
            logging.info(f"Certificate object SID is {repr(object_sid)}")
        else:
            logging.info("Certificate has no object SID")

        # Determine output filename
        out = self.out
        if out is None:
            out, _ = cert_id_to_parts(identifications)  # type: ignore
            if out is None:
                out = self.target.username

            out = out.rstrip("$").lower()

        # Create PFX and save to file
        pfx = create_pfx(key, cert, self.pfx_password)
        outfile = f"{out}.pfx"

        with open(outfile, "wb") as f:
            _ = f.write(pfx)

        logging.info(f"Saved certificate and private key to {repr(outfile)}")

        return pfx, outfile

    def getCAX(self) -> Union[bool, bytes]:
        """
        Retrieve the CAX (Exchange) certificate.

        Returns:
            CAX certificate in DER format if successful, False otherwise
        """
        if self.target is None:
            logging.error("No target specified")
            return False

        ca = CA(self.target, self.ca)
        logging.info("Trying to retrieve CAX certificate")
        cax_cert = ca.get_exchange_certificate()
        logging.info("Retrieved CAX certificate")
        cax_cert_der = cert_to_der(cax_cert)

        return cax_cert_der


# =========================================================================
# Command-line entry point
# =========================================================================


def entry(options: argparse.Namespace) -> None:
    """
    Command-line entry point for certificate operations.

    Args:
        options: Command-line arguments
    """
    # Create target from options
    target = Target.from_options(options)
    options.__delattr__("target")

    # Create request object
    request = Request(target=target, **vars(options))

    # Handle CAX certificate retrieval
    if options.cax_cert:
        if not options.out:
            logging.error("Please specify an output file for the CAX certificate!")
            return

        cax = request.getCAX()
        if isinstance(cax, bytes):
            with open(options.out, "wb") as f:
                _ = f.write(cax)
            logging.info(f"CAX certificate saved to {options.out}")
        return

    # Handle certificate retrieval or request
    if options.retrieve:
        _ = request.retrieve()
    else:
        _ = request.request()
