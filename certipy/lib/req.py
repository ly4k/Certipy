"""
Certificate Request and Management Functions for Certipy

This module implements certificate request, retrieval, and management functionality for Certipy,
providing both RPC and web-based interactions with Active Directory Certificate Services (AD CS).

The module handles:
- Certificate request submission (RPC, DCOM and web enrollment)
- Certificate retrieval for both immediate and pending requests
- Certificate storage and management (saving as PFX or PEM)
- Error handling for various certificate operations

Key components:
1. Request Class - Main interface for all certificate operations
2. Request Interfaces - Protocol-specific implementations (RPC, DCOM, Web)
3. Response Handlers - Process responses from certificate services
4. Certificate Processing - Handle certificate data once received
5. Helper Functions - Utility functions for common operations
"""

import re
from typing import Any, Dict, List, Optional, Protocol, Tuple, Union

import httpx
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from impacket.dcerpc.v5 import rpcrt
from impacket.dcerpc.v5.dcom.oaut import string_to_bin
from impacket.dcerpc.v5.dcomrt import DCOMANSWER, DCOMCALL, DCOMConnection, IRemUnknown2
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
    create_csr_attributes,
    create_key_archival,
    create_on_behalf_of,
    create_pfx,
    create_renewal,
    csr_to_der,
    csr_to_pem,
    der_to_cert,
    der_to_csr,
    der_to_pem,
    get_identities_from_certificate,
    get_object_sid_from_certificate,
    key_to_pem,
    load_pfx,
    pem_to_cert,
    pem_to_key,
    print_certificate_identities,
    rsa,
    x509,
)
from certipy.lib.constants import OID_TO_STR_NAME_MAP, USER_AGENT
from certipy.lib.errors import handle_error, translate_error_code
from certipy.lib.files import try_to_save_file
from certipy.lib.kerberos import HttpxKerberosAuth
from certipy.lib.logger import is_verbose, logging
from certipy.lib.ntlm import HttpxNtlmAuth
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

    def __init__(self, interface: IRemUnknown2):
        """
        Initialize the ICertRequestD interface.

        Args:
            interface: IRemUnknown2 interface from DCOM connection
        """
        super().__init__(interface)
        self._iid = IID_ICertRequestD


class DCERPCSessionError(rpcrt.DCERPCException):
    """
    Custom exception for handling certificate request errors.

    Enhances error messages by translating error codes to human-readable messages.
    """

    def __init__(
        self, error_string: Any = None, error_code: Any = None, packet: Any = None
    ):
        """
        Initialize the DCERPCSessionError.

        Args:
            error_string: Error description
            error_code: Numeric error code
            packet: The RPC packet that caused the error
        """
        rpcrt.DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self) -> str:
        """
        Format the error message with translated error code.

        Returns:
            Human-readable error message
        """
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
# Response Handlers
# =========================================================================


def handle_rpc_retrieve_response(
    response: Dict[str, Any],
) -> Optional[x509.Certificate]:
    """
    Process the RPC certificate retrieval response.

    Args:
        response: The RPC response dictionary

    Returns:
        Certificate object if successful, None otherwise
    """
    error_code = response["pdwDisposition"]

    if error_code == DISPOSITION_SUCCESS:
        logging.info("Successfully retrieved certificate")
        cert = der_to_cert(b"".join(response["pctbEncodedCert"]["pb"]))
        return cert

    # Handle non-success cases
    if error_code == DISPOSITION_PENDING:
        logging.warning("Certificate request is still pending approval")
    else:
        error_msg = translate_error_code(error_code)
        disposition_message = b"".join(response["pctbDispositionMessage"]["pb"]).decode(
            "utf-16le"
        )

        if "unknown error code" in error_msg:
            logging.error(
                f"Got unknown error while retrieving certificate: ({error_msg}): {disposition_message}"
            )
        else:
            logging.error(f"Got error while retrieving certificate: {error_msg}")

    return None


def handle_rpc_request_response(
    response: Dict[str, Any],
) -> Union[x509.Certificate, int]:
    """
    Process the RPC certificate request response.

    Args:
        response: The RPC response dictionary

    Returns:
        Certificate object if immediately successful, or request ID if pending/failed
    """
    error_code = response["pdwDisposition"]
    request_id = response["pdwRequestId"]

    # Always log the request ID
    logging.info(f"Request ID is {request_id}")

    # Handle success case
    if error_code == DISPOSITION_SUCCESS:
        logging.info("Successfully requested certificate")
        cert = der_to_cert(b"".join(response["pctbEncodedCert"]["pb"]))
        return cert

    # Handle non-success cases
    if error_code == DISPOSITION_PENDING:
        logging.warning("Certificate request is pending approval")
    else:
        error_msg = translate_error_code(error_code)
        disposition_message = b"".join(response["pctbDispositionMessage"]["pb"]).decode(
            "utf-16le"
        )

        if "unknown error code" in error_msg:
            logging.error(
                f"Got unknown error while requesting certificate: ({error_msg}): {disposition_message}"
            )
        else:
            logging.error(f"Got error while requesting certificate: {error_msg}")

    return request_id


# ============== Certificate Processing Functions ==============


def handle_request_response(
    cert: x509.Certificate,
    key: PrivateKeyTypes,
    username: str,
    subject: Optional[str] = None,
    alt_sid: Optional[str] = None,
    out: Optional[str] = None,
    pfx_password: Optional[str] = None,
) -> Tuple[bytes, str]:
    """
    Process a successful certificate request by saving the certificate and private key.

    Args:
        cert: The issued certificate
        key: The private key
        username: The username associated with the certificate
        subject: Optional subject name
        alt_sid: Optional alternate SID
        out: Optional output filename
        pfx_password: Optional PFX password

    Returns:
        Tuple of (pfx_data, output_filename)
    """
    # Log subject info if available
    if subject:
        subject_str = ",".join(map(lambda x: x.rfc4514_string(), cert.subject.rdns))
        logging.info(f"Got certificate with subject: {subject_str}")

    # Extract and display certificate information
    identities = get_identities_from_certificate(cert)
    print_certificate_identities(identities)

    # Check and log object SID information
    object_sid = get_object_sid_from_certificate(cert)
    if object_sid is not None:
        logging.info(f"Certificate object SID is {object_sid!r}")
    else:
        logging.info("Certificate has no object SID")
        if not alt_sid:
            logging.info(
                "Try using -sid to set the object SID or see the wiki for more details"
            )

    # Determine output filename
    out_filename = _determine_output_filename(out, identities, username)

    # Create PFX and save to file
    pfx = create_pfx(key, cert, pfx_password)

    outfile = f"{out_filename}.pfx"
    logging.info(f"Saving certificate and private key to {outfile!r}")
    saved_path = try_to_save_file(pfx, outfile)
    logging.info(f"Wrote certificate and private key to {saved_path!r}")

    return pfx, saved_path


def handle_retrieve(
    cert: x509.Certificate,
    request_id: int,
    username: str,
    out: Optional[str] = None,
    pfx_password: Optional[str] = None,
) -> bool:
    """
    Process a retrieved certificate by saving it with the private key if available.

    Args:
        cert: The retrieved certificate
        request_id: The certificate request ID
        username: The username associated with the certificate
        out: Optional output filename
        pfx_password: Optional PFX password

    Returns:
        True if successful
    """
    # Extract and display certificate information
    identities = get_identities_from_certificate(cert)
    print_certificate_identities(identities)

    # Check and log object SID information
    object_sid = get_object_sid_from_certificate(cert)
    if object_sid is not None:
        logging.info(f"Certificate object SID is {object_sid!r}")
    else:
        logging.info("Certificate has no object SID")

    # Determine output filename
    out_filename = _determine_output_filename(out, identities, username)

    # Try to find matching private key and save as PFX if found
    try:
        key_path = f"{request_id}.key"
        with open(key_path, "rb") as f:
            key = pem_to_key(f.read())

        logging.info(f"Loaded private key from {key_path!r}")
        pfx = create_pfx(key, cert, pfx_password)

        output_path = f"{out_filename}.pfx"
        logging.info(f"Saving certificate and private key to {output_path!r}")
        saved_path = try_to_save_file(pfx, output_path)
        logging.info(f"Wrote certificate and private key to {saved_path!r}")
    except Exception:
        # If no key found, save just the certificate as PEM
        logging.warning(
            "Could not find matching private key. Saving certificate as PEM"
        )
        handle_error(True)

        output_path = f"{out_filename}.crt"
        logging.info(f"Saving certificate to {output_path!r}")
        saved_path = try_to_save_file(cert_to_pem(cert), output_path)
        logging.info(f"Wrote certificate to {saved_path!r}")

    return True


def handle_pending_key_save(
    request_id: int, key: PrivateKeyTypes, out: Optional[str] = None
) -> None:
    """
    Offer to save the private key for pending certificate requests.

    Args:
        request_id: The certificate request ID
        key: The private key to save
        out: Optional output filename for the private key
    """
    should_save = input("Would you like to save the private key? (y/N): ")

    if should_save.strip().lower() == "y":
        output_path = f"{out if out is not None else str(request_id)}.key"

        try:
            logging.info(f"Saving private key to {output_path!r}")
            saved_path = try_to_save_file(key_to_pem(key), output_path)
            logging.info(f"Wrote private key to {saved_path!r}")
        except Exception as e:
            logging.error(f"Failed to save private key: {e}")
            handle_error()


# =========================================================================
# Web Request Handlers
# =========================================================================


def web_request(
    session: httpx.Client,
    username: str,
    csr: Union[str, bytes, x509.CertificateSigningRequest],
    attributes_list: List[str],
    template: str,
    key: PrivateKeyTypes,
    out: Optional[str] = None,
) -> Optional[x509.Certificate]:
    """
    Request a certificate via the web enrollment interface.

    Args:
        session: HTTP session client
        username: Username for the certificate
        csr: Certificate signing request (bytes or object)
        attributes_list: List of certificate attributes
        template: Certificate template name
        key: Private key for the certificate
        out: Optional output filename

    Returns:
        Certificate if immediately issued, None otherwise
    """
    # Convert CSR to PEM format if needed
    if isinstance(csr, x509.CertificateSigningRequest):
        csr_pem = csr_to_pem(csr).decode()
    elif isinstance(csr, bytes):
        csr_pem = der_to_pem(csr, "CERTIFICATE REQUEST")
    else:
        # Already in PEM format
        csr_pem = csr

    attributes = "\n".join(attributes_list)

    # Build request parameters
    params = {
        "Mode": "newreq",
        "CertAttrib": attributes,
        "CertRequest": csr_pem,
        "TargetStoreFlags": "0",
        "SaveCert": "yes",
        "ThumbPrint": "",
    }

    logging.info(
        f"Requesting certificate for {username!r} based on the template {template!r}"
    )

    # Send certificate request
    try:
        res = session.post("/certsrv/certfnsh.asp", data=params)
        content = res.text

        # Handle HTTP errors
        if res.status_code != 200:
            logging.error(f"Failed to request certificate (HTTP {res.status_code})")
            _log_response_if_verbose(content)
            return None

        # Check for successful issuance (certificate ready for download)
        request_id_matches = re.findall(r"certnew.cer\?ReqID=([0-9]+)&", content)
        if request_id_matches:
            request_id = int(request_id_matches[0])
            logging.info(f"Certificate issued with request ID {request_id}")
            return web_retrieve(session, request_id)

        # Handle various error conditions
        if "template that is not supported" in content:
            logging.error(f"Template {template!r} is not supported by AD CS")
        else:
            # Try to find request ID in other format
            request_id_matches = re.findall(r"Your Request Id is ([0-9]+)", content)
            if request_id_matches:
                request_id = int(request_id_matches[0])
                logging.info(f"Request ID is {request_id}")

                if "Certificate Pending" in content:
                    logging.warning("Certificate request is pending approval")
                elif '"Denied by Policy Module"' in content:
                    _handle_policy_denial(session, request_id)
                else:
                    _handle_other_errors(content)
            else:
                _handle_other_errors(content)

        # For pending requests, save the private key if requested
        request_id_matches = re.findall(r"Your Request Id is ([0-9]+)", content)
        if request_id_matches:
            request_id = int(request_id_matches[0])
            handle_pending_key_save(request_id, key, out)

        return None

    except Exception as e:
        logging.error(f"Error during web certificate request: {e}")
        handle_error()
        return None


def web_retrieve(
    session: httpx.Client,
    request_id: int,
) -> Optional[x509.Certificate]:
    """
    Retrieve a certificate via the web enrollment interface.

    Args:
        session: HTTP session client
        request_id: The certificate request ID

    Returns:
        Certificate if successfully retrieved, None otherwise
    """
    logging.info(f"Retrieving certificate for request ID: {request_id}")

    try:
        # Request the certificate
        res = session.get("/certsrv/certnew.cer", params={"ReqID": request_id})

        if res.status_code != 200:
            logging.error(f"Error retrieving certificate (HTTP {res.status_code})")
            _log_response_if_verbose(res.text)
            return None

        # Handle PEM-format certificate
        if b"BEGIN CERTIFICATE" in res.content:
            return pem_to_cert(res.content)

        # Handle DER-format certificate
        if res.headers.get("Content-Type") == "application/pkix-cert":
            return der_to_cert(res.content)

        # Handle error conditions
        content = res.text
        if "Taken Under Submission" in content:
            logging.warning("Certificate request is pending approval")
        elif "The requested property value is empty" in content:
            logging.warning(f"Unknown request ID {request_id}")
        else:
            # Try to extract error code
            error_codes = re.findall(r" (0x[0-9a-fA-F]+) \(", content)
            try:
                error_code_int = int(error_codes[0], 16)
                msg = translate_error_code(error_code_int)
                logging.warning(f"Got error from AD CS: {msg}")
            except Exception:
                logging.warning("Got unknown error from AD CS")
                _log_response_if_verbose(content)

        return None

    except Exception as e:
        logging.error(f"Error during web certificate retrieval: {e}")
        handle_error()
        return None


# =========================================================================
# Helper Functions
# =========================================================================


def _determine_output_filename(
    out: Optional[str], identities: List[Tuple[str, str]], username: str
) -> str:
    """
    Determine the output filename to use for saving certificates/keys.

    Args:
        out: User-specified output name (if any)
        identities: List of certificate identities
        username: The username associated with the certificate

    Returns:
        The output filename (without extension)
    """
    if out is not None:
        return out.removesuffix(".pfx")

    # Try to derive filename from certificate identity
    cert_username, _ = cert_id_to_parts(identities)  # type: ignore
    if cert_username is not None:
        return cert_username.rstrip("$").lower()

    # Fallback to provided username
    return username.rstrip("$").lower()


def _handle_policy_denial(session: httpx.Client, request_id: int) -> None:
    """
    Handle certificate request denied by policy.

    Args:
        session: HTTP session client
        request_id: The certificate request ID
    """
    try:
        res = session.get("/certsrv/certnew.cer", params={"ReqID": request_id})

        error_codes = re.findall(
            r"(0x[a-zA-Z0-9]+) \([-]?[0-9]+ ", res.text, flags=re.MULTILINE
        )
        if error_codes:
            error_msg = translate_error_code(int(error_codes[0], 16))
            logging.error(f"Certificate request denied: {error_msg}")
        else:
            logging.error(
                "Certificate request denied by policy module (no error code available)"
            )
            _log_response_if_verbose(res.text)

    except Exception as e:
        logging.error(f"Error retrieving denial details: {e}")
        handle_error(True)


def _handle_other_errors(content: str) -> None:
    """
    Handle other certificate request errors.

    Args:
        content: Response content
    """
    error_code_matches = re.findall(
        r"Denied by Policy Module  (0x[0-9a-fA-F]+),", content
    )

    try:
        if error_code_matches:
            error_code = int(error_code_matches[0], 16)
            msg = translate_error_code(error_code)
            logging.error(f"Got error from AD CS: {msg}")
        else:
            # Try other error code formats
            error_codes = re.findall(r"Error Number: (0x[0-9a-fA-F]+)", content)
            if error_codes:
                error_code = int(error_codes[0], 16)
                msg = translate_error_code(error_code)
                logging.error(f"Got error from AD CS: {msg}")
            else:
                logging.error("Unknown error from AD CS")
                _log_response_if_verbose(content)
    except Exception:
        logging.error("Failed to parse error message from AD CS")
        _log_response_if_verbose(content)


def _log_response_if_verbose(content: str) -> None:
    """
    Log response content if verbose logging is enabled.

    Args:
        content: Response content to log
    """
    if is_verbose():
        print(content)
    else:
        logging.warning("Use -debug to print the response")


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

        result = handle_rpc_request_response(response)

        if isinstance(result, int):
            return None

        return result

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
        # Check if the private key is available
        if self.parent.key is None:
            raise Exception("No private key found")

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

        result = handle_rpc_request_response(response)

        if isinstance(result, x509.Certificate):
            return result

        # Ask if the user wants to save the private key for pending requests
        handle_pending_key_save(result, self.parent.key, self.parent.out)

        return None


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

        self._dce = get_dce_rpc(
            MSRPC_UUID_ICPR,
            "\\pipe\\cert",
            self.parent.target,
            timeout=self.parent.target.timeout,
            dynamic=self.parent.dynamic,
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
        return handle_rpc_retrieve_response(response)

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
        # Check if the private key is available
        if self.parent.key is None:
            raise Exception("No private key found")

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

        result = handle_rpc_request_response(response)

        if isinstance(result, x509.Certificate):
            return result

        # Ask if the user wants to save the private key for pending requests
        handle_pending_key_save(result, self.parent.key, self.parent.out)

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

        # Try the specified scheme and port first
        scheme = self.parent.http_scheme or "https"
        port = self.parent.http_port or (443 if scheme == "https" else 80)

        base_url = f"{scheme}://{self.target.target_ip}:{port}"

        # Create a session with httpx with appropriate authentication
        if self.target.do_kerberos:
            session = httpx.Client(
                base_url=base_url,
                auth=HttpxKerberosAuth(
                    self.target, channel_binding=not self.parent.no_channel_binding
                ),
                timeout=self.target.timeout,
                verify=False,
            )
        else:
            session = httpx.Client(
                base_url=base_url,
                auth=HttpxNtlmAuth(
                    self.target, channel_binding=not self.parent.no_channel_binding
                ),
                timeout=self.target.timeout,
                verify=False,
            )

        logging.info(f"Checking for Web Enrollment on {base_url!r}")
        success = self._try_connection(session)

        # If the first attempt fails, try the alternative scheme
        if not success:
            alt_scheme = "http" if scheme == "https" else "https"
            alt_port = 80 if alt_scheme == "http" else 443

            base_url = f"{alt_scheme}://{self.target.target_ip}:{alt_port}"
            logging.info(f"Trying to connect to Web Enrollment interface {base_url!r}")

            session.base_url = base_url

            success = self._try_connection(session)

        if not success:
            logging.error("Could not connect to Web Enrollment")
            return None

        self.base_url = base_url
        self._session = session
        return self._session

    def _try_connection(self, session: httpx.Client) -> bool:
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
                "/certsrv/",
                headers=headers,
                timeout=self.target.timeout,
                follow_redirects=False,
            )

            if res.status_code == 200:
                return True
            elif res.status_code == 401:
                logging.error(
                    f"Unauthorized for Web Enrollment at {session.base_url!r}"
                )
            else:
                logging.warning(
                    f"Failed to authenticate to Web Enrollment at {session.base_url!r}"
                )
                logging.debug(f"Got status code: {res.status_code!r}")
                if is_verbose():
                    print(res.text)

        except Exception as e:
            logging.warning(f"Failed to connect to Web Enrollment interface: {e}")
            handle_error(True)

        return False

    def retrieve(self, request_id: int) -> Optional[x509.Certificate]:
        """
        Retrieve a certificate by request ID via Web Enrollment.

        Args:
            request_id: The request ID to retrieve

        Returns:
            Certificate object if successful, None on failure
        """
        if self.session is None:
            raise Exception("Failed to get HTTP session")

        return web_retrieve(
            self.session,
            request_id,
        )

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
        # Check if the private key is available
        if self.parent.key is None:
            raise Exception("No private key found")

        if self.session is None:
            raise Exception("Failed to get HTTP session")

        return web_request(
            self.session,
            self.target.username,
            csr,
            attributes_list,
            self.parent.template,
            self.parent.key,
            self.parent.out,
        )


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
        template: str = "User",
        upn: Optional[str] = None,
        dns: Optional[str] = None,
        sid: Optional[str] = None,
        subject: Optional[str] = None,
        application_policies: Optional[List[str]] = None,
        smime: Optional[str] = None,
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
        http_scheme: Optional[str] = None,
        http_port: Optional[int] = None,
        no_channel_binding: bool = False,
        dynamic_endpoint: bool = False,
        **kwargs,  # type: ignore
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
            application_policies: List of application policy OIDs
            smime: SMIME capability identifier
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
            OID_TO_STR_NAME_MAP.get(policy.lower(), policy)
            for policy in (application_policies or [])
        ]
        self.smime = smime

        # Connection parameters
        self.web = web
        self.dcom = dcom
        self.http_port = http_port
        self.http_scheme = http_scheme
        self.no_channel_binding = no_channel_binding

        # Handle default ports based on scheme
        if not self.http_port and self.http_scheme:
            if self.http_scheme == "http":
                self.http_port = 80
            elif self.http_scheme == "https":
                self.http_port = 443

        self.dynamic = dynamic_endpoint
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

        handle_retrieve(
            cert, request_id, self.target.username, self.out, self.pfx_password
        )

        return True

    def request(self) -> Union[bool, Tuple[bytes, str]]:
        """
        Request a new certificate from AD CS.

        Returns:
            PFX data and filename if successful, False otherwise
        """
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

        # Create the CSR
        csr, key = create_csr(
            username,
            alt_dns=self.alt_dns,
            alt_upn=self.alt_upn,
            alt_sid=self.alt_sid,
            subject=self.subject,
            key_size=self.key_size,
            application_policies=self.application_policies,
            smime=self.smime,
            key=self.key,
            renewal_cert=renewal_cert,
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
        attributes = create_csr_attributes(
            self.template,
            self.alt_dns,
            self.alt_upn,
            self.alt_sid,
            self.application_policies,
        )

        # Submit the certificate request
        cert = self.interface.request(csr_der, attributes)

        if cert is False or cert is None:
            logging.error("Failed to request certificate")
            return False

        return handle_request_response(
            cert,
            key,
            username,
            subject=self.subject,
            alt_sid=self.alt_sid,
            out=self.out,
            pfx_password=self.pfx_password,
        )

    def get_cax(self) -> Union[bool, bytes]:
        """
        Retrieve the CAX (Exchange) certificate.

        Returns:
            CAX certificate in DER format if successful, False otherwise
        """
        ca = CA(self.target, self.ca)
        logging.info("Trying to retrieve CAX certificate")
        cax_cert = ca.get_exchange_certificate()
        logging.info("Retrieved CAX certificate")
        cax_cert_der = cert_to_der(cax_cert)

        return cax_cert_der
