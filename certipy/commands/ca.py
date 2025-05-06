"""
Certificate Authority (CA) Management Module for Certipy.

This module provides functionality to interact with Active Directory Certificate Services (AD CS):
- CA certificate and security management
- Certificate template enablement/disablement
- Certificate request approval/denial
- Officer and manager role assignment
- CA backup/restore operations

It serves as a comprehensive tool for CA administration and security assessment.
"""

import argparse
import copy
import time
from typing import Any, List, Optional, Tuple, Union

from impacket.dcerpc.v5 import rpcrt, rrp, scmr
from impacket.dcerpc.v5.dcom.oaut import VARIANT
from impacket.dcerpc.v5.dcomrt import DCOMANSWER, DCOMCALL, IRemUnknown, IRemUnknown2
from impacket.dcerpc.v5.dtypes import DWORD, LONG, LPWSTR, PBYTE, ULONG, WSTR
from impacket.dcerpc.v5.ndr import NDRSTRUCT
from impacket.dcerpc.v5.nrpc import checkNullString
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException
from impacket.ldap import ldaptypes
from impacket.smbconnection import SMBConnection
from impacket.uuid import string_to_bin, uuidtup_to_bin

from certipy.lib.certificate import NameOID, create_pfx, der_to_cert, load_pfx, x509
from certipy.lib.constants import CERTIFICATION_AUTHORITY_RIGHTS
from certipy.lib.errors import translate_error_code
from certipy.lib.kerberos import get_TGS
from certipy.lib.ldap import LDAPConnection, LDAPEntry
from certipy.lib.logger import logging
from certipy.lib.rpc import (
    get_dce_rpc,
    get_dce_rpc_from_string_binding,
    get_dcom_connection,
)
from certipy.lib.security import CASecurity
from certipy.lib.target import Target

from .template import Template

# Module name
NAME = "ca"

# Constants for CA operations
IF_NOREMOTEICERTADMINBACKUP = 0x40
CR_PROP_TEMPLATES = 0x0000001D

# DCOM constants for CA interfaces
CLSID_ICertAdminD = string_to_bin("d99e6e73-fc88-11d0-b498-00a0c90312f3")
CLSID_CCertRequestD = string_to_bin("d99e6e74-fc88-11d0-b498-00a0c90312f3")
IID_ICertAdminD = uuidtup_to_bin(("d99e6e71-fc88-11d0-b498-00a0c90312f3", "0.0"))
IID_ICertAdminD2 = uuidtup_to_bin(("7fe0d935-dda6-443f-85d0-1cfb58fe41dd", "0.0"))
IID_ICertRequestD2 = uuidtup_to_bin(("5422fd3a-d4b8-4cef-a12e-e87d4ca22e90", "0.0"))


# =========================================================================
# Exception and Structure Definitions
# =========================================================================


class DCERPCSessionError(DCERPCException):
    """
    Custom exception class for CA session errors that provides more meaningful error messages.
    """

    def __init__(
        self, error_string: Any = None, error_code: Any = None, packet: Any = None
    ):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        self.error_code &= 0xFFFFFFFF  # type: ignore
        error_msg = translate_error_code(self.error_code)
        return f"CASessionError: {error_msg}"


class CERTTRANSBLOB(NDRSTRUCT):
    """
    Structure representing certificate transfer blob for RPC calls.
    """

    structure = (
        ("cb", ULONG),
        ("pb", PBYTE),
    )


# =========================================================================
# RPC Interface Definitions for CA Operations
# =========================================================================


class ICertAdminD_ResubmitRequest(DCOMCALL):
    """
    RPC interface for resubmitting certificate requests.
    Used to approve pending requests.
    """

    opnum = 5
    structure = (
        ("pwszAuthority", LPWSTR),
        ("pdwRequestId", DWORD),
        ("pwszExtensionName", LPWSTR),
    )


class ICertAdminD_ResubmitRequestResponse(DCOMANSWER):
    structure = (("pdwDisposition", ULONG),)


class ICertAdminD_DenyRequest(DCOMCALL):
    """
    RPC interface for denying certificate requests.
    """

    opnum = 6
    structure = (
        ("pwszAuthority", LPWSTR),
        ("pdwRequestId", DWORD),
    )


class ICertAdminD_DenyRequestResponse(DCOMANSWER):
    structure = (("ErrorCode", ULONG),)


class ICertRequestD2_GetCAProperty(DCOMCALL):
    """
    RPC interface for retrieving CA properties.
    """

    opnum = 7
    structure = (
        ("pwszAuthority", LPWSTR),
        ("PropId", LONG),
        ("PropIndex", LONG),
        ("PropType", LONG),
    )


class ICertRequestD2_GetCAPropertyResponse(DCOMANSWER):
    structure = (("pctbPropertyValue", CERTTRANSBLOB),)


class ICertAdminD2_GetCAProperty(DCOMCALL):
    """
    RPC interface for retrieving CA properties.
    """

    opnum = 32
    structure = (
        ("pwszAuthority", LPWSTR),
        ("PropId", LONG),
        ("PropIndex", LONG),
        ("PropType", LONG),
    )


class ICertAdminD2_GetCAPropertyResponse(DCOMANSWER):
    structure = (("pctbPropertyValue", CERTTRANSBLOB),)


class ICertAdminD2_SetCAProperty(DCOMCALL):
    """
    RPC interface for setting CA properties.
    """

    opnum = 33
    structure = (
        ("pwszAuthority", LPWSTR),
        ("PropId", LONG),
        ("PropIndex", LONG),
        ("PropType", LONG),
        ("pctbPropertyValue", CERTTRANSBLOB),
    )


class ICertAdminD2_SetCAPropertyResponse(DCOMANSWER):
    structure = (("ErrorCode", ULONG),)


class ICertAdminD2_GetCASecurity(DCOMCALL):
    """
    RPC interface for retrieving CA security settings.
    """

    opnum = 36
    structure = (("pwszAuthority", LPWSTR),)


class ICertAdminD2_GetCASecurityResponse(DCOMANSWER):
    structure = (("pctbSD", CERTTRANSBLOB),)


class ICertAdminD2_SetCASecurity(DCOMCALL):
    """
    RPC interface for setting CA security settings.
    """

    opnum = 37
    structure = (("pwszAuthority", LPWSTR), ("pctbSD", CERTTRANSBLOB))


class ICertAdminD2_SetCASecurityResponse(DCOMANSWER):
    structure = (("ErrorCode", LONG),)


class ICertAdminD2_GetConfigEntry(DCOMCALL):
    """
    RPC interface for retrieving CA configuration entries.
    """

    opnum = 44
    structure = (
        ("pwszAuthority", LPWSTR),
        ("pwszNodePath", LPWSTR),
        ("pwszEntry", WSTR),
    )


class ICertAdminD2_GetConfigEntryResponse(DCOMANSWER):
    structure = (("pVariant", VARIANT),)


# =========================================================================
# CA Interface Classes
# =========================================================================


class ICertCustom(IRemUnknown):
    """
    Base class for custom certificate service interfaces.
    """

    def request(self, req: Any, *args, **kwargs):  # type: ignore
        """
        Send a request to the CA service.

        Args:
            req: Request object
            *args: Additional arguments
            **kwargs: Additional keyword arguments

        Returns:
            Response from the CA service

        Raises:
            DCERPCException: If the RPC call fails
        """
        req["ORPCthis"] = self.get_cinstance().get_ORPCthis()  # type: ignore
        req["ORPCthis"]["flags"] = 0
        self.connect(self._iid)
        dce = self.get_dce_rpc()
        try:
            resp = dce.request(req, self.get_iPid(), *args, **kwargs)
        except Exception as e:
            if str(e).find("RPC_E_DISCONNECTED") >= 0:
                msg = str(e) + "\n"
                msg += (
                    "DCOM keep-alive pinging it might not be working as expected. You "
                    "can't be idle for more than 14 minutes!\n"
                )
                msg += "You should exit the app and start again\n"
                raise DCERPCException(msg)
            else:
                raise
        return resp


class ICertAdminD(ICertCustom):
    """
    Interface for the ICertAdminD service.
    This is the basic certificate administration interface.
    """

    def __init__(self, interface: IRemUnknown2):
        super().__init__(interface)
        self._iid = IID_ICertAdminD


class ICertAdminD2(ICertCustom):
    """
    Interface for the ICertAdminD2 service.
    This is the extended certificate administration interface.
    """

    def __init__(self, interface: IRemUnknown2):
        super().__init__(interface)
        self._iid = IID_ICertAdminD2


class ICertRequestD2(ICertCustom):
    """
    Interface for the ICertRequestD2 service.
    This interface is used for certificate requests.
    """

    def __init__(self, interface: IRemUnknown2):
        super().__init__(interface)
        self._iid = IID_ICertRequestD2


# =========================================================================
# Main CA Class
# =========================================================================


class CA:
    """
    Main class for interacting with Certificate Authorities.

    This class provides methods for:
    - Retrieving CA certificates and configuration
    - Managing certificate templates
    - Approving/denying certificate requests
    - Managing CA officers and managers
    - Backing up CA certificates and keys
    """

    def __init__(
        self,
        target: Target,
        ca: Optional[str] = None,
        template: Optional[str] = None,
        officer: Optional[str] = None,
        request_id: Optional[int] = None,
        connection: Optional[LDAPConnection] = None,
        scheme: str = "ldaps",
        dynamic: bool = False,
        config: Optional[str] = None,
        timeout: int = 5,
        debug: bool = False,
        **kwargs,  # type: ignore
    ):
        """
        Initialize CA management object.

        Args:
            target: Target information (hostname, credentials, etc.)
            ca: CA name
            template: Certificate template name
            officer: Officer username
            request_id: Certificate request ID
            connection: Existing LDAP connection to reuse
            scheme: LDAP scheme (ldap or ldaps)
            dc_host: Domain controller hostname
            dynamic: Use dynamic port allocation
            config: CA configuration string
            timeout: Connection timeout in seconds
            debug: Enable verbose debugging
            **kwargs: Additional arguments
        """
        self.target = target
        self.request_id = request_id
        self.ca = ca
        self.officer = officer
        self.template = template
        self.scheme = scheme
        self.dynamic = dynamic
        self.config = config
        self.timeout = timeout
        self.verbose = debug
        self.kwargs = kwargs

        # Initialize connection objects
        self._connection: Optional[LDAPConnection] = connection
        self._cert_admin: Optional[ICertAdminD] = None
        self._cert_admin2: Optional[ICertAdminD2] = None
        self._cert_request2: Optional[ICertRequestD2] = None
        self._rrp_dce = None

    # =========================================================================
    # Connection Properties and Methods
    # =========================================================================

    @property
    def connection(self) -> LDAPConnection:
        """
        Get or create an LDAP connection to the domain.

        Returns:
            Active LDAP connection

        Raises:
            ValueError: If target resolution fails
        """
        if self._connection:
            return self._connection

        target = copy.copy(self.target)

        if target.do_kerberos:
            if self.target.dc_host is None:
                raise Exception(
                    "Kerberos auth requires DNS name of the target DC. Use -dc-host."
                )

            target.remote_name = self.target.dc_host

        target.target_ip = target.dc_ip

        self._connection = LDAPConnection(target)
        self._connection.connect()

        return self._connection

    @property
    def cert_admin(self) -> ICertAdminD:
        """
        Get or create an ICertAdminD interface.

        Returns:
            ICertAdminD interface
        """
        if self._cert_admin is not None:
            return self._cert_admin

        dcom = get_dcom_connection(self.target)
        iInterface = dcom.CoCreateInstanceEx(CLSID_ICertAdminD, IID_ICertAdminD)
        iInterface.get_cinstance().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)  # type: ignore
        self._cert_admin = ICertAdminD(iInterface)
        return self._cert_admin

    @property
    def cert_admin2(self) -> ICertAdminD2:
        """
        Get or create an ICertAdminD2 interface.

        Returns:
            ICertAdminD2 interface
        """
        if self._cert_admin2 is not None:
            return self._cert_admin2

        dcom = get_dcom_connection(self.target)
        iInterface = dcom.CoCreateInstanceEx(CLSID_ICertAdminD, IID_ICertAdminD2)
        iInterface.get_cinstance().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)  # type: ignore
        self._cert_admin2 = ICertAdminD2(iInterface)

        return self._cert_admin2

    @property
    def cert_request2(self) -> ICertRequestD2:
        """
        Get or create an ICertRequestD2 interface.

        Returns:
            ICertRequestD2 interface
        """
        if self._cert_request2 is not None:
            return self._cert_request2

        dcom = get_dcom_connection(self.target)
        iInterface = dcom.CoCreateInstanceEx(CLSID_CCertRequestD, IID_ICertRequestD2)
        iInterface.get_cinstance().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)  # type: ignore
        self._cert_request2 = ICertRequestD2(iInterface)

        return self._cert_request2

    @property
    def rrp_dce(self):
        """
        Get or create a connection to the remote registry service.

        Returns:
            RRP DCE/RPC connection or None if connection fails
        """
        if self._rrp_dce is not None:
            return self._rrp_dce

        dce = get_dce_rpc_from_string_binding(
            "ncacn_np:445[\\pipe\\winreg]", self.target, timeout=self.target.timeout
        )

        # Try to connect up to 3 times (registry service might need to start)
        for _ in range(3):
            try:
                dce.connect()
                dce.bind(rrp.MSRPC_UUID_RRP)  # type: ignore
                logging.debug(
                    f"Connected to remote registry at {repr(self.target.remote_name)} ({self.target.target_ip})"
                )
                break
            except Exception as e:
                if "STATUS_PIPE_NOT_AVAILABLE" in str(e):
                    logging.warning(
                        "Failed to connect to remote registry. Service should be starting now. Trying again..."
                    )
                    time.sleep(1)
                else:
                    raise e
        else:
            logging.warning("Failed to connect to remote registry after 3 attempts")
            return None

        self._rrp_dce = dce
        return self._rrp_dce

    # =========================================================================
    # CA Certificate and Configuration Methods
    # =========================================================================

    def get_exchange_certificate(self) -> x509.Certificate:
        """
        Get the CA exchange certificate.

        Returns:
            CA exchange certificate

        Raises:
            Exception: If the certificate retrieval fails
        """
        request = ICertRequestD2_GetCAProperty()
        request["pwszAuthority"] = checkNullString(self.ca)
        request["PropId"] = 0x0000000F  # Exchange certificate property ID
        request["PropIndex"] = 0
        request["PropType"] = 0x00000003  # Binary data type

        resp = self.cert_request2.request(request)

        # Convert the certificate blob to an x509 certificate
        exchange_cert = der_to_cert(b"".join(resp["pctbPropertyValue"]["pb"]))
        return exchange_cert

    def get_config_csra(self) -> Tuple[int, int, int, CASecurity]:
        """
        Get CA configuration via the Certificate Services Remote Administration protocol.

        Returns:
            Tuple of (edit_flags, request_disposition, interface_flags, security)

        Raises:
            Exception: If the configuration retrieval fails
        """
        # Get request disposition setting (auto-approve, pending, etc.)
        request = ICertAdminD2_GetConfigEntry()
        request["pwszAuthority"] = checkNullString(self.ca)
        request["pwszNodePath"] = checkNullString(
            "PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy"
        )
        request["pwszEntry"] = checkNullString("RequestDisposition")

        resp = self.cert_admin2.request(request)
        request_disposition = resp["pVariant"]["_varUnion"]["lVal"]

        # Get edit flags (SAN setting, etc.)
        request["pwszEntry"] = checkNullString("EditFlags")
        resp = self.cert_admin2.request(request)
        edit_flags = resp["pVariant"]["_varUnion"]["lVal"]

        # Get interface flags (encryption settings, etc.)
        request["pwszNodePath"] = checkNullString("")
        request["pwszEntry"] = checkNullString("InterfaceFlags")
        resp = self.cert_admin2.request(request)
        interface_flags = resp["pVariant"]["_varUnion"]["lVal"]

        # Get CA security settings
        request = ICertAdminD2_GetCASecurity()
        request["pwszAuthority"] = checkNullString(self.ca)
        resp = self.cert_admin2.request(request)
        security = CASecurity(b"".join(resp["pctbSD"]["pb"]))

        return (edit_flags, request_disposition, interface_flags, security)

    def get_config_rrp(self) -> Tuple[int, int, int, CASecurity]:
        """
        Get CA configuration via the Remote Registry Protocol.
        Used as a fallback when CSRA fails.

        Returns:
            Tuple of (edit_flags, request_disposition, interface_flags, security)

        Raises:
            Exception: If the configuration retrieval fails
        """
        hklm = rrp.hOpenLocalMachine(self.rrp_dce)
        h_root_key = hklm["phKey"]

        # Get policy settings
        policy_key_path = (
            f"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{self.ca}\\"
            "PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy"
        )
        policy_key = rrp.hBaseRegOpenKey(self.rrp_dce, h_root_key, policy_key_path)

        _, edit_flags = rrp.hBaseRegQueryValue(
            self.rrp_dce, policy_key["phkResult"], "EditFlags"
        )

        if not isinstance(edit_flags, int):
            raise ValueError(
                f"Expected an int for edit flags, got {repr(type(edit_flags))}"
            )

        _, request_disposition = rrp.hBaseRegQueryValue(
            self.rrp_dce, policy_key["phkResult"], "RequestDisposition"
        )

        if not isinstance(request_disposition, int):
            raise ValueError(
                f"Expected an int for request disposition, got {repr(type(request_disposition))}"
            )

        # Get configuration settings
        configuration_key_path = (
            f"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{self.ca}"
        )
        configuration_key = rrp.hBaseRegOpenKey(
            self.rrp_dce, h_root_key, configuration_key_path
        )

        _, interface_flags = rrp.hBaseRegQueryValue(
            self.rrp_dce, configuration_key["phkResult"], "InterfaceFlags"
        )

        if not isinstance(interface_flags, int):
            raise ValueError(
                f"Expected an int for interface flags, got {repr(type(interface_flags))}"
            )

        _, security_descriptor = rrp.hBaseRegQueryValue(
            self.rrp_dce, configuration_key["phkResult"], "Security"
        )

        if not isinstance(security_descriptor, bytes):
            raise ValueError(
                f"Expected a bytes object for security descriptor, got {repr(type(security_descriptor))}"
            )

        security_descriptor = CASecurity(security_descriptor)
        return (edit_flags, request_disposition, interface_flags, security_descriptor)

    def get_config(
        self,
    ) -> Tuple[Optional[int], Optional[int], Optional[int], Optional[CASecurity]]:
        """
        Get CA configuration using either CSRA or RRP protocol.
        Tries CSRA first, then falls back to RRP if CSRA fails.

        Returns:
            Tuple of (edit_flags, request_disposition, interface_flags, security)
            Returns (None, None, None, None) if both methods fail
        """
        try:
            logging.info(f"Trying to get CA configuration for {repr(self.ca)} via CSRA")
            result = self.get_config_csra()
            logging.info(f"Got CA configuration for {repr(self.ca)}")
            return result
        except Exception as e:
            logging.warning(
                f"Got error while trying to get CA configuration for {repr(self.ca)} via CSRA: {str(e)}"
            )

        try:
            logging.info(f"Trying to get CA configuration for {repr(self.ca)} via RRP")
            result = self.get_config_rrp()
            logging.info(f"Got CA configuration for {repr(self.ca)}")
            return result
        except Exception as e:
            logging.warning(
                f"Got error while trying to get CA configuration for {repr(self.ca)} via RRP: {str(e)}"
            )

        logging.warning(f"Failed to get CA configuration for {repr(self.ca)}")
        return (None, None, None, None)

    # =========================================================================
    # Certificate Request Management Methods
    # =========================================================================

    def issue(self) -> bool:
        """
        Issue (approve) a pending certificate request.

        Returns:
            True if successful, False otherwise
        """
        if self.request_id is None:
            logging.error(
                "A request ID (-request-id) is required in order to issue a pending or failed certificate request"
            )
            return False

        request = ICertAdminD_ResubmitRequest()
        request["pwszAuthority"] = checkNullString(self.ca)
        request["pdwRequestId"] = int(self.request_id)
        request["pwszExtensionName"] = checkNullString(None)  # No extension

        try:
            resp = self.cert_admin.request(request)
        except DCERPCSessionError as e:
            if "E_ACCESSDENIED" in str(e):
                logging.error(
                    "Access denied: Insufficient permissions to issue certificate"
                )
                return False
            raise e

        error_code = resp["pdwDisposition"]

        if error_code == 3:  # Success
            logging.info(
                f"Successfully issued certificate request ID {self.request_id}"
            )
            return True
        else:
            error_msg = translate_error_code(error_code)
            logging.error(f"Failed to issue certificate: {error_msg}")
            return False

    def deny(self) -> bool:
        """
        Deny a pending certificate request.

        Returns:
            True if successful, False otherwise
        """
        if self.request_id is None:
            logging.error(
                "A request ID (-request-id) is required in order to deny a pending certificate request"
            )
            return False

        request = ICertAdminD_DenyRequest()
        request["pwszAuthority"] = checkNullString(self.ca)
        request["pdwRequestId"] = int(self.request_id)

        try:
            resp = self.cert_admin.request(request)
        except DCERPCSessionError as e:
            if "E_ACCESSDENIED" in str(e):
                logging.error(
                    "Access denied: Insufficient permissions to deny certificate request"
                )
                return False
            raise

        error_code = resp["ErrorCode"]

        if error_code == 0:  # Success
            logging.info(
                f"Successfully denied certificate request ID {self.request_id}"
            )
            return True
        else:
            error_msg = translate_error_code(error_code)
            logging.error(f"Failed to deny certificate request: {error_msg}")
            return False

    # =========================================================================
    # Template Management Methods
    # =========================================================================

    def get_templates(self) -> Optional[List[str]]:
        """
        Get list of templates enabled on the CA.

        Returns:
            List of template names and their OIDs
            Returns False if the operation fails
        """
        if self.ca is None:
            logging.error("A CA (-ca) is required")
            return None

        request = ICertAdminD2_GetCAProperty()
        request["pwszAuthority"] = checkNullString(self.ca)
        request["PropId"] = CR_PROP_TEMPLATES
        request["PropIndex"] = 0
        request["PropType"] = 4  # String data type

        try:
            resp = self.cert_admin2.request(request)
        except DCERPCSessionError as e:
            if "E_ACCESSDENIED" in str(e):
                logging.error(
                    "Access denied: Insufficient permissions to get templates"
                )
                return None
            raise e

        # Parse templates (format is name\noid\nname\noid...)
        certificate_templates = (
            b"".join(resp["pctbPropertyValue"]["pb"]).decode("utf-16le").split("\n")
        )
        return certificate_templates

    def list_templates(self) -> None:
        """
        List templates enabled on the CA.

        Prints the list of templates to stdout.
        """
        certificate_templates = self.get_templates()

        if certificate_templates is None:
            return

        if len(certificate_templates) == 1:
            logging.info(
                f"There are no enabled certificate templates on {repr(self.ca)}"
            )
            return

        logging.info(f"Enabled certificate templates on {repr(self.ca)}:")
        for i in range(0, len(certificate_templates) - 1, 2):
            print(f"    {certificate_templates[i]}")

    def enable(self, disable: bool = False) -> bool:
        """
        Enable or disable a template on the CA.

        Args:
            disable: If True, disable the template; otherwise enable it

        Returns:
            True if successful, False otherwise
        """
        if self.ca is None:
            logging.error("A CA (-ca) is required")
            return False

        if self.template is None:
            logging.error("A template (-template) is required")
            return False

        # Get current templates
        certificate_templates = self.get_templates()
        if certificate_templates is None:
            return False

        # Get template to enable/disable
        template_obj = Template(self.target, connection=self.connection)
        template = template_obj.get_configuration(self.template)
        if template is None:
            return False

        action = "disable" if disable else "enable"

        # Update template list based on action
        if disable:
            if template.get("cn") not in certificate_templates:
                logging.error(
                    f"Certificate template {repr(template.get('cn'))} is not enabled on {repr(self.ca)}"
                )
                return False

            # Remove template and its OID from the list
            template_index = certificate_templates.index(template.get("cn"))
            certificate_templates = (
                certificate_templates[:template_index]
                + certificate_templates[template_index + 2 :]
            )
        else:
            # Add template and its OID to the start of the list
            certificate_templates = [
                template.get("cn"),
                template.get("msPKI-Cert-Template-OID"),
            ] + certificate_templates

        # Convert to UTF-16LE bytes for RPC call
        certificate_templates_bytes = [
            bytes([c]) for c in "\n".join(certificate_templates).encode("utf-16le")
        ]

        # Update CA property
        request = ICertAdminD2_SetCAProperty()
        request["pwszAuthority"] = checkNullString(self.ca)
        request["PropId"] = CR_PROP_TEMPLATES
        request["PropIndex"] = 0
        request["PropType"] = 4  # String data type
        request["pctbPropertyValue"]["cb"] = len(certificate_templates_bytes)
        request["pctbPropertyValue"]["pb"] = certificate_templates_bytes

        try:
            resp = self.cert_admin2.request(request)
        except DCERPCSessionError as e:
            if "E_ACCESSDENIED" in str(e):
                logging.error(
                    f"Access denied: Insufficient permissions to {action} template"
                )
                return False
            raise e

        error_code = resp["ErrorCode"]
        if error_code == 0:
            logging.info(
                f"Successfully {action}d {repr(template.get('cn'))} on {repr(self.ca)}"
            )
            return True
        else:
            error_msg = translate_error_code(error_code)
            logging.error(f"Failed to {action} certificate template: {error_msg}")
            return False

    def disable(self) -> bool:
        """
        Disable a template on the CA.
        Convenience method that calls enable() with disable=True.

        Returns:
            True if successful, False otherwise
        """
        return self.enable(disable=True)

    # =========================================================================
    # CA Security Management Methods
    # =========================================================================

    def _modify_ca_security(
        self, user: str, right: int, right_type: str, remove: bool = False
    ) -> Union[bool, None]:
        """
        Add or remove rights for a user on the CA.

        Args:
            user: Username
            right: Right to add/remove (from CERTIFICATION_AUTHORITY_RIGHTS)
            right_type: Description of the right (for logging)
            remove: If True, remove the right; otherwise add it

        Returns:
            True if successful, False if failed, None if user not found
        """
        connection = self.connection

        # Get user object
        user_obj = connection.get_user(user)
        if user_obj is None:
            return None

        # Get user SID
        sid = ldaptypes.LDAP_SID(data=user_obj.get_raw("objectSid")[0])

        # Get current CA security descriptor
        request = ICertAdminD2_GetCASecurity()
        request["pwszAuthority"] = checkNullString(self.ca)

        try:
            resp = self.cert_admin2.request(request)
        except DCERPCSessionError as e:
            if "E_ACCESSDENIED" in str(e):
                logging.error(
                    "Access denied: Insufficient permissions to get CA security"
                )
                return False
            raise e

        # Parse security descriptor
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd.fromString(b"".join(resp["pctbSD"]["pb"]))

        # Find ACE for the user or create a new one
        for i in range(len(sd["Dacl"]["Data"])):
            ace = sd["Dacl"]["Data"][i]
            if ace["AceType"] != ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
                continue

            if ace["Ace"]["Sid"].getData() != sid.getData():
                continue

            # Found existing ACE for this user
            action = "remove" if remove else "add"

            if remove:
                # Check if user has the right
                if ace["Ace"]["Mask"]["Mask"] & right == 0:
                    logging.info(
                        f"User {repr(user_obj.get('sAMAccountName'))} does not have {right_type} "
                        f"rights on {repr(self.ca)}"
                    )
                    return True

                # Remove the right
                ace["Ace"]["Mask"]["Mask"] ^= right

                # Remove the ACE if no rights remaining
                if ace["Ace"]["Mask"]["Mask"] == 0:
                    sd["Dacl"]["Data"].pop(i)
            else:
                # Check if user already has the right
                if ace["Ace"]["Mask"]["Mask"] & right != 0:
                    logging.info(
                        f"User {repr(user_obj.get('sAMAccountName'))} already has {right_type} "
                        f"rights on {repr(self.ca)}"
                    )
                    return True

                # Add the right
                ace["Ace"]["Mask"]["Mask"] |= right

            break
        else:
            # No existing ACE found
            if remove:
                # Nothing to remove
                logging.info(
                    f"User {repr(user_obj.get('sAMAccountName'))} does not have {right_type} "
                    f"rights on {repr(self.ca)}"
                )
                return True

            # Create new ACE
            ace = ldaptypes.ACE()
            ace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
            ace["AceFlags"] = 0
            ace["Ace"] = ldaptypes.ACCESS_ALLOWED_ACE()
            ace["Ace"]["Mask"] = ldaptypes.ACCESS_MASK()
            ace["Ace"]["Mask"]["Mask"] = right
            ace["Ace"]["Sid"] = sid

            sd["Dacl"]["Data"].append(ace)

        # Convert SD back to bytes
        sd_bytes = [bytes([c]) for c in sd.getData()]

        # Set updated security descriptor
        request = ICertAdminD2_SetCASecurity()
        request["pwszAuthority"] = checkNullString(self.ca)
        request["pctbSD"]["cb"] = len(sd_bytes)
        request["pctbSD"]["pb"] = sd_bytes

        try:
            resp = self.cert_admin2.request(request)
        except DCERPCSessionError as e:
            if "E_ACCESSDENIED" in str(e):
                action = "remove" if remove else "add"
                logging.error(
                    f"Access denied: Insufficient permissions to {action} {right_type}"
                )
                return False
            raise e

        error_code = resp["ErrorCode"]
        if error_code == 0:
            action = "removed" if remove else "added"
            logging.info(
                f"Successfully {action} {right_type} {repr(user_obj.get('sAMAccountName'))} "
                f"on {repr(self.ca)}"
            )
            return True
        else:
            error_msg = translate_error_code(error_code)
            action = "remove" if remove else "add"
            logging.error(f"Failed to {action} {right_type}: {error_msg}")
            return False

    def add(self, user: str, right: int, right_type: str) -> Union[bool, None]:
        """
        Add a right for a user on the CA.

        Args:
            user: Username
            right: Right to add (from CERTIFICATION_AUTHORITY_RIGHTS)
            right_type: Description of the right (for logging)

        Returns:
            True if successful, False if failed, None if user not found
        """
        return self._modify_ca_security(user, right, right_type, remove=False)

    def remove(self, user: str, right: int, right_type: str) -> Union[bool, None]:
        """
        Remove a right from a user on the CA.

        Args:
            user: Username
            right: Right to remove (from CERTIFICATION_AUTHORITY_RIGHTS)
            right_type: Description of the right (for logging)

        Returns:
            True if successful, False if failed, None if user not found
        """
        return self._modify_ca_security(user, right, right_type, remove=True)

    def add_officer(self, officer: str) -> Union[bool, None]:
        """
        Add certificate officer rights for a user.
        Officers can approve/deny certificate requests.

        Args:
            officer: Username to add as an officer

        Returns:
            True if successful, False if failed, None if user not found
        """
        return self.add(
            officer, CERTIFICATION_AUTHORITY_RIGHTS.MANAGE_CERTIFICATES.value, "officer"
        )

    def remove_officer(self, officer: str) -> Union[bool, None]:
        """
        Remove certificate officer rights from a user.

        Args:
            officer: Username to remove as an officer

        Returns:
            True if successful, False if failed, None if user not found
        """
        return self.remove(
            officer, CERTIFICATION_AUTHORITY_RIGHTS.MANAGE_CERTIFICATES.value, "officer"
        )

    def add_manager(self, manager: str) -> Union[bool, None]:
        """
        Add certificate manager rights for a user.
        Managers can manage CA configuration.

        Args:
            manager: Username to add as a manager

        Returns:
            True if successful, False if failed, None if user not found
        """
        return self.add(
            manager, CERTIFICATION_AUTHORITY_RIGHTS.MANAGE_CA.value, "manager"
        )

    def remove_manager(self, manager: str) -> Union[bool, None]:
        """
        Remove certificate manager rights from a user.

        Args:
            manager: Username to remove as a manager

        Returns:
            True if successful, False if failed, None if user not found
        """
        return self.remove(
            manager, CERTIFICATION_AUTHORITY_RIGHTS.MANAGE_CA.value, "manager"
        )

    # =========================================================================
    # CA Backup Methods
    # =========================================================================

    def get_enrollment_services(self) -> List[LDAPEntry]:
        """
        Get all enrollment services in the domain.

        Returns:
            List of enrollment service objects
        """
        enrollment_services = self.connection.search(
            "(&(objectClass=pKIEnrollmentService))",
            search_base=f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{self.connection.configuration_path}",
        )
        return enrollment_services

    def get_enrollment_service(self, ca: str) -> Optional[LDAPEntry]:
        """
        Get a specific enrollment service.

        Args:
            ca: CA name

        Returns:
            Enrollment service object or None if not found
        """
        enrollment_services = self.connection.search(
            f"(&(cn={ca})(objectClass=pKIEnrollmentService))",
            search_base=f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{self.connection.configuration_path}",
        )

        if len(enrollment_services) == 0:
            logging.warning(
                f"Could not find any enrollment service identified by {repr(ca)}"
            )
            return None

        return enrollment_services[0]

    def get_backup(self) -> Optional[bytes]:
        """
        Retrieve CA backup file from the target.

        Returns:
            PFX data as bytes or None if retrieval fails
        """
        # Connect to SMB share
        smbclient = SMBConnection(
            self.target.remote_name,
            self.target.target_ip or "",
            timeout=self.target.timeout,
        )

        # Authenticate with appropriate method
        if self.target.do_kerberos:
            tgs, cipher, session_key, username, domain = get_TGS(
                self.target, self.target.remote_name, "cifs"
            )

            TGS = {"KDC_REP": tgs, "cipher": cipher, "sessionKey": session_key}

            _ = smbclient.kerberosLogin(
                username,
                self.target.password,
                domain,
                self.target.lmhash,
                self.target.nthash,
                kdcHost=self.target.dc_ip,
                TGS=TGS,
            )
        else:
            _ = smbclient.login(
                self.target.username,
                self.target.password,
                self.target.domain,
                self.target.lmhash,
                self.target.nthash,
            )

        # Try to connect to C$ or ADMIN$ share
        tid = None
        share = None
        file_path = None

        try:
            share = "C$"
            tid = smbclient.connectTree(share)
            file_path = "\\Windows\\Tasks\\certipy.pfx"
        except Exception as e:
            if "STATUS_BAD_NETWORK_NAME" in str(e):
                tid = None
            else:
                raise e

        # Fall back to ADMIN$ if C$ fails
        if tid is None:
            try:
                share = "ADMIN$"
                tid = smbclient.connectTree(share)
                file_path = "\\Tasks\\certipy.pfx"
            except Exception as e:
                if "STATUS_BAD_NETWORK_NAME" in str(e):
                    raise Exception(
                        f"Could not connect to 'C$' or 'ADMIN$' on {repr(self.target.target_ip)}"
                    )
                else:
                    raise e

        pfx = None

        # Callback to store PFX data
        def _read_pfx(data: bytes):
            nonlocal pfx
            logging.info("Got certificate and private key")
            pfx = data

        # Download PFX file
        try:
            _ = smbclient.getFile(share, file_path, _read_pfx)
        except Exception as e:
            if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                logging.error(
                    "Could not find the certificate and private key. This most likely means that the backup failed"
                )

        # Clean up by deleting the temporary file
        try:
            _ = smbclient.deleteFile(share, file_path)
        except Exception:
            logging.debug(
                f"Failed to delete {file_path} - it may have already been deleted"
            )

        return pfx

    def backup(self) -> bool:
        """
        Create a backup of the CA key and certificate.

        Returns:
            True if successful, False otherwise
        """
        # Connect to service control manager
        dce = get_dce_rpc(
            scmr.MSRPC_UUID_SCMR,  # type: ignore
            "\\pipe\\svcctl",
            self.target,
            timeout=self.timeout,
            dynamic=self.dynamic,
            verbose=self.verbose,
            auth_level_np=rpcrt.RPC_C_AUTHN_LEVEL_NONE,
        )

        if dce is None:
            logging.error(
                "Failed to connect to Service Control Manager Remote Protocol"
            )
            return False

        # Open service manager
        res = scmr.hROpenSCManagerW(dce)
        handle = res["lpScHandle"]

        # Prepare backup command
        config_param = f" -config {self.config}" if self.config else ""
        backup_cmd = (
            "cmd.exe /c certutil"
            + config_param
            + " -backupkey -f -p certipy C:\\Windows\\Tasks\\Certipy && "
            + "move /y C:\\Windows\\Tasks\\Certipy\\* C:\\Windows\\Tasks\\certipy.pfx"
        )

        logging.info("Creating new service for backup operation")
        try:
            # Create service for backup operation
            resp = scmr.hRCreateServiceW(
                dce,
                handle,
                "Certipy",
                "Certipy",
                lpBinaryPathName=backup_cmd,  # type: ignore
                dwStartType=scmr.SERVICE_DEMAND_START,
            )
            service_handle = resp["lpServiceHandle"]
        except Exception as e:
            # Handle case where service already exists
            if "ERROR_SERVICE_EXISTS" in str(e):
                resp = scmr.hROpenServiceW(dce, handle, "Certipy")
                service_handle = resp["lpServiceHandle"]

                # Update existing service with our command
                resp = scmr.hRChangeServiceConfigW(
                    dce,
                    service_handle,
                    lpBinaryPathName=backup_cmd,  # type: ignore
                )
            else:
                raise e

        logging.info("Creating backup")
        try:
            # Start the service to execute our command
            scmr.hRStartServiceW(dce, service_handle)
        except Exception as e:
            # Ignore service-specific errors (usually means it's already running)
            logging.debug(f"Service start returned: {str(e)}")

        logging.info("Retrieving backup")
        try:
            # Get the backup file
            pfx = self.get_backup()
            if pfx:
                # Save raw PFX with password "certipy"
                with open("pfx.p12", "wb") as f:
                    _ = f.write(pfx)

                # Parse and convert to standard PFX format
                key, cert = load_pfx(pfx, b"certipy")

                if cert is None:
                    logging.error("Failed to load certificate from PFX")
                    return False

                if key is None:
                    logging.error("Failed to load private key from PFX")
                    return False

                common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[
                    0
                ]

                # Create new PFX with default password
                pfx = create_pfx(key, cert)

                pfx_out = f"{common_name.value}.pfx"
                with open(pfx_out, "wb") as f:
                    _ = f.write(pfx)

                logging.info(f"Saved certificate and private key to {repr(pfx_out)}")
        except Exception as e:
            logging.error(f"Backup failed: {e}")
            return False

        logging.info("Cleaning up")

        # Clean up: delete temporary files on the server
        cleanup_cmd = "cmd.exe /c del /f /q C:\\Windows\\Tasks\\Certipy\\* && rmdir C:\\Windows\\Tasks\\Certipy"

        # Update and run the service again for cleanup
        resp = scmr.hRChangeServiceConfigW(
            dce,
            service_handle,
            lpBinaryPathName=cleanup_cmd,  # type: ignore
        )

        try:
            scmr.hRStartServiceW(dce, service_handle)
        except Exception:
            pass

        # Remove the temporary service
        scmr.hRDeleteService(dce, service_handle)
        scmr.hRCloseServiceHandle(dce, service_handle)

        return True


def entry(options: argparse.Namespace) -> None:
    """
    Entry point for the 'ca' command.

    Args:
        options: Command-line arguments
    """
    target = Target.from_options(options)
    options.__delattr__("target")

    ca = CA(target, **vars(options))

    # Validate CA name if required
    if not options.backup:
        if not options.ca:
            logging.error("A CA (-ca) is required")
            return

    # Dispatch to appropriate subcommand handler
    if options.backup is True:
        _ = ca.backup()
    elif options.add_officer is not None:
        _ = ca.add_officer(options.add_officer)
    elif options.remove_officer is not None:
        _ = ca.remove_officer(options.remove_officer)
    elif options.add_manager is not None:
        _ = ca.add_manager(options.add_manager)
    elif options.remove_manager is not None:
        _ = ca.remove_manager(options.remove_manager)
    elif options.list_templates:
        _ = ca.list_templates()
    elif options.issue_request is not None:
        ca.request_id = int(options.issue_request)
        _ = ca.issue()
    elif options.deny_request is not None:
        ca.request_id = int(options.deny_request)
        _ = ca.deny()
    elif options.enable_template is not None:
        ca.template = options.enable_template
        _ = ca.enable()
    elif options.disable_template is not None:
        ca.template = options.disable_template
        _ = ca.disable()
    else:
        logging.error("No action specified")
