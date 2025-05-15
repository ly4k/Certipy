"""
Certificate Finder Module for Certipy.

This module allows enumerating Active Directory Certificate Services (AD CS) components:
- Certificate templates
- Certificate authorities
- Certificate issuance policies
- Security permissions and ACLs
- Vulnerability detection for ESC1-15

It provides detailed information about certificate templates, authorities, and security
settings, helping identify misconfiguration and potential attack vectors.
"""

import argparse
import copy
import csv
import io
import json
import time
from collections import OrderedDict
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple, cast

import httpx
import requests
from asn1crypto import x509
from impacket.dcerpc.v5 import rpcrt, rrp

from certipy.lib.constants import (
    EXTENDED_RIGHTS_MAP,
    EXTENDED_RIGHTS_NAME_MAP,
    OID_TO_STR_MAP,
    USER_AGENT,
    ActiveDirectoryRights,
    CertificateAuthorityRights,
    CertificateNameFlag,
    CertificateRights,
    EnrollmentFlag,
    IssuancePolicyRights,
    PrivateKeyFlag,
)
from certipy.lib.errors import handle_error
from certipy.lib.files import try_to_save_file
from certipy.lib.formatting import pretty_print
from certipy.lib.kerberos import HttpxKerberosAuth
from certipy.lib.ldap import LDAPConnection, LDAPEntry
from certipy.lib.logger import is_verbose, logging
from certipy.lib.ntlm import HttpxNtlmAuth
from certipy.lib.rpc import get_dce_rpc_from_string_binding
from certipy.lib.security import (
    CertificateSecurity,
    IssuancePolicySecurity,
    is_admin_sid,
)
from certipy.lib.target import Target
from certipy.lib.time import filetime_to_str

from .ca import CA


class Find:
    def __init__(
        self,
        target: Target,
        json: bool = False,
        csv: bool = False,
        text: bool = False,
        stdout: bool = False,
        output: Optional[str] = None,
        trailing_output: str = "",
        enabled: bool = False,
        oids: bool = False,
        vulnerable: bool = False,
        hide_admins: bool = False,
        sid: Optional[str] = None,
        dn: Optional[str] = None,
        dc_only: bool = False,
        connection: Optional[LDAPConnection] = None,
        **kwargs,  # type: ignore
    ):
        self.target = target
        self.json = json
        self.csv = csv
        self.text = text or stdout
        self.stdout = stdout
        self.output = output
        self.trailing_output = trailing_output
        self.enabled = enabled
        self.oids = oids
        self.vuln = vulnerable
        self.hide_admins = hide_admins
        self.sid = sid
        self.dn = dn
        self.dc_only = dc_only
        self.kwargs = kwargs

        self._connection = connection
        self._user_sids = None

    # =========================================================================
    # Connection Handling
    # =========================================================================

    @property
    def connection(self) -> LDAPConnection:
        """
        Get or create an LDAP connection.

        Returns:
            Active LDAP connection to the target
        """
        if self._connection is not None:
            return self._connection

        self._connection = LDAPConnection(self.target)
        self._connection.connect()

        return self._connection

    @property
    def user_sids(self) -> Set[str]:
        """
        Get current user's SIDs.

        Returns:
            Set of SIDs associated with the current user
        """
        if self._user_sids is None:
            self._user_sids: Optional[Set[str]] = self.connection.get_user_sids(
                self.target.username, self.sid, self.dn
            )

        return self._user_sids

    def open_remote_registry(
        self, target_ip: str, dns_host_name: str
    ) -> Optional[rpcrt.DCERPC_v5]:
        """
        Open a connection to the remote registry service.

        Args:
            target_ip: IP address of the target
            dns_host_name: DNS host name of the target

        Returns:
            DCE/RPC connection to the remote registry or None if failed
        """
        dce = get_dce_rpc_from_string_binding(
            "ncacn_np:445[\\pipe\\winreg]",
            self.target,
            timeout=self.target.timeout,
            target_ip=target_ip,
            remote_name=dns_host_name,
        )

        # Try to connect up to 3 times (registry service might need to start)
        for _ in range(3):
            try:
                dce.connect()
                _ = dce.bind(rrp.MSRPC_UUID_RRP)
                logging.debug(
                    f"Connected to remote registry at {self.target.remote_name!r} ({self.target.target_ip!r})"
                )
                return dce
            except Exception as e:
                if "STATUS_PIPE_NOT_AVAILABLE" in str(e):
                    logging.warning(
                        "Failed to connect to remote registry. Service should be starting now. Trying again..."
                    )
                    time.sleep(2)
                else:
                    raise

        logging.warning("Failed to connect to remote registry after 3 attempts")
        return None

    # =========================================================================
    # LDAP Query Methods
    # =========================================================================

    def get_certificate_templates(self) -> List[LDAPEntry]:
        """
        Query LDAP for certificate templates.

        Returns:
            List of certificate template entries
        """
        return self.connection.search(
            "(objectclass=pKICertificateTemplate)",
            search_base=f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{self.connection.configuration_path}",
            attributes=[
                "cn",
                "name",
                "displayName",
                "pKIExpirationPeriod",
                "pKIOverlapPeriod",
                "msPKI-Enrollment-Flag",
                "msPKI-Private-Key-Flag",
                "msPKI-Certificate-Name-Flag",
                "msPKI-Certificate-Policy",
                "msPKI-Minimal-Key-Size",
                "msPKI-RA-Signature",
                "msPKI-Template-Schema-Version",
                "msPKI-RA-Application-Policies",
                "pKIExtendedKeyUsage",
                "nTSecurityDescriptor",
                "objectGUID",
                "whenCreated",
                "whenChanged",
            ],
            query_sd=True,
        )

    def get_certificate_authorities(self) -> List[LDAPEntry]:
        """
        Query LDAP for certificate authorities.

        Returns:
            List of certificate authority entries
        """
        return self.connection.search(
            "(&(objectClass=pKIEnrollmentService))",
            search_base=f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{self.connection.configuration_path}",
            attributes=[
                "cn",
                "name",
                "dNSHostName",
                "cACertificateDN",
                "cACertificate",
                "certificateTemplates",
                "objectGUID",
            ],
        )

    def get_issuance_policies(self) -> List[LDAPEntry]:
        """
        Query LDAP for issuance policies (OIDs).

        Returns:
            List of issuance policy entries
        """
        return self.connection.search(
            "(objectclass=msPKI-Enterprise-Oid)",
            search_base=f"CN=OID,CN=Public Key Services,CN=Services,{self.connection.configuration_path}",
            attributes=[
                "cn",
                "name",
                "displayName",
                "msDS-OIDToGroupLink",
                "msPKI-Cert-Template-OID",
                "nTSecurityDescriptor",
                "objectGUID",
            ],
            query_sd=True,
        )

    # =========================================================================
    # Main Discovery Method
    # =========================================================================

    def find(self) -> None:
        """
        Discover and analyze AD CS components and detect vulnerabilities.

        This is the main entry point that:
        1. Discovers templates, CAs, and issuance policies
        2. Processes their properties and security settings
        3. Detects vulnerabilities
        4. Outputs results in requested formats
        """
        # Early establish connection

        _connection = self.connection

        # Get user SIDs for vulnerability assessment if needed
        if self.vuln:
            sids = self.user_sids

            if is_verbose():
                logging.debug("List of current user's SIDs:")
                for sid in sids:
                    sid_info = self.connection.lookup_sid(sid)
                    print(f"     {sid_info.get('name')} ({sid_info.get('objectSid')})")

        # Step 1: Query and discover AD CS components
        logging.info("Finding certificate templates")
        templates = self.get_certificate_templates()
        logging.info(
            f"Found {len(templates)} certificate template{'s' if len(templates) != 1 else ''}"
        )

        logging.info("Finding certificate authorities")
        cas = self.get_certificate_authorities()
        logging.info(
            f"Found {len(cas)} certificate authorit{'ies' if len(cas) != 1 else 'y'}"
        )

        # Step 2: Find relationships between CAs and templates
        enabled_templates_count = self._link_cas_and_templates(cas, templates)
        logging.info(
            f"Found {enabled_templates_count} enabled certificate template{'s' if enabled_templates_count != 1 else ''}"
        )

        # Step 3: Find issuance policies and their relationships
        logging.info("Finding issuance policies")
        oids = self.get_issuance_policies()
        logging.info(
            f"Found {len(oids)} issuance polic{'ies' if len(oids) != 1 else 'y'}"
        )

        # Step 4: Link templates to issuance policies
        enabled_oids_count = self._link_templates_and_policies(templates, oids)
        logging.info(
            f"Found {enabled_oids_count} OID{'s' if enabled_oids_count != 1 else ''} "
            f"linked to {'templates' if enabled_oids_count != 1 else 'a template'}"
        )

        # Step 5: Process CA certificates and properties
        self._process_ca_properties(cas)

        # Step 6: Process template properties
        self._process_template_properties(templates)

        # Step 7: Generate and save output
        prefix = (
            datetime.now().strftime("%Y%m%d%H%M%S") if not self.output else self.output
        )
        self._save_output(templates, cas, oids, prefix)

    # =========================================================================
    # Certificate Authority (CA) Methods
    # =========================================================================

    def _link_cas_and_templates(
        self, cas: List[LDAPEntry], templates: List[LDAPEntry]
    ) -> int:
        """
        Link certificate authorities to templates and vice versa.

        Args:
            cas: List of certificate authorities
            templates: List of certificate templates

        Returns:
            Number of enabled templates
        """
        enabled_templates_count = 0

        for ca in cas:
            # Clean GUID format
            object_id = ca.get("objectGUID").lstrip("{").rstrip("}")
            ca.set("object_id", object_id)

            # Get templates enabled on this CA
            ca_templates = ca.get("certificateTemplates") or []

            # Link CA to templates
            for template in templates:
                if template.get("name") in ca_templates:
                    enabled_templates_count += 1

                    # Add CA to template's CA list
                    if "cas" in template["attributes"]:
                        template.get("cas").append(ca.get("name"))
                        template.get("cas_ids").append(object_id)
                    else:
                        template.set("cas", [ca.get("name")])
                        template.set("cas_ids", [object_id])

        return enabled_templates_count

    def _link_templates_and_policies(
        self, templates: List[LDAPEntry], oids: List[LDAPEntry]
    ) -> int:
        """
        Link templates to their issuance policies and vice versa.

        Args:
            templates: List of certificate templates
            oids: List of issuance policies

        Returns:
            Number of enabled OIDs
        """
        enabled_oids_count = 0

        for template in templates:
            # Clean GUID format
            object_id = template.get("objectGUID").lstrip("{").rstrip("}")
            template.set("object_id", object_id)

            # Process issuance policies
            issuance_policies = template.get("msPKI-Certificate-Policy")
            if not isinstance(issuance_policies, list):
                issuance_policies = (
                    [] if issuance_policies is None else [issuance_policies]
                )

            template.set("issuance_policies", issuance_policies)

            # Link OIDs to templates and vice versa
            for oid in oids:
                oid_value = oid.get("msPKI-Cert-Template-OID")
                if oid_value in issuance_policies:
                    enabled_oids_count += 1

                    # Get linked group (if any)
                    linked_group = oid.get("msDS-OIDToGroupLink")

                    # Add template to OID's template list
                    if "templates" in oid["attributes"]:
                        oid.get("templates").append(template.get("name"))
                        oid.get("templates_ids").append(object_id)
                    else:
                        oid.set("templates", [template.get("name")])
                        oid.set("templates_ids", [object_id])

                    # Add linked group info
                    if linked_group:
                        oid.set("linked_group", linked_group)

                        # Add linked group to template
                        if "issuance_policies_linked_groups" in template["attributes"]:
                            template.get("issuance_policies_linked_groups").append(
                                linked_group
                            )
                        else:
                            template.set(
                                "issuance_policies_linked_groups", [linked_group]
                            )

        return enabled_oids_count

    def _process_ca_properties(self, cas: List[LDAPEntry]) -> None:
        """
        Process certificate authority properties and security settings.

        Args:
            cas: List of certificate authorities
        """
        for ca in cas:
            if self.dc_only:
                # In DC-only mode, we don't connect to CAs directly
                ca_properties = {
                    "user_specified_san": "Unknown",
                    "request_disposition": "Unknown",
                    "enforce_encrypt_icertrequest": "Unknown",
                    "security": None,
                    "web_enrollment": {
                        "http": {"enabled": "Unknown"},
                        "https": {"enabled": "Unknown", "channel_binding": None},
                    },
                }

            else:
                # Connect to CA and get configuration
                ca_properties = self._get_ca_config_and_web_enrollment(ca)

            # Apply all properties to the CA object
            for key, value in ca_properties.items():
                ca.set(key, value)

            # Process CA certificate if available
            self._process_ca_certificate(ca)

    def _get_ca_config_and_web_enrollment(self, ca: LDAPEntry) -> Dict[str, Any]:
        """
        Get CA configuration and web enrollment settings.

        Args:
            ca: Certificate authority object

        Returns:
            Dictionary of CA properties
        """
        # Default values
        ca_properties: Dict[str, Any] = {
            "user_specified_san": "Unknown",
            "request_disposition": "Unknown",
            "enforce_encrypt_icertrequest": "Unknown",
            "security": None,
            "web_enrollment": {
                "http": {"enabled": "Unknown"},
                "https": {"enabled": "Unknown", "channel_binding": None},
            },
        }

        ca_name = ca.get("name")
        ca_remote_name = ca.get("dNSHostName")

        try:
            # Get CA hostname and IP
            ca_target_ip = self.target.resolver.resolve(ca_remote_name)

            # Clone target for this CA
            ca_target = copy.copy(self.target)
            ca_target.remote_name = ca_remote_name
            ca_target.target_ip = ca_target_ip

            # Connect to CA and get configuration
            ca_service = CA(ca_target, ca=ca_name)
            ca_configuration = ca_service.get_config()

            active_policy = "Unknown"
            request_disposition = "Unknown"
            user_specified_san = "Unknown"
            enforce_encrypt_icertrequest = "Unknown"
            disabled_extensions = "Unknown"
            security = None

            if ca_configuration is not None:
                active_policy = ca_configuration.active_policy

                # Process request disposition
                request_disposition = (
                    "Pending"
                    if ca_configuration.request_disposition & 0x100
                    else "Issue"
                )

                # Process SAN flag
                user_specified_san = (
                    ca_configuration.edit_flags & 0x00040000
                ) == 0x00040000
                user_specified_san = "Enabled" if user_specified_san else "Disabled"

                # Process encryption flag
                enforce_encrypt = (
                    ca_configuration.interface_flags & 0x00000200
                ) == 0x00000200
                enforce_encrypt_icertrequest = (
                    "Enabled" if enforce_encrypt else "Disabled"
                )

                # TODO: Map to human-readable format
                disabled_extensions = ca_configuration.disable_extension_list

                security = ca_configuration.security

            # Update properties
            ca_properties.update(
                {
                    "active_policy": active_policy,
                    "user_specified_san": user_specified_san,
                    "request_disposition": request_disposition,
                    "enforce_encrypt_icertrequest": enforce_encrypt_icertrequest,
                    "disabled_extensions": disabled_extensions,
                    "security": security,
                }
            )

        except Exception as e:
            logging.warning(
                f"Failed to get CA security and configuration for {ca_name!r}: {e}"
            )
            handle_error(True)

        # Check web enrollment
        logging.info(f"Checking web enrollment for CA {ca_name!r} @ {ca_remote_name!r}")
        try:

            ca_properties["web_enrollment"]["http"]["enabled"] = (
                self.check_web_enrollment(ca, "http")
            )

            https_enabled = self.check_web_enrollment(ca, "https")

            ca_properties["web_enrollment"]["https"]["enabled"] = https_enabled

            if https_enabled:
                # Check channel binding (EPA)
                channel_binding_enabled = self.check_channel_binding(ca)

                ca_properties["web_enrollment"]["https"]["channel_binding"] = (
                    "Unknown"
                    if channel_binding_enabled is None
                    else channel_binding_enabled
                )

        except Exception as e:
            logging.warning(f"Failed to check Web Enrollment for CA {ca_name!r}: {e}")
            handle_error(True)

        return ca_properties

    def _process_ca_certificate(self, ca: LDAPEntry):
        """
        Process CA certificate information.

        Args:
            ca: Certificate authority object
        """
        subject_name = ca.get("cACertificateDN")
        ca.set("subject_name", subject_name)

        try:
            if not ca.get("cACertificate"):
                return

            # Parse the CA certificate
            ca_cert = x509.Certificate.load(ca.get("cACertificate")[0])[
                "tbs_certificate"
            ]

            # Get certificate serial number
            serial_number = hex(int(ca_cert["serial_number"]))[2:].upper()

            # Get certificate validity period
            validity = ca_cert["validity"].native
            validity_start = str(validity["not_before"])
            validity_end = str(validity["not_after"])

            # Set certificate properties
            ca.set("serial_number", serial_number)
            ca.set("validity_start", validity_start)
            ca.set("validity_end", validity_end)

        except Exception as e:
            logging.warning(
                f"Could not parse CA certificate for {ca.get('name')!r}: {e}"
            )
            handle_error(True)

    def check_web_enrollment(self, ca: LDAPEntry, channel: str) -> bool:
        """
        Check if web enrollment is enabled on the CA.

        Args:
            ca: Certificate authority object
            channel: Protocol to check (http or https)

        Returns:
            True if enabled, False if disabled, None if unknown
        """
        target_name = ca.get("dNSHostName")
        target_ip = self.target.resolver.resolve(target_name)

        headers = {
            "User-Agent": USER_AGENT,
            "Host": target_name,
        }

        session = httpx.Client(
            timeout=self.target.timeout,
            verify=False,
        )

        url = f"{channel}://{target_ip}/certsrv/"

        try:
            logging.debug(f"Connecting to {url!r}")

            res = session.get(
                url,
                headers=headers,
                timeout=self.target.timeout,
                follow_redirects=False,
            )

            # 401 indicates authentication required (service is running)
            if res.status_code == 401:
                logging.debug(f"Web enrollment seems enabled over {channel}")
                return True

        except requests.exceptions.Timeout:
            logging.debug(f"Web enrollment seems disabled over {channel}")
            return False

        except Exception as e:
            logging.warning(f"Error checking web enrollment: {e}")
            handle_error(True)

        return False

    def check_channel_binding(self, ca: LDAPEntry) -> Optional[bool]:
        """
        Check if a Certificate Authority web enrollment endpoint enforces channel binding (EPA).

        This method tests HTTPS web enrollment authentication with and without channel binding
        to determine if Extended Protection for Authentication (EPA) is enabled.

        Args:
            ca: LDAP entry for the Certificate Authority

        Returns:
            True if channel binding is enforced
            False if channel binding is disabled
            None if the test was inconclusive or failed
        """
        target_name = ca.get("dNSHostName")
        ca_name = ca.get("name")

        logging.debug(f"Checking channel binding for CA {ca_name!r} ({target_name!r})")

        # Set up connection parameters
        try:
            target_ip = self.target.resolver.resolve(target_name)

            # Create a copy of the target with CA-specific settings
            ca_target = copy.copy(self.target)
            ca_target.remote_name = target_name

            # Select authentication method based on whether Kerberos is enabled
            if self.target.do_kerberos:
                no_cb_auth = HttpxKerberosAuth(ca_target, channel_binding=False)
                cb_auth = HttpxKerberosAuth(ca_target, channel_binding=True)
            else:
                no_cb_auth = HttpxNtlmAuth(ca_target, channel_binding=False)
                cb_auth = HttpxNtlmAuth(ca_target, channel_binding=True)

            url = f"https://{target_ip}/certsrv/"
            headers = {"User-Agent": USER_AGENT, "Host": target_name}

            # First test: Try authentication without channel binding
            no_cb_session = httpx.Client(
                auth=no_cb_auth,
                timeout=self.target.timeout,
                verify=False,
            )

            res_no_cb = no_cb_session.get(
                url,
                headers=headers,
                timeout=self.target.timeout,
                follow_redirects=False,
            )

            logging.debug(
                f"CA {ca_name!r} responds with {res_no_cb.status_code} over HTTPS without channel binding"
            )

            # If non-401 status code, channel binding is likely disabled
            # (server accepted auth without channel binding)
            if res_no_cb.status_code != 401:
                logging.debug("Channel binding (EPA) seems disabled")
                return False

            # Second test: Try authentication with channel binding
            cb_session = httpx.Client(
                auth=cb_auth,
                timeout=self.target.timeout,
                verify=False,
            )

            res_cb = cb_session.get(
                url,
                headers=headers,
                timeout=self.target.timeout,
                follow_redirects=False,
            )

            logging.debug(
                f"CA {ca_name!r} responds with {res_cb.status_code} over HTTPS with channel binding"
            )

            # If status code is not 401, channel binding is likely enabled
            # (server accepted auth with channel binding but not without it)
            if res_cb.status_code != 401:
                logging.debug("Channel binding (EPA) seems enabled")
                return True
            else:
                # Both requests returned 401, likely due to invalid credentials
                logging.warning(
                    "Channel binding (EPA) produces the same response as without it. Perhaps invalid credentials?"
                )
                return None

        except Exception as e:
            logging.warning(f"Failed to check channel binding: {e}")
            handle_error(True)
            return None

    # =========================================================================
    # Certificate Template Methods
    # =========================================================================

    def _process_template_properties(self, templates: List[LDAPEntry]):
        """
        Process certificate template properties.

        Args:
            templates: List of certificate templates
        """
        for template in templates:
            # Set enabled flag
            template_cas = template.get("cas")
            enabled = template_cas is not None and len(template_cas) > 0
            template.set("enabled", enabled)

            # Process validity periods
            self._process_template_validity(template)

            # Process template flags
            self._process_template_flags(template)

            # Process template policies
            self._process_template_policies(template)

    def _process_template_validity(self, template: LDAPEntry):
        """
        Process template validity periods.

        Args:
            template: Certificate template
        """
        # Process expiration period
        expiration_period = template.get("pKIExpirationPeriod")
        if expiration_period is not None:
            validity_period = filetime_to_str(expiration_period)
        else:
            validity_period = 0
        template.set("validity_period", validity_period)

        # Process overlap (renewal) period
        overlap_period = template.get("pKIOverlapPeriod")
        if overlap_period is not None:
            renewal_period = filetime_to_str(overlap_period)
        else:
            renewal_period = 0
        template.set("renewal_period", renewal_period)

    def _process_template_flags(self, template: LDAPEntry):
        """
        Process template flag attributes.

        Args:
            template: Certificate template
        """
        # Process certificate name flags
        certificate_name_flag = template.get("msPKI-Certificate-Name-Flag")
        if certificate_name_flag is not None:
            certificate_name_flag = CertificateNameFlag(int(certificate_name_flag))
        else:
            certificate_name_flag = CertificateNameFlag(0)
        template.set("certificate_name_flag", certificate_name_flag.to_list())

        # Process enrollment flags
        enrollment_flag = template.get("msPKI-Enrollment-Flag")
        if enrollment_flag is not None:
            enrollment_flag = EnrollmentFlag(int(enrollment_flag))
        else:
            enrollment_flag = EnrollmentFlag(0)
        template.set("enrollment_flag", enrollment_flag.to_list())

        # Process private key flags
        private_key_flag = template.get("msPKI-Private-Key-Flag")
        if private_key_flag is not None:
            private_key_flag = PrivateKeyFlag(int(private_key_flag))
        else:
            private_key_flag = PrivateKeyFlag(0)
        template.set("private_key_flag", private_key_flag.to_list())

        # Process signature requirements
        authorized_signatures_required = template.get("msPKI-RA-Signature")
        if authorized_signatures_required is not None:
            authorized_signatures_required = int(authorized_signatures_required)
        else:
            authorized_signatures_required = 0
        template.set("authorized_signatures_required", authorized_signatures_required)

        # Process schema version
        schema_version = template.get("msPKI-Template-Schema-Version")
        if schema_version is not None:
            schema_version = int(schema_version)
        else:
            schema_version = 1
        template.set("schema_version", schema_version)

    def _process_template_policies(self, template: LDAPEntry):
        """
        Process template policy attributes and extended key usage.

        Args:
            template: Certificate template
        """
        # Process application policies
        application_policies = template.get_raw("msPKI-RA-Application-Policies")
        if not isinstance(application_policies, list):
            application_policies = (
                [] if application_policies is None else [application_policies]
            )

        # Convert from bytes to strings and resolve OIDs
        application_policies = [p.decode() for p in application_policies]
        application_policies = [OID_TO_STR_MAP.get(p, p) for p in application_policies]
        template.set("application_policies", application_policies)

        # Process extended key usage (EKU)
        eku = template.get_raw("pKIExtendedKeyUsage")
        if not isinstance(eku, list):
            eku = [] if eku is None else [eku]

        # Convert from bytes to strings and resolve OIDs
        eku = cast(List[str], [e.decode() for e in eku])
        extended_key_usage = [OID_TO_STR_MAP.get(e, e) for e in eku]
        template.set("extended_key_usage", extended_key_usage)

        # Determine template capabilities
        self._determine_template_capabilities(template, extended_key_usage)

    def _determine_template_capabilities(
        self, template: LDAPEntry, extended_key_usage: List[str]
    ):
        """
        Determine template capabilities from EKU and flags.

        Args:
            template: Certificate template
            extended_key_usage: List of extended key usage values
        """
        # Check for "any purpose" EKU
        any_purpose = "Any Purpose" in extended_key_usage or not extended_key_usage
        template.set("any_purpose", any_purpose)

        # Check for client authentication capability
        client_auth_ekus = [
            "Client Authentication",
            "Smart Card Logon",
            "PKINIT Client Authentication",
        ]
        client_authentication = any_purpose or any(
            eku in extended_key_usage for eku in client_auth_ekus
        )
        template.set("client_authentication", client_authentication)

        # Check for enrollment agent capability
        enrollment_agent = (
            any_purpose or "Certificate Request Agent" in extended_key_usage
        )
        template.set("enrollment_agent", enrollment_agent)

        # Check if enrollee can supply subject
        certificate_name_flag = template.get("certificate_name_flag", [])
        enrollee_supplies_subject = any(
            CertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT in flag
            for flag in certificate_name_flag
        )
        template.set("enrollee_supplies_subject", enrollee_supplies_subject)

        # Check if template requires manager approval
        enrollment_flag = template.get("enrollment_flag", [])
        requires_manager_approval = EnrollmentFlag.PEND_ALL_REQUESTS in enrollment_flag
        template.set("requires_manager_approval", requires_manager_approval)

        # Check if template has no security extension
        no_security_extension = EnrollmentFlag.NO_SECURITY_EXTENSION in enrollment_flag
        template.set("no_security_extension", no_security_extension)

        # Check if template requires key archival
        private_key_flag = template.get("private_key_flag", [])
        requires_key_archival = (
            PrivateKeyFlag.REQUIRE_PRIVATE_KEY_ARCHIVAL in private_key_flag
        )
        template.set("requires_key_archival", requires_key_archival)

    # =========================================================================
    # Output Methods
    # =========================================================================

    def _save_output(
        self,
        templates: List[LDAPEntry],
        cas: List[LDAPEntry],
        oids: List[LDAPEntry],
        prefix: str,
    ):
        """
        Generate and save output in requested formats.

        Args:
            templates: List of certificate templates
            cas: List of certificate authorities
            oids: List of issuance policies
            prefix: Output file prefix
        """
        # Determine if default output format should be used
        not_specified = not any([self.json, self.text, self.csv])

        # Generate output for text/JSON formats
        output = self.get_output_for_text_and_json(templates, cas, oids)

        # Save text output
        if self.text or not_specified:
            output_text_stdout = copy.copy(output)

            if self.trailing_output:
                output_text_stdout["ESC14"] = self.trailing_output

            if self.stdout:
                logging.info("Enumeration output:")
                pretty_print(output_text_stdout)
            else:
                output_path = f"{prefix}_Certipy.txt"
                logging.info(f"Saving text output to {output_path!r}")

                f = io.StringIO()
                pretty_print(
                    output_text_stdout,
                    print_func=lambda x: f.write(x + "\n"),
                )

                output_path = try_to_save_file(
                    f.getvalue(),
                    output_path,
                )
                logging.info(f"Wrote text output to {output_path!r}")

        # Save JSON output
        if self.json or not_specified:
            output_path = f"{prefix}_Certipy.json"
            logging.info(f"Saving JSON output to {output_path!r}")

            f = io.StringIO()
            json.dump(
                output,
                f,
                indent=2,
                default=str,
            )

            output_path = try_to_save_file(
                f.getvalue(),
                output_path,
            )
            logging.info(f"Wrote JSON output to {output_path!r}")

        # Save CSV output
        if self.csv:
            # Save templates CSV
            template_output = self.get_template_output_for_csv(output)
            template_output_path = f"{prefix}_Templates_Certipy.csv"
            logging.info(f"Saving templates CSV output to {template_output_path!r}")
            template_output_path = try_to_save_file(
                template_output, template_output_path
            )
            logging.info(f"Wrote templates CSV output to {template_output_path!r}")

            # Save CA CSV
            ca_output = self.get_ca_output_for_csv(output)
            ca_output_path = f"{prefix}_CAs_Certipy.csv"
            logging.info(f"Saving CA CSV output to {ca_output_path!r}")
            ca_output_path = try_to_save_file(ca_output, ca_output_path)
            logging.info(f"Wrote CA CSV output to {ca_output_path!r}")

    def get_output_for_text_and_json(
        self, templates: List[LDAPEntry], cas: List[LDAPEntry], oids: List[LDAPEntry]
    ) -> Dict[str, Any]:
        """
        Generate structured output for text and JSON formats.

        Args:
            templates: List of certificate templates
            cas: List of certificate authorities
            oids: List of issuance policies

        Returns:
            Dictionary containing structured output
        """
        ca_entries = {}
        template_entries = {}
        oids_entries = {}

        # Process templates
        for template in templates:
            # Skip if only showing enabled templates and this one isn't
            if self.enabled and template.get("enabled") is not True:
                continue

            # Get template vulnerabilities
            (vulnerabilities, remarks, enrollable_principals, acl_principals) = (
                self.get_template_vulnerabilities(template)
            )

            # Skip if only showing vulnerable templates and this one isn't
            if self.vuln and not vulnerabilities:
                continue

            # Create entry with properties and permissions
            entry = OrderedDict()
            entry = self.get_template_properties(template, entry)

            # Add permissions
            permissions = self.get_template_permissions(template)
            if permissions:
                entry["Permissions"] = permissions

            # Add enrollable principals
            if enrollable_principals:
                entry["[+] User Enrollable Principals"] = enrollable_principals

            # Add ACL principals
            if acl_principals:
                entry["[+] User ACL Principals"] = acl_principals

            # Add vulnerabilities
            if vulnerabilities:
                entry["[!] Vulnerabilities"] = vulnerabilities

            if remarks:
                entry["[*] Remarks"] = remarks

            # Add entry to collection
            template_entries[len(template_entries)] = entry

        # Process CAs
        for ca in cas:
            # Create entry with properties and permissions
            entry = OrderedDict()
            entry = self.get_ca_properties(ca, entry)

            # Add permissions
            permissions = self.get_ca_permissions(ca)
            if permissions:
                entry["Permissions"] = permissions

            # Add vulnerabilities
            (vulnerabilities, remarks, enrollable_principals, acl_principals) = (
                self.get_ca_vulnerabilities(ca)
            )

            # Add enrollable principals
            if acl_principals:
                entry["[+] User Enrollable Principals"] = enrollable_principals

            # Add ACL principals
            if acl_principals:
                entry["[+] User ACL Principals"] = acl_principals

            # Add vulnerabilities
            if vulnerabilities:
                entry["[!] Vulnerabilities"] = vulnerabilities

            # Add CA certificate properties
            if remarks:
                entry["[*] Remarks"] = remarks

            # Add entry to collection
            ca_entries[len(ca_entries)] = entry

        # Process OIDs if requested
        if self.oids:
            for oid in oids:
                # Get OID vulnerabilities
                (vulnerabilities, acl_principals) = self.get_oid_vulnerabilities(oid)

                # Skip if only showing vulnerable OIDs and this one isn't
                if self.vuln and not vulnerabilities:
                    continue

                # Create entry with properties and permissions
                entry = OrderedDict()
                entry = self.get_oid_properties(oid, entry)

                # Add permissions
                permissions = self.get_oid_permissions(oid)
                if permissions:
                    entry["Permissions"] = permissions

                # Add ACL principals
                if acl_principals:
                    entry["[+] User ACL Principals"] = acl_principals

                # Add vulnerabilities
                if vulnerabilities:
                    entry["[!] Vulnerabilities"] = vulnerabilities

                # Add entry to collection
                oids_entries[len(oids_entries)] = entry

        # Build final output dictionary
        output = {}

        # Add CAs
        if not ca_entries:
            output["Certificate Authorities"] = "[!] Could not find any CAs"
        else:
            output["Certificate Authorities"] = ca_entries

        # Add templates
        if not template_entries:
            output["Certificate Templates"] = (
                "[!] Could not find any certificate templates"
            )
        else:
            output["Certificate Templates"] = template_entries

        # Add OIDs if requested
        if self.oids:
            if not oids_entries:
                output["Issuance Policies"] = "[!] Could not find any issuance policy"
            else:
                output["Issuance Policies"] = oids_entries

        return output

    def get_ca_output_for_csv(self, output: Dict[str, Any]) -> str:
        """
        Convert Certificate Authority data to CSV format.

        This function transforms nested CA data into a flattened CSV format.
        It handles complex nested structures like permissions and web enrollment
        settings in a way that makes them readable in CSV format.

        Args:
            output: Dictionary containing CA data (from get_output_for_text_and_json)

        Returns:
            String containing CSV-formatted data
        """
        # Column order for the CSV output (determines which fields to include and their order)
        column_order = [
            "CA Name",
            "DNS Name",
            "Certificate Subject",
            "Certificate Serial Number",
            "Certificate Validity Start",
            "Certificate Validity End",
            "User Specified SAN",
            "Request Disposition",
            "Enforce Encryption for Requests",
            "Web Enrollment HTTP",
            "Web Enrollment HTTPS",
            "Channel Binding",
            "Owner",
            "Manage CA Principals",
            "Manage Certificates Principals",
            "[!] Vulnerabilities",
        ]

        # Create CSV writer with semicolon delimiter and quote all fields
        csvfile = io.StringIO(newline="")
        writer = csv.DictWriter(
            csvfile,
            fieldnames=column_order,
            extrasaction="ignore",  # Ignore fields not in column_order
            delimiter=";",
            quoting=csv.QUOTE_ALL,
        )

        # Write header row
        writer.writeheader()

        # Check if we have valid CA data
        if not isinstance(output.get("Certificate Authorities"), dict):
            logging.warning("No certificate authority data available for CSV export")
            return csvfile.getvalue()

        try:
            # Process each CA and flatten its structure
            ca_rows = [
                self._flatten_ca_data(output["Certificate Authorities"][id_])
                for id_ in output["Certificate Authorities"]
            ]

            # Write all rows to CSV
            writer.writerows(ca_rows)
            return csvfile.getvalue()

        except Exception as e:
            logging.error(f"Error generating CA CSV data: {e}")
            handle_error()
            return csvfile.getvalue()

    def _flatten_ca_data(self, ca_entry: Dict[str, Any]) -> Dict[str, str]:
        """
        Flatten a nested CA dictionary for CSV output.

        Handles special cases like permissions dictionaries, web enrollment settings,
        and list values by converting them to appropriate string representations.

        Args:
            ca_entry: Dictionary containing CA data

        Returns:
            Flattened dictionary with string values suitable for CSV
        """
        items = []

        # Process each field in the CA entry
        for key, value in ca_entry.items():
            # Handle web enrollment specially
            if key == "Web Enrollment" and isinstance(value, dict):
                # Extract HTTP status
                if (
                    "http" in value
                    and isinstance(value["http"], dict)
                    and "enabled" in value["http"]
                ):
                    http_status = "Enabled" if value["http"]["enabled"] else "Disabled"
                    items.append(("Web Enrollment HTTP", http_status))

                # Extract HTTPS status
                if "https" in value and isinstance(value["https"], dict):
                    if "enabled" in value["https"]:
                        https_status = (
                            "Enabled" if value["https"]["enabled"] else "Disabled"
                        )
                        items.append(("Web Enrollment HTTPS", https_status))

                    # Extract channel binding status
                    if "channel_binding" in value["https"]:
                        cb_status = "Unknown"
                        if value["https"]["channel_binding"] is True:
                            cb_status = "Enabled"
                        elif value["https"]["channel_binding"] is False:
                            cb_status = "Disabled"
                        items.append(("Channel Binding", cb_status))

            # Handle permissions specially
            elif "Permissions" in key and isinstance(value, dict):
                # Process owner
                if "Owner" in value:
                    items.append(("Owner", str(value["Owner"])))

                # Process access rights
                if "Access Rights" in value and isinstance(
                    value["Access Rights"], dict
                ):
                    access_rights = value["Access Rights"]

                    # Process Manage CA permissions
                    if "Manage CA" in access_rights and isinstance(
                        access_rights["Manage CA"], list
                    ):
                        items.append(
                            (
                                "Manage CA Principals",
                                "\n".join(access_rights["Manage CA"]),
                            )
                        )

                    # Process Manage Certificates permissions
                    if "Manage Certificates" in access_rights and isinstance(
                        access_rights["Manage Certificates"], list
                    ):
                        items.append(
                            (
                                "Manage Certificates Principals",
                                "\n".join(access_rights["Manage Certificates"]),
                            )
                        )

            # Handle vulnerabilities specially
            elif "[!] Vulnerabilities" in key and isinstance(value, dict):
                vuln_list = [f"{k}: {v}" for k, v in value.items()]
                items.append((key, "\n".join(vuln_list)))

            # Handle dictionaries (convert to "key: value" format)
            elif isinstance(value, dict):
                formatted_value = ", ".join([f"{k}: {v}" for k, v in value.items()])
                items.append((key, formatted_value))

            # Handle lists (join with newlines for better CSV reading)
            elif isinstance(value, list):
                items.append((key, "\n".join(map(str, value))))

            # Handle simple values
            else:
                items.append((key, str(value) if value is not None else ""))

        return dict(items)

    def get_template_output_for_csv(self, output: Dict[str, Any]) -> str:
        """
        Convert certificate template data to CSV format.

        This function transforms nested certificate templates data into a flattened CSV format.
        It handles complex nested structures like permissions and lists in a way that makes them
        readable in CSV format.

        Args:
            output: Dictionary containing certificate template data (from get_output_for_text_and_json)

        Returns:
            String containing CSV-formatted data

        Raises:
            ValueError: If certificate template data is malformed or missing
        """
        # Column order for the CSV output (determines which fields to include and their order)
        column_order = [
            "Template Name",
            "Display Name",
            "Certificate Authorities",
            "Enabled",
            "Client Authentication",
            "Enrollment Agent",
            "Any Purpose",
            "Enrollee Supplies Subject",
            "Certificate Name Flag",
            "Enrollment Flag",
            "Private Key Flag",
            "Extended Key Usage",
            "Requires Manager Approval",
            "Requires Key Archival",
            "Authorized Signatures Required",
            "Validity Period",
            "Renewal Period",
            "Minimum RSA Key Length",
            "Enrollment Permissions",
            "Owner",
            "Write Owner Principals",
            "Write Dacl Principals",
            "Write Property Principals",
            "[!] Vulnerabilities",
        ]

        # Create CSV writer with semicolon delimiter and quote all fields
        csvfile = io.StringIO(newline="")
        writer = csv.DictWriter(
            csvfile,
            fieldnames=column_order,
            extrasaction="ignore",  # Ignore fields not in column_order
            delimiter=";",
            quoting=csv.QUOTE_ALL,
        )

        # Write header row
        writer.writeheader()

        # Check if we have valid template data
        if not isinstance(output.get("Certificate Templates"), dict):
            logging.warning("No certificate templates data available for CSV export")
            return csvfile.getvalue()

        try:
            # Process each template and flatten its structure
            template_rows = [
                self._flatten_template_data(output["Certificate Templates"][id_])
                for id_ in output["Certificate Templates"]
            ]

            # Write all rows to CSV
            writer.writerows(template_rows)
            return csvfile.getvalue()

        except Exception as e:
            logging.error(f"Error generating CSV data: {e}")
            handle_error()
            return csvfile.getvalue()

    def _flatten_template_data(self, template_entry: Dict[str, Any]) -> Dict[str, str]:
        """
        Flatten a nested template dictionary for CSV output.

        Handles special cases like permissions dictionaries, nested objects,
        and list values by converting them to appropriate string representations.

        Args:
            template_entry: Dictionary containing template data

        Returns:
            Flattened dictionary with string values suitable for CSV
        """
        items = []

        # Process each field in the template
        for key, value in template_entry.items():
            # Handle permissions specially
            if "Permissions" in key and isinstance(value, dict):
                for section_name, section_data in value.items():
                    if "Enrollment Permissions" in section_name:
                        # Extract enrollment rights
                        if (
                            isinstance(section_data, dict)
                            and "Enrollment Rights" in section_data
                        ):
                            items.append(
                                (
                                    section_name,
                                    "\n".join(section_data["Enrollment Rights"]),
                                )
                            )
                    elif "Object Control Permissions" in section_name:
                        # Process each permission type
                        for perm_name, principals in section_data.items():
                            if isinstance(principals, list):
                                items.append((perm_name, "\n".join(principals)))
                            else:
                                items.append((perm_name, str(principals)))
            # Handle dictionaries (convert to "key: value" format)
            elif isinstance(value, dict):
                formatted_value = ", ".join([f"{k}: {v}" for k, v in value.items()])
                items.append((key, formatted_value))
            # Handle lists (join with newlines for better CSV reading)
            elif isinstance(value, list):
                items.append((key, "\n".join(map(str, value))))
            # Handle simple values
            else:
                items.append((key, str(value) if value is not None else ""))

        return dict(items)

    # =========================================================================
    # Property Extraction Methods
    # =========================================================================

    def get_template_properties(
        self, template: LDAPEntry, template_properties: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Extract template properties for output.

        Args:
            template: Certificate template
            template_properties: Optional existing properties dictionary

        Returns:
            Dictionary of template properties
        """
        # Map of template properties to display names
        properties_map = {
            "cn": "Template Name",
            "displayName": "Display Name",
            "cas": "Certificate Authorities",
            "enabled": "Enabled",
            "client_authentication": "Client Authentication",
            "enrollment_agent": "Enrollment Agent",
            "any_purpose": "Any Purpose",
            "enrollee_supplies_subject": "Enrollee Supplies Subject",
            "certificate_name_flag": "Certificate Name Flag",
            "enrollment_flag": "Enrollment Flag",
            "private_key_flag": "Private Key Flag",
            "extended_key_usage": "Extended Key Usage",
            "requires_manager_approval": "Requires Manager Approval",
            "requires_key_archival": "Requires Key Archival",
            "application_policies": "RA Application Policies",
            "authorized_signatures_required": "Authorized Signatures Required",
            "schema_version": "Schema Version",
            "validity_period": "Validity Period",
            "renewal_period": "Renewal Period",
            "msPKI-Minimal-Key-Size": "Minimum RSA Key Length",
            "whenCreated": "Template Created",
            "whenChanged": "Template Last Modified",
            "msPKI-Certificate-Policy": "Issuance Policies",
            "issuance_policies_linked_groups": "Linked Groups",
        }

        # Create properties dictionary
        if template_properties is None:
            template_properties = OrderedDict()

        # Extract properties that exist
        for property_key, display_name in properties_map.items():
            property_value = template.get(property_key)
            if property_value is not None:
                template_properties[display_name] = property_value

        return template_properties

    def get_ca_properties(
        self, ca: LDAPEntry, ca_properties: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Extract CA properties for output.

        Args:
            ca: Certificate authority
            ca_properties: Optional existing properties dictionary

        Returns:
            Dictionary of CA properties
        """
        # Map of CA properties to display names
        properties_map = {
            "name": "CA Name",
            "dNSHostName": "DNS Name",
            "cACertificateDN": "Certificate Subject",
            "serial_number": "Certificate Serial Number",
            "validity_start": "Certificate Validity Start",
            "validity_end": "Certificate Validity End",
            "web_enrollment": "Web Enrollment",
            "user_specified_san": "User Specified SAN",
            "request_disposition": "Request Disposition",
            "enforce_encrypt_icertrequest": "Enforce Encryption for Requests",
            "active_policy": "Active Policy",
            "disabled_extensions": "Disabled Extensions",
        }

        # Create properties dictionary
        if ca_properties is None:
            ca_properties = OrderedDict()

        # Extract properties that exist
        for property_key, display_name in properties_map.items():
            property_value = ca.get(property_key)
            if property_value is not None:
                ca_properties[display_name] = property_value

        return ca_properties

    def get_oid_properties(
        self, oid: LDAPEntry, oid_properties: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Extract OID properties for output.

        Args:
            oid: Issuance policy object
            oid_properties: Optional existing properties dictionary

        Returns:
            Dictionary of OID properties
        """
        # Map of OID properties to display names
        properties_map = {
            "cn": "Issuance Policy Name",
            "displayName": "Display Name",
            "templates": "Certificate Template(s)",
            "linked_group": "Linked Group",
        }

        # Create properties dictionary
        if oid_properties is None:
            oid_properties = OrderedDict()

        # Extract properties that exist
        for property_key, display_name in properties_map.items():
            property_value = oid.get(property_key)
            if property_value is not None:
                oid_properties[display_name] = property_value

        return oid_properties

    # =========================================================================
    # Permission Extraction Methods
    # =========================================================================

    def get_template_permissions(self, template: LDAPEntry) -> Dict[str, Any]:
        """
        Extract template permissions for output.

        Args:
            template: Certificate template

        Returns:
            Dictionary of template permissions
        """
        security = CertificateSecurity(template.get("nTSecurityDescriptor"))
        permissions = {}

        # Process enrollment permissions
        enrollment_permissions = {}
        enrollment_rights = []
        all_extended_rights = []

        for sid, rights in security.aces.items():
            # Skip admin principals if requested
            if self.hide_admins and is_admin_sid(sid):
                continue

            # Check for Enroll right
            has_enroll = (rights["rights"] & ActiveDirectoryRights.EXTENDED_RIGHT) and (
                EXTENDED_RIGHTS_NAME_MAP["Enroll"] in rights["extended_rights"]
            )
            if has_enroll:
                enrollment_rights.append(self.connection.lookup_sid(sid).get("name"))

            # Check for All-Extended-Rights
            has_all_rights = (
                rights["rights"] & ActiveDirectoryRights.EXTENDED_RIGHT
            ) and (
                EXTENDED_RIGHTS_NAME_MAP["All-Extended-Rights"]
                in rights["extended_rights"]
            )
            if has_all_rights:
                all_extended_rights.append(self.connection.lookup_sid(sid).get("name"))

        # Add enrollment rights
        if enrollment_rights:
            enrollment_permissions["Enrollment Rights"] = enrollment_rights

        # Add all extended rights
        if all_extended_rights:
            enrollment_permissions["All Extended Rights"] = all_extended_rights

        # Add enrollment permissions
        if enrollment_permissions:
            permissions["Enrollment Permissions"] = enrollment_permissions

        # Process object control permissions
        object_control_permissions = {}

        # Add owner
        if not self.hide_admins or not is_admin_sid(security.owner):
            object_control_permissions["Owner"] = self.connection.lookup_sid(
                security.owner
            ).get("name")

        # Add rights mappings
        rights_mapping = [
            (CertificateRights.GENERIC_ALL, [], "Full Control Principals"),
            (CertificateRights.WRITE_OWNER, [], "Write Owner Principals"),
            (CertificateRights.WRITE_DACL, [], "Write Dacl Principals"),
        ]

        # Process write property permissions
        write_permissions = {}
        for sid, rights in security.aces.items():
            # Skip admin principals if requested
            if self.hide_admins and is_admin_sid(sid):
                continue

            # Get rights information
            extended_rights = rights["extended_rights"]
            ad_rights = rights["rights"]
            principal_name = self.connection.lookup_sid(sid).get("name")

            # Check for each standard right type
            for right, principal_list, _ in rights_mapping:
                if right in ad_rights and (
                    ad_rights & ActiveDirectoryRights.EXTENDED_RIGHT
                ):
                    principal_list.append(principal_name)

            # Check for write property rights
            can_write_property = (CertificateRights.WRITE_PROPERTY in ad_rights) and (
                ad_rights & ActiveDirectoryRights.EXTENDED_RIGHT
            )
            if can_write_property:
                for extended_right in extended_rights:
                    # Resolve extended right name
                    resolved_right = EXTENDED_RIGHTS_MAP.get(
                        extended_right, extended_right
                    )

                    # Add principal to the list for this right
                    principal_list = write_permissions.get(resolved_right, [])
                    if principal_name not in principal_list:
                        principal_list.append(principal_name)
                    write_permissions[resolved_right] = principal_list

        # Add write property rights
        for extended_right, principal_list in write_permissions.items():
            rights_mapping.append(
                (
                    CertificateRights.WRITE_PROPERTY,
                    principal_list,
                    f"Write Property {extended_right}",
                )
            )

        # Add all rights to permissions
        for _, principal_list, name in rights_mapping:
            if principal_list:
                object_control_permissions[name] = principal_list

        # Add object control permissions
        if object_control_permissions:
            permissions["Object Control Permissions"] = object_control_permissions

        return permissions

    def get_ca_permissions(self, ca: LDAPEntry) -> Dict[str, Any]:
        """
        Extract CA permissions for output.

        Args:
            ca: Certificate authority

        Returns:
            Dictionary of CA permissions
        """
        security = ca.get("security")
        if security is None:
            return {}

        ca_permissions = {}
        access_rights = {}

        # Add owner
        if not self.hide_admins or not is_admin_sid(security.owner):
            ca_permissions["Owner"] = self.connection.lookup_sid(security.owner).get(
                "name"
            )

        # Process ACEs
        for sid, rights in security.aces.items():
            # Skip admin principals if requested
            if self.hide_admins and is_admin_sid(sid):
                continue

            # Get principal name
            principal_name = self.connection.lookup_sid(sid).get("name")

            # Get list of rights
            ca_rights = rights["rights"].to_list()

            # Add each right to the access rights dictionary
            for ca_right in ca_rights:
                if ca_right not in access_rights:
                    access_rights[ca_right] = [principal_name]
                else:
                    access_rights[ca_right].append(principal_name)

        # Add access rights
        if access_rights:
            ca_permissions["Access Rights"] = access_rights

        return ca_permissions

    def get_oid_permissions(self, oid: LDAPEntry) -> Dict[str, Any]:
        """
        Extract OID permissions for output.

        Args:
            oid: Issuance policy object

        Returns:
            Dictionary of OID permissions
        """
        nt_security_descriptor = oid.get("nTSecurityDescriptor")
        if nt_security_descriptor is None:
            return {}

        security = IssuancePolicySecurity(nt_security_descriptor)

        oid_permissions = {}
        access_rights = {}

        # Add owner
        if not self.hide_admins or not is_admin_sid(security.owner):
            oid_permissions["Owner"] = self.connection.lookup_sid(security.owner).get(
                "name"
            )

        # Process ACEs
        for sid, rights in security.aces.items():
            # Skip admin principals if requested
            if self.hide_admins and is_admin_sid(sid):
                continue

            # Get principal name
            principal_name = self.connection.lookup_sid(sid).get("name")

            # Get list of rights
            oid_rights = rights["rights"].to_list()

            # Add each right to the access rights dictionary
            for oid_right in oid_rights:
                if oid_right not in access_rights:
                    access_rights[oid_right] = [principal_name]
                else:
                    access_rights[oid_right].append(principal_name)

        # Add access rights
        if access_rights:
            oid_permissions["Access Rights"] = access_rights

        return oid_permissions

    # =========================================================================
    # Vulnerability Detection Methods
    # =========================================================================

    def get_template_vulnerabilities(
        self, template: LDAPEntry
    ) -> Tuple[Dict[str, str], Dict[str, str], List[str], List[str]]:
        """
        Detect vulnerabilities in certificate templates.

        This method checks for various Enterprise Security Configuration (ESC) vulnerabilities:
        - ESC1: Client authentication template with enrollee-supplied subject
        - ESC2: Template that allows any purpose
        - ESC3: Template with Certificate Request Agent EKU or vulnerable configuration
        - ESC4: Template with dangerous permissions or owned by current user
        - ESC9: Template with no security extension
        - ESC13: Template linked to a group through issuance policy
        - ESC15: Schema v1 template with enrollee-supplied subject (CVE-2024-49019)

        Args:
            template: Certificate template to analyze

        Returns:
            Tuple of detected vulnerabilities, remarks, enrollable principals, and ACL principals
        """
        # Return cached vulnerabilities if already processed
        if template.get("vulnerabilities"):
            return template.get("vulnerabilities")

        vulnerabilities = {}
        remarks = {}
        enrollable_principals = []
        acl_principals = []
        user_can_enroll, enrollable_sids = self.can_user_enroll_in_template(template)
        is_enabled = template.get("enabled", False)

        # Skip enrollment-based vulnerability checks if user can't enroll or
        # if template requires approval or signatures
        requires_approval = (
            template.get("requires_manager_approval")
            or template.get("authorized_signatures_required", 0) > 0
        )

        if is_enabled and user_can_enroll:
            enrollable_principals = self.format_principals(enrollable_sids)

            if not requires_approval:
                # ESC1: Client authentication with enrollee-supplied subject
                if template.get("enrollee_supplies_subject") and template.get(
                    "client_authentication"
                ):
                    vulnerabilities["ESC1"] = (
                        f"Enrollee supplies subject "
                        "and template allows client authentication."
                    )

                # ESC2: Any purpose template
                if template.get("any_purpose"):
                    vulnerabilities["ESC2"] = f"Template can be used for any purpose."

                # ESC3: Certificate Request Agent
                if template.get("enrollment_agent"):
                    vulnerabilities["ESC3"] = (
                        f"Template has Certificate Request Agent EKU set."
                    )

                # ESC9: No security extension
                if template.get("no_security_extension") and template.get(
                    "client_authentication"
                ):
                    vulnerabilities["ESC9"] = f"Template has no security extension."
                    remarks["ESC9"] = (
                        "Other prerequisites may be required for this to be exploitable. See "
                        "the wiki for more details."
                    )

                # ESC13: Template with issuance policy linked to a group
                if (
                    template.get("client_authentication")
                    and template.get("msPKI-Certificate-Policy")
                    and template.get("issuance_policies_linked_groups")
                ):
                    groups = template.get("issuance_policies_linked_groups")
                    if not isinstance(groups, list):
                        groups = [groups]

                    if len(groups) == 1:
                        vulnerabilities["ESC13"] = (
                            f"Template allows client authentication "
                            f"and issuance policy is linked to group {groups[0]!r}."
                        )
                    else:
                        vulnerabilities["ESC13"] = (
                            f"Template allows client authentication "
                            f"and issuance policy is linked to groups {groups!r}."
                        )

                # ESC15: Schema v1 template with enrollee-supplied subject (CVE-2024-49019)
                if (
                    template.get("enrollee_supplies_subject")
                    and template.get("schema_version") == 1
                ):
                    vulnerabilities["ESC15"] = (
                        f"Enrollee supplies subject and " "schema version is 1."
                    )
                    remarks["ESC15"] = (
                        f"Only applicable if the environment has not been patched. "
                        "See CVE-2024-49019 or the wiki for more details."
                    )

            # ESC2 Target: Schema v1 or requires Any Purpose signature
            if template.get("client_authentication") and (
                template.get("schema_version") == 1
                or (
                    template.get("schema_version") > 1
                    and template.get("authorized_signatures_required") > 0
                    and template.get("application_policies") is not None
                    and "Any Purpose" in template.get("application_policies")
                )
            ):
                reason = "has schema version 1"
                if template.get("schema_version") != 1:
                    reason = (
                        "requires a signature with the Any Purpose application policy"
                    )

                remarks["ESC2 Target Template"] = (
                    "Template can be targeted as part of ESC2 exploitation. This is not a vulnerability "
                    f"by itself. See the wiki for more details. Template {reason}."
                )

            # ESC3 Target: Schema v1 or requires Certificate Request Agent signature
            if template.get("client_authentication") and (
                template.get("schema_version") == 1
                or (
                    template.get("schema_version") > 1
                    and template.get("authorized_signatures_required") > 0
                    and template.get("application_policies") is not None
                    and "Certificate Request Agent"
                    in template.get("application_policies")
                )
            ):
                reason = "has schema version 1"
                if template.get("schema_version") != 1:
                    reason = "requires a signature with the Certificate Request Agent application policy"

                remarks["ESC3 Target Template"] = (
                    "Template can be targeted as part of ESC3 exploitation. This is not a vulnerability "
                    f"by itself. See the wiki for more details. Template {reason}."
                )

        # ESC4: Template ownership or vulnerable ACL
        security = CertificateSecurity(template.get("nTSecurityDescriptor"))
        user_sids = self.connection.get_user_sids(
            self.target.username, self.sid, self.dn
        )

        # Check if user owns the template
        if security.owner in user_sids:
            owner_name = self.connection.lookup_sid(security.owner).get("name")
            acl_principals = [owner_name]
            vulnerabilities["ESC4"] = f"Template is owned by user."
        else:
            # Check for vulnerable permissions if not already owner
            has_vulnerable_acl, vulnerable_acl_sids = self.template_has_vulnerable_acl(
                template
            )
            acl_principals = self.format_principals(vulnerable_acl_sids)
            if has_vulnerable_acl:
                vulnerabilities["ESC4"] = "User has dangerous permissions."

        return (vulnerabilities, remarks, enrollable_principals, acl_principals)

    def template_has_vulnerable_acl(
        self, template: LDAPEntry
    ) -> Tuple[bool, List[str]]:
        """
        Check if the template has vulnerable permissions for the current user.

        Args:
            template: Certificate template to analyze

        Returns:
            Tuple of (has_vulnerable_acl, list_of_vulnerable_sids)
        """
        security = CertificateSecurity(template.get("nTSecurityDescriptor"))
        user_sids = self.connection.get_user_sids(
            self.target.username, self.sid, self.dn
        )

        vulnerable_acl_sids = []
        has_vulnerable_acl = False

        # Check ACEs for vulnerable permissions
        for sid, rights in security.aces.items():
            # Skip if not related to current user
            if sid not in user_sids:
                continue

            ad_rights = rights["rights"]
            ad_extended_rights = rights["extended_rights"]

            # Check for dangerous permissions
            dangerous_rights = [
                CertificateRights.GENERIC_ALL,
                CertificateRights.WRITE_OWNER,
                CertificateRights.WRITE_DACL,
                CertificateRights.GENERIC_WRITE,
            ]

            if any(right in ad_rights for right in dangerous_rights):
                vulnerable_acl_sids.append(sid)
                has_vulnerable_acl = True
                continue

            # WRITE_PROPERTY is only dangerous if you can write the entire object
            if (
                CertificateRights.WRITE_PROPERTY in ad_rights
                and "00000000-0000-0000-0000-000000000000" in ad_extended_rights
                and ad_rights & ActiveDirectoryRights.EXTENDED_RIGHT
            ):
                vulnerable_acl_sids.append(sid)
                has_vulnerable_acl = True

        return has_vulnerable_acl, list(set(vulnerable_acl_sids))  # Deduplicate SIDs

    def can_user_enroll_in_template(
        self, template: LDAPEntry
    ) -> Tuple[bool, List[str]]:
        """
        Check if the current user can enroll in the template.

        Args:
            template: Certificate template to analyze

        Returns:
            Tuple of (can_enroll, list_of_enrollable_sids)
        """
        security = CertificateSecurity(template.get("nTSecurityDescriptor"))
        user_sids = self.connection.get_user_sids(
            self.target.username, self.sid, self.dn
        )

        enrollable_sids = []
        user_can_enroll = False

        # Check ACEs for enrollment rights
        for sid, rights in security.aces.items():
            if sid not in user_sids:
                continue

            # Check for enrollment rights (All-Extended-Rights, Enroll, or Generic All)
            if (
                (
                    EXTENDED_RIGHTS_NAME_MAP["All-Extended-Rights"]
                    in rights["extended_rights"]
                    and rights["rights"] & ActiveDirectoryRights.EXTENDED_RIGHT
                )
                or (
                    EXTENDED_RIGHTS_NAME_MAP["Enroll"] in rights["extended_rights"]
                    and rights["rights"] & ActiveDirectoryRights.EXTENDED_RIGHT
                )
                or CertificateRights.GENERIC_ALL in rights["rights"]
            ):
                enrollable_sids.append(sid)
                user_can_enroll = True

        return user_can_enroll, list(set(enrollable_sids))  # Deduplicate SIDs

    def get_ca_vulnerabilities(
        self, ca: LDAPEntry
    ) -> Tuple[Dict[str, str], Dict[str, str], List[str], List[str]]:
        """
        Detect vulnerabilities in certificate authorities.

        This method checks for various Enterprise Security Configuration (ESC) vulnerabilities:
        - ESC6: CA allows user-specified SAN and auto-issues certificates
        - ESC7: CA with dangerous permissions
        - ESC8: Insecure web enrollment
        - ESC11: Unencrypted certificate requests

        Args:
            ca: Certificate authority to analyze

        Returns:
            Tuple of detected vulnerabilities, remarks, enrollable principals, and ACL principals
        """
        # Return cached vulnerabilities if already processed
        if ca.get("vulnerabilities"):
            return ca.get("vulnerabilities")

        vulnerabilities = {}
        remarks = {}
        acl_principals = []
        request_disposition = ca.get("request_disposition")
        will_issue = request_disposition in ["Issue", "Unknown"]
        user_can_enroll, enrollable_sids = self.can_user_enroll_in_ca(ca)

        enrollable_principals = self.format_principals(enrollable_sids)

        # ESC6: User-specified SAN with auto-issuance
        if ca.get("user_specified_san") == "Enabled" and will_issue and user_can_enroll:
            vulnerabilities["ESC6"] = "Enrollee can specify SAN."
            remarks["ESC6"] = (
                "Other prerequisites may be required for this to be exploitable. See "
                "the wiki for more details."
            )

        if ca.get("active_policy") != "CertificateAuthority_MicrosoftDefault.Policy":
            remarks["Policy"] = "Not using the built-in Microsoft default policy."

        # ESC7: CA with dangerous permissions
        has_vulnerable_acl, vulnerable_acl_sids = self.ca_has_vulnerable_acl(ca)
        if has_vulnerable_acl:
            acl_principals = self.format_principals(vulnerable_acl_sids)
            vulnerabilities["ESC7"] = f"User has dangerous permissions."

        # ESC8: Insecure web enrollment
        web_enrollment = ca.get("web_enrollment")
        if web_enrollment and will_issue:
            http_enabled = (
                web_enrollment["http"] is not None
                and web_enrollment["http"]["enabled"]
                and web_enrollment["http"]["enabled"] != "Unknown"
            )
            https_enabled = (
                web_enrollment["https"] is not None
                and web_enrollment["https"]["enabled"]
                and web_enrollment["https"]["enabled"] != "Unknown"
            )
            channel_binding_enforced = (
                web_enrollment["https"] is not None
                and web_enrollment["https"]["channel_binding"]
                and web_enrollment["https"]["channel_binding"] != "Unknown"
            )

            # Determine vulnerability based on protocol and channel binding
            if http_enabled and https_enabled and not channel_binding_enforced:
                vulnerabilities["ESC8"] = (
                    f"Web Enrollment is enabled over HTTP and HTTPS, and Channel Binding is disabled."
                )
            elif http_enabled:
                vulnerabilities["ESC8"] = f"Web Enrollment is enabled over HTTP."
            elif https_enabled and not channel_binding_enforced:
                vulnerabilities["ESC8"] = (
                    f"Web Enrollment is enabled over HTTPS and Channel Binding is disabled."
                )
            elif https_enabled and channel_binding_enforced == "Unknown":
                remarks["ESC8"] = (
                    "Channel Binding couldn't be verified for HTTPS Web Enrollment. "
                    "For manual verification, request a certificate via HTTPS with Channel Binding disabled "
                    "and observe if the request succeeds or is rejected."
                )

        # ESC11: Unencrypted certificate requests
        if ca.get("enforce_encrypt_icertrequest") == "Disabled" and will_issue:
            vulnerabilities["ESC11"] = (
                "Encryption is not enforced for ICPR (RPC) requests."
            )

        # ESC16: Security extension disabled (similar to ESC9)
        disabled_extensions = ca.get("disabled_extensions")
        if disabled_extensions and will_issue and user_can_enroll:
            if "1.3.6.1.4.1.311.25.2" in disabled_extensions:
                vulnerabilities["ESC16"] = "Security Extension is disabled."
                remarks["ESC16"] = (
                    "Other prerequisites may be required for this to be exploitable. See "
                    "the wiki for more details."
                )

        return (vulnerabilities, remarks, enrollable_principals, acl_principals)

    def ca_has_vulnerable_acl(self, ca: LDAPEntry) -> Tuple[bool, List[str]]:
        """
        Check if the CA has vulnerable permissions for the current user.

        Args:
            ca: Certificate authority to analyze

        Returns:
            Tuple of (has_vulnerable_acl, list_of_vulnerable_sids)
        """
        has_vulnerable_acl = False
        vulnerable_acl_sids = []

        security = ca.get("security")
        if security is None:
            return has_vulnerable_acl, vulnerable_acl_sids

        user_sids = self.connection.get_user_sids(
            self.target.username, self.sid, self.dn
        )

        # Check ACEs for vulnerable permissions
        for sid, rights in security.aces.items():
            # Skip if not related to current user
            if sid not in user_sids:
                continue

            ad_rights = rights["rights"]

            # Check for dangerous CA permissions
            dangerous_rights = [
                CertificateAuthorityRights.MANAGE_CA,
                CertificateAuthorityRights.MANAGE_CERTIFICATES,
            ]

            if any(right in ad_rights for right in dangerous_rights):
                vulnerable_acl_sids.append(sid)
                has_vulnerable_acl = True

        return has_vulnerable_acl, list(set(vulnerable_acl_sids))  # Deduplicate SIDs

    def can_user_enroll_in_ca(self, ca: LDAPEntry) -> Tuple[Optional[bool], List[str]]:
        """
        Check if the current user can enroll in the CA.

        Args:
            ca: CA to analyze

        Returns:
            Tuple of (can_enroll, list_of_enrollable_sids)
        """
        security = ca.get("security")
        if security is None:
            return None, []

        user_sids = self.connection.get_user_sids(
            self.target.username, self.sid, self.dn
        )

        enrollable_sids = []
        user_can_enroll = False

        # Process ACEs
        for sid, rights in security.aces.items():
            if sid not in user_sids:
                continue

            if CertificateAuthorityRights.ENROLL in rights["rights"]:
                enrollable_sids.append(sid)
                user_can_enroll = True

        return user_can_enroll, list(set(enrollable_sids))  # Deduplicate SIDs

    def get_oid_vulnerabilities(
        self, oid: LDAPEntry
    ) -> Tuple[Dict[str, str], List[str]]:
        """
        Detect vulnerabilities in issuance policy OIDs.

        This method checks for Enterprise Security Configuration (ESC) vulnerabilities:
        - ESC13: OID with dangerous permissions or owned by current user

        Args:
            oid: Issuance policy OID to analyze

        Returns:
            Tuple of detected vulnerabilities and ACL principals
        """
        # Return cached vulnerabilities if already processed
        if oid.get("vulnerabilities"):
            return oid.get("vulnerabilities")

        vulnerabilities = {}
        acl_principals = []

        # ESC13: OID ownership or vulnerable ACL
        security = IssuancePolicySecurity(oid.get("nTSecurityDescriptor"))
        user_sids = self.connection.get_user_sids(
            self.target.username, self.sid, self.dn
        )

        # Check if user owns the OID
        if security.owner in user_sids:
            owner_name = self.connection.lookup_sid(security.owner).get("name")
            acl_principals = [owner_name]
            vulnerabilities["ESC13"] = f"Issuance Policy OID is owned by user."
        else:
            # Check for vulnerable permissions if not already owner
            has_vulnerable_acl, vulnerable_acl_sids = self.oid_has_vulnerable_acl(oid)
            if has_vulnerable_acl:
                acl_principals = self.format_principals(vulnerable_acl_sids)
                vulnerabilities["ESC13"] = f"User has dangerous permissions."

        return (vulnerabilities, acl_principals)

    def oid_has_vulnerable_acl(self, oid: LDAPEntry) -> Tuple[bool, List[str]]:
        """
        Check if the OID has vulnerable permissions for the current user.

        Args:
            oid: Issuance policy OID to analyze

        Returns:
            Tuple of (has_vulnerable_acl, list_of_vulnerable_sids)
        """
        security = IssuancePolicySecurity(oid.get("nTSecurityDescriptor"))
        user_sids = self.connection.get_user_sids(
            self.target.username, self.sid, self.dn
        )

        vulnerable_acl_sids = []
        has_vulnerable_acl = False

        # Check ACEs for vulnerable permissions
        for sid, rights in security.aces.items():
            # Skip if not related to current user
            if sid not in user_sids:
                continue

            ad_rights = rights["rights"]

            # Check for dangerous OID permissions
            dangerous_rights = [
                IssuancePolicyRights.GENERIC_ALL,
                IssuancePolicyRights.WRITE_OWNER,
                IssuancePolicyRights.WRITE_DACL,
                IssuancePolicyRights.WRITE_PROPERTY,
            ]

            if any(right in ad_rights for right in dangerous_rights):
                vulnerable_acl_sids.append(sid)
                has_vulnerable_acl = True

        return has_vulnerable_acl, list(set(vulnerable_acl_sids))  # Deduplicate SIDs

    def format_principals(self, sids: List[str]) -> List[str]:
        """
        Format a list of SIDs into a human-readable string.

        Args:
            sids: List of SIDs to format

        Returns:
            List of principal names
        """
        return [self.connection.lookup_sid(sid).get("name") for sid in sids]


def entry(options: argparse.Namespace) -> None:
    """
    Entry point for the 'find' command.

    Args:
        options: Command-line arguments
    """
    target = Target.from_options(options, dc_as_target=True)
    options.__delattr__("target")

    find = Find(target=target, **vars(options))
    find.find()
