import argparse
import copy
import json
import os
import socket
import struct
import time
import zipfile
from collections import OrderedDict
from datetime import datetime
from typing import List

from asn1crypto import x509
from certipy.lib.constants import (
    CERTIFICATE_RIGHTS,
    CERTIFICATION_AUTHORITY_RIGHTS,
    EXTENDED_RIGHTS_MAP,
    EXTENDED_RIGHTS_NAME_MAP,
    MS_PKI_CERTIFICATE_NAME_FLAG,
    MS_PKI_ENROLLMENT_FLAG,
    MS_PKI_PRIVATE_KEY_FLAG,
    OID_TO_STR_MAP,
    WELLKNOWN_SIDS,
)
from certipy.lib.formatting import pretty_print
from certipy.lib.ldap import LDAPConnection, LDAPEntry
from certipy.lib.logger import logging
from certipy.lib.rpc import get_dce_rpc_from_string_binding
from certipy.lib.security import (
    ActiveDirectorySecurity,
    CertifcateSecurity,
    is_admin_sid,
)
from certipy.lib.target import Target
from impacket.dcerpc.v5 import rrp

from .ca import CA


def filetime_to_span(filetime: str) -> int:
    (span,) = struct.unpack("<q", filetime)

    span *= -0.0000001

    return int(span)


def span_to_str(span: int) -> str:
    if (span % 31536000 == 0) and (span // 31536000) >= 1:
        if (span / 31536000) == 1:
            return "1 year"
        return "%i years" % (span // 31536000)
    elif (span % 2592000 == 0) and (span // 2592000) >= 1:
        if (span // 2592000) == 1:
            return "1 month"
        else:
            return "%i months" % (span // 2592000)
    elif (span % 604800 == 0) and (span // 604800) >= 1:
        if (span / 604800) == 1:
            return "1 week"
        else:
            return "%i weeks" % (span // 604800)

    elif (span % 86400 == 0) and (span // 86400) >= 1:
        if (span // 86400) == 1:
            return "1 day"
        else:
            return "%i days" % (span // 86400)
    elif (span % 3600 == 0) and (span / 3600) >= 1:
        if (span // 3600) == 1:
            return "1 hour"
        else:
            return "%i hours" % (span // 3600)
    else:
        return ""


def filetime_to_str(filetime: str) -> str:
    return span_to_str(filetime_to_span(filetime))


class Find:
    def __init__(
        self,
        target: Target,
        json: bool = False,
        bloodhound: bool = False,
        old_bloodhound: bool = False,
        text: bool = False,
        stdout: bool = False,
        output: str = None,
        enabled: bool = False,
        vulnerable: bool = False,
        hide_admins: bool = False,
        dc_only: bool = False,
        scheme: str = "ldaps",
        connection: LDAPConnection = None,
        debug=False,
        **kwargs
    ):
        self.target = target
        self.json = json
        self.bloodhound = bloodhound or old_bloodhound
        self.old_bloodhound = old_bloodhound
        self.text = text or stdout
        self.stdout = stdout
        self.output = output
        self.enabled = enabled
        self.vuln = vulnerable
        self.hide_admins = hide_admins
        self.dc_only = dc_only
        self.scheme = scheme
        self.verbose = debug
        self.kwargs = kwargs

        self._connection = connection

    @property
    def connection(self) -> LDAPConnection:
        if self._connection is not None:
            return self._connection

        self._connection = LDAPConnection(self.target, self.scheme)
        self._connection.connect()

        return self._connection

    def open_remote_registry(self, target_ip: str, dns_host_name: str):

        dce = get_dce_rpc_from_string_binding(
            "ncacn_np:445[\\pipe\\winreg]",
            self.target,
            timeout=self.target.timeout,
            target_ip=target_ip,
            remote_name=dns_host_name,
        )

        for _ in range(3):
            try:
                dce.connect()
                dce.bind(rrp.MSRPC_UUID_RRP)
                logging.debug(
                    "Connected to remote registry at %s (%s)"
                    % (repr(self.target.remote_name), self.target.target_ip)
                )
                break
            except Exception as e:
                if "STATUS_PIPE_NOT_AVAILABLE" in str(e):
                    logging.warning(
                        (
                            "Failed to connect to remote registry. Service should be "
                            "starting now. Trying again..."
                        )
                    )
                    time.sleep(1)
                else:
                    raise e
        else:
            logging.warning("Failed to connect to remote registry")
            return None

        return dce

    def find(self):
        connection = self.connection

        if self.vuln:
            sids = connection.get_user_sids(self.target.username)

            if self.verbose:
                logging.debug("List of current user's SIDs:")
                for sid in sids:
                    print(
                        "     %s (%s)"
                        % (
                            self.connection.lookup_sid(sid).get("name"),
                            self.connection.lookup_sid(sid).get("objectSid"),
                        )
                    )
        else:
            sids = []

        logging.info("Finding certificate templates")

        templates = self.get_certificate_templates()

        logging.info(
            "Found %d certificate template%s"
            % (
                len(templates),
                "s" if len(templates) != 1 else "",
            )
        )

        logging.info("Finding certificate authorities")

        cas = self.get_certificate_authorities()

        logging.info(
            "Found %d certificate authorit%s"
            % (
                len(cas),
                "ies" if len(cas) != 1 else "y",
            )
        )

        no_enabled_templates = 0
        for ca in cas:
            object_id = ca.get("objectGUID").lstrip("{").rstrip("}")
            ca.set("object_id", object_id)

            ca_templates = ca.get("certificateTemplates")
            if ca_templates is None:
                ca_templates = []

            for template in templates:
                if template.get("name") in ca_templates:
                    no_enabled_templates += 1
                    if "cas" in template["attributes"].keys():
                        template.get("cas").append(ca.get("name"))
                        template.get("cas_ids").append(object_id)
                    else:
                        template.set("cas", [ca.get("name")])
                        template.set("cas_ids", [object_id])

        logging.info(
            "Found %d enabled certificate template%s"
            % (
                no_enabled_templates,
                "s" if no_enabled_templates != 1 else "",
            )
        )

        for ca in cas:

            if self.dc_only:
                user_specified_san, request_disposition, enforce_encrypt_icertrequest, security, web_enrollment = (
                    "Unknown",
                    "Unknown",
                    "Unknown",
                    None,
                    "Unknown",
                )
            else:
                user_specified_san, request_disposition, enforce_encrypt_icertrequest, security = (
                    "Unknown",
                    "Unknown",
                    "Unknown",
                    None,
                )
                try:
                    ca_name = ca.get("name")
                    ca_remote_name = ca.get("dNSHostName")
                    ca_target_ip = self.target.resolver.resolve(ca_remote_name)

                    ca_target = copy.copy(self.target)
                    ca_target.remote_name = ca_remote_name
                    ca_target.target_ip = ca_target_ip

                    ca_service = CA(ca_target, ca=ca_name)
                    edit_flags, request_disposition, interface_flags, security = ca_service.get_config()

                    if request_disposition:
                        request_disposition = (
                            "Pending" if request_disposition & 0x100 else "Issue"
                        )
                    else:
                        request_disposition = "Unknown"

                    if edit_flags:
                        user_specified_san = (edit_flags & 0x00040000) == 0x00040000
                        user_specified_san = (
                            "Enabled" if user_specified_san else "Disabled"
                        )
                    else:
                        user_specified_san = "Unknown"

                    if interface_flags:
                        enforce_encrypt_icertrequest = (interface_flags & 0x00000200) == 0x00000200
                        enforce_encrypt_icertrequest = (
                            "Enabled" if enforce_encrypt_icertrequest else "Disabled"
                        )
                    else:
                        enforce_encrypt_icertrequest = "Unknown"

                except Exception as e:
                    logging.warning(
                        "Failed to get CA security and configuration for %s: %s"
                        % (repr(ca.get("name")), e)
                    )

                try:
                    web_enrollment = self.check_web_enrollment(ca)
                    web_enrollment = "Enabled" if web_enrollment else "Disabled"
                except Exception as e:
                    logging.warning(
                        "Failed to check Web Enrollment for CA %s: %s"
                        % (repr(ca.get("name")), e)
                    )
                    web_enrollment = "Unknown"

            ca.set("user_specified_san", user_specified_san)
            ca.set("request_disposition", request_disposition)
            ca.set("enforce_encrypt_icertrequest", enforce_encrypt_icertrequest)
            ca.set("security", security)
            ca.set("web_enrollment", web_enrollment)

            subject_name = ca.get("cACertificateDN")

            ca_cert = x509.Certificate.load(ca.get("cACertificate")[0])[
                "tbs_certificate"
            ]

            serial_number = hex(int(ca_cert["serial_number"]))[2:].upper()

            validity = ca_cert["validity"].native
            validity_start = str(validity["not_before"])
            validity_end = str(validity["not_after"])

            ca.set("subject_name", subject_name)
            ca.set("serial_number", serial_number)
            ca.set("validity_start", validity_start)
            ca.set("validity_end", validity_end)

        for template in templates:
            template_cas = template.get("cas")
            enabled = template_cas is not None and len(template_cas) > 0
            template.set("enabled", enabled)

            object_id = template.get("objectGUID").lstrip("{").rstrip("}")
            template.set("object_id", object_id)

            validity_period = filetime_to_str(template.get("pKIExpirationPeriod"))
            template.set("validity_period", validity_period)

            renewal_period = filetime_to_str(template.get("pKIOverlapPeriod"))
            template.set("renewal_period", renewal_period)

            certificate_name_flag = template.get("msPKI-Certificate-Name-Flag")
            if certificate_name_flag is not None:
                certificate_name_flag = MS_PKI_CERTIFICATE_NAME_FLAG(
                    int(certificate_name_flag)
                )
            else:
                certificate_name_flag = MS_PKI_CERTIFICATE_NAME_FLAG(0)
            template.set("certificate_name_flag", certificate_name_flag.to_str_list())

            enrollment_flag = template.get("msPKI-Enrollment-Flag")
            if enrollment_flag is not None:
                enrollment_flag = MS_PKI_ENROLLMENT_FLAG(int(enrollment_flag))
            else:
                enrollment_flag = MS_PKI_ENROLLMENT_FLAG(0)
            template.set("enrollment_flag", enrollment_flag.to_str_list())

            private_key_flag = template.get("msPKI-Private-Key-Flag")
            if private_key_flag is not None:
                private_key_flag = MS_PKI_PRIVATE_KEY_FLAG(int(private_key_flag))
            else:
                private_key_flag = MS_PKI_PRIVATE_KEY_FLAG(0)
            template.set("private_key_flag", private_key_flag.to_str_list())

            authorized_signatures_required = template.get("msPKI-RA-Signature")
            if authorized_signatures_required is not None:
                authorized_signatures_required = int(authorized_signatures_required)
            else:
                authorized_signatures_required = 0
            template.set(
                "authorized_signatures_required", authorized_signatures_required
            )

            application_policies = template.get_raw("msPKI-RA-Application-Policies")
            if not isinstance(application_policies, list):
                if application_policies is None:
                    application_policies = []
                else:
                    application_policies = [application_policies]

            application_policies = list(map(lambda x: x.decode(), application_policies))

            application_policies = list(
                map(
                    lambda x: OID_TO_STR_MAP[x] if x in OID_TO_STR_MAP else x,
                    application_policies,
                )
            )
            template.set("application_policies", application_policies)

            eku = template.get_raw("pKIExtendedKeyUsage")
            if not isinstance(eku, list):
                if eku is None:
                    eku = []
                else:
                    eku = [eku]

            eku = list(map(lambda x: x.decode(), eku))

            extended_key_usage = list(
                map(lambda x: OID_TO_STR_MAP[x] if x in OID_TO_STR_MAP else x, eku)
            )
            template.set("extended_key_usage", extended_key_usage)

            any_purpose = (
                "Any Purpose" in extended_key_usage or len(extended_key_usage) == 0
            )
            template.set("any_purpose", any_purpose)

            client_authentication = any_purpose or any(
                eku in extended_key_usage
                for eku in [
                    "Client Authentication",
                    "Smart Card Logon",
                    "PKINIT Client Authentication",
                ]
            )
            template.set("client_authentication", client_authentication)

            enrollment_agent = any_purpose or any(
                eku in extended_key_usage
                for eku in [
                    "Certificate Request Agent",
                ]
            )
            template.set("enrollment_agent", enrollment_agent)

            enrollee_supplies_subject = any(
                flag in certificate_name_flag
                for flag in [
                    MS_PKI_CERTIFICATE_NAME_FLAG.ENROLLEE_SUPPLIES_SUBJECT,
                ]
            )
            template.set("enrollee_supplies_subject", enrollee_supplies_subject)

            requires_manager_approval = (
                MS_PKI_ENROLLMENT_FLAG.PEND_ALL_REQUESTS in enrollment_flag
            )
            template.set("requires_manager_approval", requires_manager_approval)

            no_security_extension = (
                MS_PKI_ENROLLMENT_FLAG.NO_SECURITY_EXTENSION in enrollment_flag
            )
            template.set("no_security_extension", no_security_extension)

            requires_key_archival = (
                MS_PKI_PRIVATE_KEY_FLAG.REQUIRE_PRIVATE_KEY_ARCHIVAL in private_key_flag
            )
            template.set("requires_key_archival", requires_key_archival)

        prefix = (
            datetime.now().strftime("%Y%m%d%H%M%S") if not self.output else self.output
        )

        not_specified = not any([self.json, self.bloodhound, self.text])

        if self.bloodhound or not_specified:
            self.output_bloodhound_data(prefix, templates, cas)

        if self.text or self.json or not_specified:
            output = self.get_output_for_text_and_json(templates, cas)

            if self.text or not_specified:
                if self.stdout:
                    logging.info("Enumeration output:")
                    pretty_print(output)
                else:
                    with open("%s_Certipy.txt" % prefix, "w") as f:
                        pretty_print(output, print=lambda x: f.write(x) + f.write("\n"))
                    logging.info(
                        "Saved text output to %s" % repr("%s_Certipy.txt" % prefix)
                    )

            if self.json or not_specified:
                with open("%s_Certipy.json" % prefix, "w") as f:
                    json.dump(output, f, indent=2)

                logging.info(
                    "Saved JSON output to %s" % repr("%s_Certipy.json" % prefix)
                )

    def get_output_for_text_and_json(
        self, templates: List[LDAPEntry], cas: List[LDAPEntry]
    ):
        ca_entries = {}
        template_entries = {}

        for template in templates:
            if self.enabled and template.get("enabled") is not True:
                continue

            vulnerabilities = self.get_template_vulnerabilities(template)
            if self.vuln and len(vulnerabilities) == 0:
                continue

            entry = OrderedDict()
            entry = self.get_template_properties(template, entry)

            permissions = self.get_template_permissions(template)
            if len(permissions) > 0:
                entry["Permissions"] = permissions

            if len(vulnerabilities) > 0:
                entry["[!] Vulnerabilities"] = vulnerabilities

            template_entries[len(template_entries)] = entry

        for ca in cas:
            entry = OrderedDict()
            entry = self.get_ca_properties(ca, entry)

            permissions = self.get_ca_permissions(ca)
            if len(permissions) > 0:
                entry["Permissions"] = permissions

            vulnerabilities = self.get_ca_vulnerabilities(ca)
            if len(vulnerabilities) > 0:
                entry["[!] Vulnerabilities"] = vulnerabilities

            ca_entries[len(ca_entries)] = entry

        output = {}

        if len(ca_entries) == 0:
            output["Certificate Authorities"] = "[!] Could not find any CAs"
        else:
            output["Certificate Authorities"] = ca_entries

        if len(template_entries) == 0:
            output[
                "Certificate Templates"
            ] = "[!] Could not find any certificate templates"
        else:
            output["Certificate Templates"] = template_entries

        return output

    def output_bloodhound_data(
        self, prefix: str, templates: List[LDAPEntry], cas: List[LDAPEntry]
    ):
        template_entries = []
        ca_entries = []

        for template in templates:
            template_properties = OrderedDict()
            template_properties["name"] = "%s@%s" % (
                template.get("cn").upper(),
                self.connection.domain.upper(),
            )
            template_properties["highvalue"] = template.get("enabled") and any(
                [
                    all(
                        [
                            template.get("enrollee_supplies_subject"),
                            not template.get("requires_manager_approval"),
                            template.get("client_authentication"),
                        ]
                    ),
                    all(
                        [
                            template.get("enrollment_agent"),
                            not template.get("requires_manager_approval"),
                        ]
                    ),
                ]
            )

            template_properties = self.get_template_properties(
                template, template_properties
            )

            template_properties["domain"] = self.connection.domain.upper()

            if self.old_bloodhound:
                template_properties["type"] = "Certificate Template"

            security = CertifcateSecurity(template.get("nTSecurityDescriptor"))
            if security is None:
                aces = []
            else:
                aces = self.security_to_bloodhound_aces(security)

            entry = {
                "Properties": template_properties,
                "ObjectIdentifier": template.get("object_id"),
                "Aces": aces,
            }

            if not self.old_bloodhound:
                entry["cas_ids"] = template.get("cas_ids")

            template_entries.append(entry)

        for ca in cas:
            ca_properties = OrderedDict()
            ca_properties["name"] = "%s@%s" % (
                ca.get("name").upper(),
                self.connection.domain.upper(),
            )
            ca_properties[
                "highvalue"
            ] = False  # It is a high value, but the 'Enroll' will give many false positives

            ca_properties = self.get_ca_properties(ca, ca_properties)

            ca_properties["domain"] = self.connection.domain.upper()

            if self.old_bloodhound:
                ca_properties["type"] = "Enrollment Service"

            security = ca.get("security")
            if security is None:
                aces = []
            else:
                aces = self.security_to_bloodhound_aces(security)

            entry = {
                "Properties": ca_properties,
                "ObjectIdentifier": ca.get("object_id"),
                "Aces": aces,
            }

            ca_entries.append(entry)

        zipf = zipfile.ZipFile("%s_Certipy.zip" % prefix, "w")

        if self.old_bloodhound:
            gpos_filename = "%s_gpos.json" % prefix
            entries = ca_entries + template_entries
            with open(gpos_filename, "w") as f:
                json.dump(
                    {
                        "data": entries,
                        "meta": {
                            "count": len(entries),
                            "type": "gpos",
                            "version": 4,
                        },
                    },
                    f,
                )
            zipf.write(gpos_filename, gpos_filename)
            os.unlink(gpos_filename)
        else:
            cas_filename = "%s_cas.json" % prefix
            with open(cas_filename, "w") as f:
                json.dump(
                    {
                        "data": ca_entries,
                        "meta": {
                            "count": len(ca_entries),
                            "type": "cas",
                            "version": 4,
                        },
                    },
                    f,
                )
            zipf.write(cas_filename, cas_filename)
            os.unlink(cas_filename)

            templates_filename = "%s_templates.json" % prefix
            with open(templates_filename, "w") as f:
                json.dump(
                    {
                        "data": template_entries,
                        "meta": {
                            "count": len(template_entries),
                            "type": "templates",
                            "version": 4,
                        },
                    },
                    f,
                )
            zipf.write(templates_filename, templates_filename)
            os.unlink(templates_filename)

        zipf.close()
        logging.info(
            (
                "Saved BloodHound data to %s. Drag and drop the file into the "
                "BloodHound GUI from %s"
            )
            % (
                repr(
                    "%s_Certipy.zip" % prefix,
                ),
                "@BloodHoundAD" if self.old_bloodhound else "@ly4k",
            )
        )

    def check_web_enrollment(self, ca: LDAPEntry) -> bool:
        target_name = ca.get("dNSHostName")

        target_ip = self.target.resolver.resolve(target_name)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.target.timeout)

            logging.debug("Connecting to %s:80" % target_ip)
            sock.connect((target_ip, 80))
            sock.sendall(
                "\r\n".join(
                    ["HEAD /certsrv/ HTTP/1.1", "Host: %s" % target_name, "\r\n"]
                ).encode()
            )
            resp = sock.recv(256)
            sock.close()
            head = resp.split(b"\r\n")[0].decode()

            return " 404 " not in head
        except ConnectionRefusedError:
            return False
        except socket.timeout:
            return False
        except Exception as e:
            logging.warning(
                "Got error while trying to check for web enrollment: %s" % e
            )

        return False

    def get_certificate_templates(self) -> List[LDAPEntry]:
        templates = self.connection.search(
            "(objectclass=pkicertificatetemplate)",
            search_base="CN=Certificate Templates,CN=Public Key Services,CN=Services,%s"
            % self.connection.configuration_path,
            attributes=[
                "cn",
                "name",
                "displayName",
                "pKIExpirationPeriod",
                "pKIOverlapPeriod",
                "msPKI-Enrollment-Flag",
                "msPKI-Private-Key-Flag",
                "msPKI-Certificate-Name-Flag",
                "msPKI-Minimal-Key-Size",
                "msPKI-RA-Signature",
                "pKIExtendedKeyUsage",
                "nTSecurityDescriptor",
                "objectGUID",
            ],
            query_sd=True,
        )

        return templates

    def get_certificate_authorities(self) -> List[LDAPEntry]:
        cas = self.connection.search(
            "(&(objectClass=pKIEnrollmentService))",
            search_base="CN=Enrollment Services,CN=Public Key Services,CN=Services,%s"
            % self.connection.configuration_path,
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

        return cas

    def security_to_bloodhound_aces(self, security: ActiveDirectorySecurity) -> List:
        aces = []

        owner = self.connection.lookup_sid(security.owner)

        aces.append(
            {
                "PrincipalSID": owner.get("objectSid"),
                "PrincipalType": owner.get("objectType"),
                "RightName": "Owns",
                "IsInherited": False,
            }
        )

        for sid, rights in security.aces.items():
            is_inherited = rights["inherited"]
            principal = self.connection.lookup_sid(sid)

            standard_rights = rights["rights"].to_list()

            for right in standard_rights:
                aces.append(
                    {
                        "PrincipalSID": principal.get("objectSid"),
                        "PrincipalType": principal.get("objectType"),
                        "RightName": str(right),
                        "IsInherited": is_inherited,
                    }
                )

            extended_rights = rights["extended_rights"]

            for extended_right in extended_rights:
                aces.append(
                    {
                        "PrincipalSID": principal.get("objectSid"),
                        "PrincipalType": principal.get("objectType"),
                        "RightName": EXTENDED_RIGHTS_MAP[extended_right].replace(
                            "-", ""
                        )
                        if extended_right in EXTENDED_RIGHTS_MAP
                        else extended_right,
                        "IsInherited": is_inherited,
                    }
                )

        return aces

    def get_template_properties(
        self, template: LDAPEntry, template_properties: dict = None
    ) -> dict:
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
            "application_policies": "Application Policies",
            "authorized_signatures_required": "Authorized Signatures Required",
            "validity_period": "Validity Period",
            "renewal_period": "Renewal Period",
            "msPKI-Minimal-Key-Size": "Minimum RSA Key Length"
        }

        if template_properties is None:
            template_properties = OrderedDict()

        for property_key, property_display in properties_map.items():
            property_value = template.get(property_key)
            if property_value is None:
                continue
            template_properties[property_display] = property_value

        return template_properties

    def get_template_permissions(self, template: LDAPEntry):
        security = CertifcateSecurity(template.get("nTSecurityDescriptor"))
        permissions = {}
        enrollment_permissions = {}
        enrollment_rights = []
        all_extended_rights = []

        for sid, rights in security.aces.items():
            if self.hide_admins and is_admin_sid(sid):
                continue

            if (
                EXTENDED_RIGHTS_NAME_MAP["Enroll"] in rights["extended_rights"]
            ):
                enrollment_rights.append(self.connection.lookup_sid(sid).get("name"))
            if (
                EXTENDED_RIGHTS_NAME_MAP["All-Extended-Rights"]
                in rights["extended_rights"]
            ):
                all_extended_rights.append(self.connection.lookup_sid(sid).get("name"))

        if len(enrollment_rights) > 0:
            enrollment_permissions["Enrollment Rights"] = enrollment_rights

        if len(all_extended_rights) > 0:
            enrollment_permissions["All Extended Rights"] = all_extended_rights

        if len(enrollment_permissions) > 0:
            permissions["Enrollment Permissions"] = enrollment_permissions

        object_control_permissions = {}
        if not self.hide_admins or not is_admin_sid(security.owner):
            object_control_permissions["Owner"] = self.connection.lookup_sid(
                security.owner
            ).get("name")

        rights_mapping = [
            (CERTIFICATE_RIGHTS.GENERIC_ALL, [], "Full Control Principals"),
            (CERTIFICATE_RIGHTS.WRITE_OWNER, [], "Write Owner Principals"),
            (CERTIFICATE_RIGHTS.WRITE_DACL, [], "Write Dacl Principals"),
            (
                CERTIFICATE_RIGHTS.WRITE_PROPERTY,
                [],
                "Write Property Principals",
            ),
        ]
        for sid, rights in security.aces.items():
            if self.hide_admins and is_admin_sid(sid):
                continue

            rights = rights["rights"]
            sid = self.connection.lookup_sid(sid).get("name")

            for (right, principal_list, _) in rights_mapping:
                if right in rights:
                    principal_list.append(sid)

        for _, rights, name in rights_mapping:
            if len(rights) > 0:
                object_control_permissions[name] = rights

        if len(object_control_permissions) > 0:
            permissions["Object Control Permissions"] = object_control_permissions

        return permissions

    def get_template_vulnerabilities(self, template: LDAPEntry):
        def list_sids(sids: List[str]):
            sids_mapping = list(
                map(
                    lambda sid: repr(self.connection.lookup_sid(sid).get("name")),
                    sids,
                )
            )
            if len(sids_mapping) == 1:
                return sids_mapping[0]

            return ", ".join(sids_mapping[:-1]) + " and " + sids_mapping[-1]

        if template.get("vulnerabilities"):
            return template.get("vulnerabilities")

        vulnerabilities = {}

        user_can_enroll, enrollable_sids = self.can_user_enroll_in_template(template)

        if (
            not template.get("requires_manager_approval")
            and not template.get("authorized_signatures_required") > 0
        ):
            # ESC1
            if (
                user_can_enroll
                and template.get("enrollee_supplies_subject")
                and template.get("client_authentication")
            ):
                vulnerabilities["ESC1"] = (
                    "%s can enroll, enrollee supplies subject and template allows client authentication"
                    % list_sids(enrollable_sids)
                )

            # ESC2
            if user_can_enroll and template.get("any_purpose"):
                vulnerabilities["ESC2"] = (
                    "%s can enroll and template can be used for any purpose"
                    % list_sids(enrollable_sids)
                )

            # ESC3
            if user_can_enroll and template.get("enrollment_agent"):
                vulnerabilities["ESC3"] = (
                    "%s can enroll and template has Certificate Request Agent EKU set"
                    % list_sids(enrollable_sids)
                )

            # ESC9
            if user_can_enroll and template.get("no_security_extension"):
                vulnerabilities[
                    "ESC9"
                ] = "%s can enroll and template has no security extension" % list_sids(
                    enrollable_sids
                )

        # ESC4
        security = CertifcateSecurity(template.get("nTSecurityDescriptor"))
        owner_sid = security.owner

        if owner_sid in self.connection.get_user_sids(self.target.username):
            vulnerabilities[
                "ESC4"
            ] = "Template is owned by %s" % self.connection.lookup_sid(owner_sid).get(
                "name"
            )
        else:
            # No reason to show if user is already owner
            has_vulnerable_acl, vulnerable_acl_sids = self.template_has_vulnerable_acl(
                template
            )
            if has_vulnerable_acl:
                vulnerabilities["ESC4"] = "%s has dangerous permissions" % list_sids(
                    vulnerable_acl_sids
                )

        return vulnerabilities

    def template_has_vulnerable_acl(self, template: LDAPEntry):
        has_vulnerable_acl = False

        security = CertifcateSecurity(template.get("nTSecurityDescriptor"))
        aces = security.aces
        vulnerable_acl_sids = []
        for sid, rights in aces.items():
            if sid not in self.connection.get_user_sids(self.target.username):
                continue

            ad_rights = rights["rights"]
            if any(
                right in ad_rights
                for right in [
                    CERTIFICATE_RIGHTS.GENERIC_ALL,
                    CERTIFICATE_RIGHTS.WRITE_OWNER,
                    CERTIFICATE_RIGHTS.WRITE_DACL,
                    CERTIFICATE_RIGHTS.WRITE_PROPERTY,
                ]
            ):
                vulnerable_acl_sids.append(sid)
                has_vulnerable_acl = True

        return has_vulnerable_acl, vulnerable_acl_sids

    def can_user_enroll_in_template(self, template: LDAPEntry):
        user_can_enroll = False

        security = CertifcateSecurity(template.get("nTSecurityDescriptor"))
        aces = security.aces
        enrollable_sids = []
        for sid, rights in aces.items():
            if sid not in self.connection.get_user_sids(self.target.username):
                continue

            if (
                EXTENDED_RIGHTS_NAME_MAP["All-Extended-Rights"]
                in rights["extended_rights"]
                or EXTENDED_RIGHTS_NAME_MAP["Enroll"] in rights["extended_rights"]
                or CERTIFICATE_RIGHTS.GENERIC_ALL in rights["rights"]
            ):
                enrollable_sids.append(sid)
                user_can_enroll = True

        return user_can_enroll, enrollable_sids

    def get_ca_properties(self, ca: LDAPEntry, ca_properties: dict = None) -> dict:
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
        }

        if ca_properties is None:
            ca_properties = OrderedDict()

        for property_key, property_display in properties_map.items():
            property_value = ca.get(property_key)
            if property_value is None:
                continue
            ca_properties[property_display] = property_value

        return ca_properties

    def get_ca_permissions(self, ca: LDAPEntry):
        security = ca.get("security")

        ca_permissions = {}
        access_rights = {}
        if security is not None:
            if not self.hide_admins or not is_admin_sid(security.owner):
                ca_permissions["Owner"] = self.connection.lookup_sid(
                    security.owner
                ).get("name")

            for sid, rights in security.aces.items():
                if self.hide_admins and is_admin_sid(sid):
                    continue
                ca_rights = rights["rights"].to_list()
                for ca_right in ca_rights:
                    if ca_right not in access_rights:
                        access_rights[ca_right] = [
                            self.connection.lookup_sid(sid).get("name")
                        ]
                    else:
                        access_rights[ca_right].append(
                            self.connection.lookup_sid(sid).get("name")
                        )

            ca_permissions["Access Rights"] = access_rights

        return ca_permissions

    def get_ca_vulnerabilities(self, ca: LDAPEntry):
        def list_sids(sids: List[str]):
            sids_mapping = list(
                map(
                    lambda sid: repr(self.connection.lookup_sid(sid).get("name")),
                    sids,
                )
            )
            if len(sids_mapping) == 1:
                return sids_mapping[0]

            return ", ".join(sids_mapping[:-1]) + " and " + sids_mapping[-1]

        if ca.get("vulnerabilities"):
            return ca.get("vulnerabilities")

        vulnerabilities = {}

        # ESC6
        if (
            ca.get("user_specified_san") == "Enabled"
            and ca.get("request_disposition") == "Issue"
        ):
            vulnerabilities[
                "ESC6"
            ] = "Enrollees can specify SAN and Request Disposition is set to Issue. Does not work after May 2022"

        # ESC7
        has_vulnerable_acl, vulnerable_acl_sids = self.ca_has_vulnerable_acl(ca)
        if has_vulnerable_acl:
            vulnerabilities["ESC7"] = "%s has dangerous permissions" % list_sids(
                vulnerable_acl_sids
            )

        # ESC8
        if ca.get("web_enrollment") == "Enabled" and ca.get("request_disposition") in [
            "Issue",
            "Unknown",
        ]:
            vulnerabilities["ESC8"] = (
                "Web Enrollment is enabled and Request Disposition is set to %s"
                % ca.get("request_disposition")
            )

        # ESC11
        if (
            ca.get("enforce_encrypt_icertrequest") == "Disabled"
            and ca.get("request_disposition") == "Issue"
        ):
            vulnerabilities[
                "ESC11"
            ] = "Encryption is not enforced for ICPR requests and Request Disposition is set to Issue"

        return vulnerabilities

    def ca_has_vulnerable_acl(self, ca: LDAPEntry):
        has_vulnerable_acl = False
        vulnerable_acl_sids = []

        security = ca.get("security")
        if security is None:
            return has_vulnerable_acl, vulnerable_acl_sids

        aces = security.aces
        for sid, rights in aces.items():
            if sid not in self.connection.get_user_sids(self.target.username):
                continue

            ad_rights = rights["rights"]
            if any(
                right in ad_rights
                for right in [
                    CERTIFICATION_AUTHORITY_RIGHTS.MANAGE_CA,
                    CERTIFICATION_AUTHORITY_RIGHTS.MANAGE_CERTIFICATES,
                ]
            ):
                vulnerable_acl_sids.append(sid)
                has_vulnerable_acl = True

        return has_vulnerable_acl, vulnerable_acl_sids


def entry(options: argparse.Namespace) -> None:
    target = Target.from_options(options, dc_as_target=True)
    del options.target

    find = Find(target=target, **vars(options))
    find.find()
