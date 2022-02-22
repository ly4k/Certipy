import argparse
import copy
import json
import logging
import os
import socket
import struct
import zipfile
from datetime import datetime
from typing import Callable, List, Tuple

from asn1crypto import x509

from certipy import target
from certipy.ca import CA
from certipy.constants import (
    CERTIFICATE_RIGHTS,
    EXTENDED_RIGHTS_MAP,
    EXTENDED_RIGHTS_NAME_MAP,
    MS_PKI_CERTIFICATE_NAME_FLAG,
    MS_PKI_ENROLLMENT_FLAG,
    OID_TO_STR_MAP,
    WELL_KNOWN_SIDS,
)
from certipy.formatting import pretty_print
from certipy.ldap import LDAPConnection, LDAPEntry
from certipy.security import ActiveDirectorySecurity, CertifcateSecurity
from certipy.target import Target

NAME = "find"


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
        text: bool = False,
        output: str = None,
        enabled: bool = False,
        scheme: str = "ldaps",
        connection: LDAPConnection = None,
        debug=False,
        **kwargs
    ):
        self.target = target
        self.json = json
        self.bloodhound = bloodhound
        self.text = text
        self.output = output
        self.enabled = enabled
        self.scheme = scheme
        self.verbose = debug
        self.kwargs = kwargs

        self.sid_map = {}

        self._connection = connection

    @property
    def connection(self) -> LDAPConnection:
        if self._connection is not None:
            return self._connection

        self._connection = LDAPConnection(self.target, self.scheme)
        self._connection.connect()

        return self._connection

    def find(self):
        logging.info("Finding certificate templates")

        certificate_templates = self.get_certificate_templates()

        logging.info(
            "Found %d certificate template%s"
            % (
                len(certificate_templates),
                "s" if len(certificate_templates) != 1 else "",
            )
        )

        logging.info("Finding certificate authorities")

        enrollment_services = self.get_enrollment_services()

        logging.info(
            "Found %d certificate authorit%s"
            % (
                len(enrollment_services),
                "ies" if len(enrollment_services) != 1 else "y",
            )
        )

        bloodhound_data = []
        output_cas = {}
        i = 0
        for enrollment_service in enrollment_services:
            templates = enrollment_service.get("certificateTemplates")
            if templates is None:
                templates = []

            for template in certificate_templates:
                if template.get("name") in templates:
                    if "cas" in template["attributes"].keys():
                        template.get("cas").append(enrollment_service.get("name"))
                    else:
                        template.set("cas", [enrollment_service.get("name")])

            object_identifier = enrollment_service.get("objectGUID")

            try:
                ca_name = enrollment_service.get("name")
                ca_remote_name = enrollment_service.get("dNSHostName")
                ca_target_ip = self.target.resolver.resolve(ca_remote_name)

                ca_target = copy.copy(self.target)
                ca_target.remote_name = ca_remote_name
                ca_target.target_ip = ca_target_ip

                ca = CA(ca_target, ca=ca_name)
                edit_flags, request_disposition, security = ca.get_config()
            except Exception as e:
                logging.warning(
                    "Failed to get CA security and configuration for %s: %s"
                    % (repr(enrollment_service.get("name")), e)
                )
                edit_flags, request_disposition, security = (None, None, None)

            try:
                web_enrollment = self.check_web_enrollment(enrollment_service)
            except Exception as e:
                logging.warning(
                    "Failed to check Web Enrollment for CA %s: %s"
                    % (repr(enrollment_service.get("name")), e)
                )
                web_enrollment = None

            ca_name = enrollment_service.get("cn")
            dns_name = enrollment_service.get("dNSHostName")
            subject_name = enrollment_service.get("cACertificateDN")

            ca_certificate = x509.Certificate.load(
                enrollment_service.get("cACertificate")[0]
            )["tbs_certificate"]

            serial_number = hex(int(ca_certificate["serial_number"]))[2:].upper()

            validity = ca_certificate["validity"].native
            validity_start = str(validity["not_before"])
            validity_end = str(validity["not_after"])

            output_cas[i] = {
                "CA Name": enrollment_service.get("name"),
                "DNS Name": dns_name,
                "Certificate Subject": subject_name,
                "Certificate Serial Number": serial_number,
                "Certificate Validity Start": validity_start,
                "Certificate Validity End": validity_end,
            }

            if web_enrollment is not None:
                output_cas[i]["Web Enrollment"] = (
                    "Enabled" if web_enrollment else "Disabled"
                )

            if edit_flags is not None:
                user_specifies_san = (edit_flags & 0x00040000) == 0x00040000
                output_cas[i]["User Specified SAN"] = (
                    "Enabled" if user_specifies_san else "Disabled"
                )

            if request_disposition is not None:
                output_cas[i]["Request Disposition"] = (
                    "Pending" if request_disposition & 0x100 else "Issue"
                )

            ca_permissions = {}
            access_rights = {}
            aces = []
            if security is not None:
                aces = self.security_to_bloodhound_aces(security)

                ca_permissions["Owner"] = self.lookup_sid(security.owner).get("name")

                for sid, rights in security.aces.items():
                    ca_rights = rights["rights"].to_list()
                    for ca_right in ca_rights:
                        if ca_right not in access_rights:
                            access_rights[ca_right] = [self.lookup_sid(sid).get("name")]
                        else:
                            access_rights[ca_right].append(
                                self.lookup_sid(sid).get("name")
                            )

                ca_permissions["Access Rights"] = access_rights

            # For BloodHound
            bloodhound_entry = {
                "Properties": {
                    "highvalue": True,
                    "name": "%s@%s"
                    % (
                        ca_name.upper(),
                        self.connection.domain.upper(),
                    ),
                    "domain": self.connection.domain.upper(),
                    "type": "Enrollment Service",
                },
                "ObjectIdentifier": object_identifier.lstrip("{").rstrip("}"),
                "Aces": aces,
            }

            bloodhound_entry["Properties"].update(output_cas[i])

            bloodhound_data.append(bloodhound_entry)

            output_cas[i]["CA Permissions"] = ca_permissions

            i += 1

        output_templates = {}
        i = 0
        enabled_templates = 0
        for template in certificate_templates:
            cas = template.get("cas")

            if cas is None and self.enabled:
                # Don't show templates with no CAs (not enabled)
                continue

            enabled = cas is not None and len(cas) > 0

            enabled_templates += int(enabled)

            object_identifier = template.get("objectGUID")

            validity_period = filetime_to_str(template.get("pKIExpirationPeriod"))
            renewal_period = filetime_to_str(template.get("pKIOverlapPeriod"))

            certificate_name_flag = template.get("msPKI-Certificate-Name-Flag")
            if certificate_name_flag is not None:
                certificate_name_flag = MS_PKI_CERTIFICATE_NAME_FLAG(
                    int(certificate_name_flag)
                )
            else:
                certificate_name_flag = MS_PKI_CERTIFICATE_NAME_FLAG(0)

            enrollment_flag = template.get("msPKI-Enrollment-Flag")
            if enrollment_flag is not None:
                enrollment_flag = MS_PKI_ENROLLMENT_FLAG(int(enrollment_flag))
            else:
                enrollment_flag = MS_PKI_ENROLLMENT_FLAG(0)

            authorized_signatures_required = template.get("msPKI-RA-Signature")
            if authorized_signatures_required is not None:
                authorized_signatures_required = int(authorized_signatures_required)

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

            client_authentication = (
                any(
                    eku in extended_key_usage
                    for eku in [
                        "Client Authentication",
                        "Smart Card Logon",
                        "PKINIT Client Authentication",
                        "Any Purpose",
                    ]
                )
                or len(extended_key_usage) == 0
            )

            enrollment_agent = (
                any(
                    eku in extended_key_usage
                    for eku in [
                        "Certificate Request Agent",
                        "Any Purpose",
                    ]
                )
                or len(extended_key_usage) == 0
            )

            enrollee_supplies_subject = any(
                flag in certificate_name_flag
                for flag in [
                    MS_PKI_CERTIFICATE_NAME_FLAG.ENROLLEE_SUPPLIES_SUBJECT,
                ]
            )

            requires_manager_approval = (
                MS_PKI_ENROLLMENT_FLAG.PEND_ALL_REQUESTS in enrollment_flag
            )

            security = CertifcateSecurity(template.get("nTSecurityDescriptor"))

            aces = self.security_to_bloodhound_aces(security)

            # For BloodHound
            bloodhound_entry = {
                "Properties": {
                    "highvalue": (
                        enabled
                        and any(
                            [
                                all(
                                    [
                                        enrollee_supplies_subject,
                                        not requires_manager_approval,
                                        client_authentication,
                                    ]
                                ),
                                all([enrollment_agent, not requires_manager_approval]),
                            ]
                        )
                    ),
                    "name": "%s@%s"
                    % (
                        template.get("cn").upper(),
                        self.connection.domain.upper(),
                    ),
                    "Template Name": template.get("cn"),
                    "Display Name": template.get("displayName"),
                    "Certificate Authorities": cas,
                    "Enabled": enabled,
                    "Client Authentication": client_authentication,
                    "Enrollee Supplies Subject": enrollee_supplies_subject,
                    "Certificate Name Flag": certificate_name_flag.to_str_list(),
                    "Enrollment Flag": enrollment_flag.to_str_list(),
                    "Extended Key Usage": extended_key_usage,
                    "Requires Manager Approval": requires_manager_approval,
                    "Application Policies": application_policies,
                    "Authorized Signatures Required": authorized_signatures_required,
                    "Validity Period": validity_period,
                    "Renewal Period": renewal_period,
                    "domain": self.connection.domain.upper(),
                    "type": "Certificate Template",
                },
                "ObjectIdentifier": object_identifier.lstrip("{").rstrip("}"),
                "Aces": aces,
            }

            bloodhound_data.append(bloodhound_entry)

            output_templates[i] = {
                "Template Name": template.get("cn"),
                "Display Name": template.get("displayName"),
                "Certificate Authorities": cas,
                "Enabled": enabled,
                "Client Authentication": client_authentication,
                "Enrollee Supplies Subject": enrollee_supplies_subject,
                "Certificate Name Flag": certificate_name_flag.to_str_list(),
                "Enrollment Flag": enrollment_flag.to_str_list(),
                "Extended Key Usage": extended_key_usage,
                "Requires Manager Approval": requires_manager_approval,
                "Application Policies": application_policies,
                "Authorized Signatures Required": authorized_signatures_required,
                "Validity Period": validity_period,
                "Renewal Period": renewal_period,
            }

            permissions = {}

            enrollment_permissions = {}

            enrollment_rights = []
            all_extended_rights = []

            for sid, rights in security.aces.items():
                if (
                    EXTENDED_RIGHTS_NAME_MAP["Enroll"] in rights["extended_rights"]
                    or EXTENDED_RIGHTS_NAME_MAP["AutoEnroll"]
                    in rights["extended_rights"]
                ):
                    enrollment_rights.append(self.lookup_sid(sid).get("name"))
                if (
                    EXTENDED_RIGHTS_NAME_MAP["All-Extended-Rights"]
                    in rights["extended_rights"]
                ):
                    all_extended_rights.append(self.lookup_sid(sid).get("name"))

            if len(enrollment_rights) > 0:
                enrollment_permissions["Enrollment Rights"] = enrollment_rights

            if len(all_extended_rights) > 0:
                enrollment_permissions["All Extended Rights"] = all_extended_rights

            if len(enrollment_permissions) > 0:
                permissions["Enrollment Permissions"] = enrollment_permissions

            object_control_permissions = {}
            object_control_permissions["Owner"] = self.lookup_sid(security.owner).get(
                "name"
            )

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
                rights = rights["rights"]
                sid = self.lookup_sid(sid).get("name")

                for (right, principal_list, _) in rights_mapping:
                    if right in rights:
                        principal_list.append(sid)

            for _, rights, name in rights_mapping:
                if len(rights) > 0:
                    object_control_permissions[name] = rights

            if len(object_control_permissions) > 0:
                permissions["Object Control Permissions"] = object_control_permissions

            if len(permissions) > 0:
                output_templates[i]["Permissions"] = permissions

            i += 1

        logging.info(
            "Found %d enabled certificate template%s"
            % (enabled_templates, "s" if enabled_templates != 1 else "")
        )

        output = {}
        prefix = (
            datetime.now().strftime("%Y%m%d%H%M%S") if not self.output else self.output
        )
        bloodhound = self.bloodhound or not any([self.json, self.bloodhound, self.text])

        zipf = None
        if bloodhound:
            zipf = zipfile.ZipFile("%s_Certipy.zip" % prefix, "w")

        if len(output_cas.keys()) == 0:
            output["Certificate Authorities"] = "[!] Could not find any CAs"
        else:
            output["Certificate Authorities"] = output_cas

        if len(output_templates.keys()) == 0:
            output[
                "Certificate Templates"
            ] = "[!] Could not find any certificate templates"
        else:
            output["Certificate Templates"] = output_templates

        if bloodhound:
            gpos_filename = "%s_gpos.json" % prefix
            with open(gpos_filename, "w") as f:
                json.dump(
                    {
                        "data": bloodhound_data,
                        "meta": {
                            "count": len(bloodhound_data),
                            "type": "gpos",
                            "version": 4,
                        },
                    },
                    f,
                )
            zipf.write(gpos_filename, gpos_filename)
            os.unlink(gpos_filename)

        if self.text or not any([self.json, self.bloodhound, self.text]):
            with open("%s_Certipy.txt" % prefix, "w") as f:
                pretty_print(output, print=lambda x: f.write(x) + f.write("\n"))
            logging.info("Saved text output to %s" % repr("%s_Certipy.txt" % prefix))

        if self.json or not any([self.json, self.bloodhound, self.text]):
            with open("%s_Certipy.json" % prefix, "w") as f:
                json.dump(output, f, indent=2)

            logging.info("Saved JSON output to %s" % repr("%s_Certipy.json" % prefix))

        if self.bloodhound or not any([self.json, self.bloodhound, self.text]):
            zipf.close()
            logging.info(
                (
                    "Saved BloodHound data to %s. Drag and drop the file into the "
                    "BloodHound GUI"
                )
                % repr("%s_Certipy.zip" % prefix)
            )

    def security_to_bloodhound_aces(self, security: ActiveDirectorySecurity) -> List:
        aces = []

        owner = self.lookup_sid(security.owner)
        owner_type = "Group" if "group" in owner.get("objectClass") else "User"

        aces.append(
            {
                "PrincipalSID": owner.get("objectSid"),
                "PrincipalType": owner_type,
                "RightName": "Owner",
                "IsInherited": False,
            }
        )

        for sid, rights in security.aces.items():
            principal = self.lookup_sid(sid)

            principal_type = (
                "Group" if "group" in principal.get("objectClass") else "User"
            )

            standard_rights = rights["rights"].to_list()

            for right in standard_rights:
                aces.append(
                    {
                        "PrincipalSID": principal.get("objectSid"),
                        "PrincipalType": principal_type,
                        "RightName": str(right),
                        "IsInherited": False,
                    }
                )

            extended_rights = rights["extended_rights"]

            for extended_right in extended_rights:
                aces.append(
                    {
                        "PrincipalSID": principal.get("objectSid"),
                        "PrincipalType": principal_type,
                        "RightName": EXTENDED_RIGHTS_MAP[extended_right].replace(
                            "-", ""
                        )
                        if extended_right in EXTENDED_RIGHTS_MAP
                        else extended_right,
                        "IsInherited": False,
                    }
                )

        return aces

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

    def lookup_sid(self, sid: str) -> LDAPEntry:
        if sid in self.sid_map:
            return self.sid_map[sid]

        if sid in WELL_KNOWN_SIDS:
            name = WELL_KNOWN_SIDS[sid]
            sid = "%s-%s" % (self.connection.domain, sid)
            object_class = ["top", "group"]

            return LDAPEntry(
                **{
                    "attributes": {
                        "objectClass": object_class,
                        "objectSid": sid,
                        "name": "%s\\%s" % (self.connection.domain, name),
                    }
                }
            )
        results = self.connection.search(
            "(&(objectSid=%s)(|(objectClass=group)(objectClass=user)))" % sid,
            attributes=[
                "objectClass",
                "objectSid",
                "name",
            ],
        )

        if len(results) != 1:
            logging.warning("Failed to lookup user with SID %s" % repr(sid))
            return LDAPEntry(
                **{
                    "attributes": {
                        "objectClass": sid,
                        "objectSid": sid,
                        "name": sid,
                    }
                }
            )

        entry = results[0]
        entry.set("name", "%s\\%s" % (self.connection.domain, entry.get("name")))
        self.sid_map[sid] = entry

        return entry

    def get_certificate_templates(self) -> List[LDAPEntry]:
        certificate_templates = self.connection.search(
            "(objectclass=pkicertificatetemplate)",
            search_base="CN=Certificate Templates,CN=Public Key Services,CN=Services,%s"
            % self.connection.configuration_path,
            attributes=[
                "cn",
                "name",
                "pKIExpirationPeriod",
                "pKIOverlapPeriod",
                "msPKI-Certificate-Name-Flag",
                "msPKI-Enrollment-Flag",
                "msPKI-RA-Signature",
                "pKIExtendedKeyUsage",
                "nTSecurityDescriptor",
                "objectGUID",
            ],
            query_sd=True,
        )

        return certificate_templates

    def get_enrollment_services(self) -> List[LDAPEntry]:
        enrollment_services = self.connection.search(
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

        return enrollment_services


def entry(options: argparse.Namespace) -> None:
    target = Target.from_options(options, dc_as_target=True)
    del options.target

    find = Find(target=target, **vars(options))
    find.find()


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(NAME, help="Enumerate AD CS")
    subparser.add_argument("-debug", action="store_true", help="Turn debug output on")

    group = subparser.add_argument_group("output options")
    group.add_argument(
        "-json",
        action="store_true",
        help="Output result as JSON only",
    )
    group.add_argument(
        "-bloodhound",
        action="store_true",
        help="Output result as BloodHound data only",
    )
    group.add_argument(
        "-text",
        "-txt",
        action="store_true",
        help="Output result as text only",
    )
    group.add_argument(
        "-output",
        action="store",
        metavar="prefix",
        help="Filename prefix for writing results to",
    )

    group = subparser.add_argument_group("find options")
    group.add_argument(
        "-enabled",
        action="store_true",
        help="Show only enabled certificate templates",
    )

    group = subparser.add_argument_group("connection options")
    group.add_argument(
        "-scheme",
        action="store",
        metavar="ldap scheme",
        choices=["ldap", "ldaps"],
        default="ldaps",
    )

    target.add_argument_group(subparser, connection_options=group)

    return NAME, entry
