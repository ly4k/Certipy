# Certipy - Active Directory certificate abuse
#
# Description:
#   Find certificate templates
#
# Authors:
#   @ly4k (https://github.com/ly4k)
#
# References:
#   https://stackoverflow.com/questions/38878647/python-convert-filetime-to-datetime-for-dates-before-1970
#   https://github.com/GhostPack/Certify/blob/2b1530309c0c5eaf41b2505dfd5a68c83403d031/Certify/Commands/Find.cs#L581
#

import argparse
import json
import logging
import struct
import time

from asn1crypto import x509
from impacket.dcerpc.v5 import rrp, transport
from impacket.smbconnection import SMBConnection
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.protocol.microsoft import security_descriptor_control

from certipy.constants import (
    ACTIVE_DIRECTORY_RIGHTS,
    CERTIFICATION_AUTHORITY_RIGHTS,
    EXTENDED_RIGHTS_NAME_MAP,
    MS_PKI_CERTIFICATE_NAME_FLAG,
    MS_PKI_ENROLLMENT_FLAG,
    OID_TO_STR_MAP,
    WELL_KNOWN_SIDS,
)
from certipy.dnsresolve import DnsResolver
from certipy.formatting import pretty_print
from certipy.ldap import (
    DEFAULT_CONTROL_FLAGS,
    LDAPConnection,
    LDAPEntry,
    SecurityInformation,
)
from certipy.security import ActiveDirectorySecurity, is_low_priv_sid
from certipy.target import Target

# https://stackoverflow.com/questions/38878647/python-convert-filetime-to-datetime-for-dates-before-1970
EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000


def filetime_to_span(filetime: bytes) -> int:
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


def filetime_to_str(filetime: bytes) -> str:
    return span_to_str(filetime_to_span(filetime))


class EnrollmentService:
    ATTRIBUTES = [
        "cn",
        "dNSHostName",
        "cACertificateDN",
        "cACertificate",
        "certificateTemplates",
    ]

    def __init__(
        self,
        entry: LDAPEntry,
        instance: "Find",
        edit_flags: int = None,
        security_descriptor: ActiveDirectorySecurity = None,
        enrollment_restrictions: ActiveDirectorySecurity = None,
    ):
        self.entry = entry
        self.instance = instance
        self.edit_flags = edit_flags
        self.security_descriptor = security_descriptor
        self.enrollment_restrictions = enrollment_restrictions

        self.ca_name = entry.get("cn")
        self.dns_name = entry.get("dNSHostName")
        self.subject_name = entry.get("cACertificateDN")

        ca_certificate = x509.Certificate.load(entry.get_raw("cACertificate"))[
            "tbs_certificate"
        ]

        self.serial_number = hex(int(ca_certificate["serial_number"]))[2:].upper()

        validity = ca_certificate["validity"].native
        self.validity_start = str(validity["not_before"])
        self.validity_end = str(validity["not_after"])
        
        if entry.get_raw("certificateTemplates"):
            self.certificate_templates = list(
                map(lambda x: x.decode(), entry.get_raw("certificateTemplates"))
            )
        else:
            self.certificate_templates = []

        # EDITF_ATTRIBUTESUBJECTALTNAME2
        self.user_specifies_san = (edit_flags & 0x00040000) == 0x00040000

    def to_dict(self) -> dict:
        output = {}

        output["CA Name"] = self.ca_name
        output["DNS Name"] = self.dns_name
        output["Certificate Subject"] = self.subject_name
        output["Certificate Serial Number"] = self.serial_number
        output["Certificate Validity Start"] = self.validity_start
        output["Certificate Validity End"] = self.validity_end
        output["User Specified SAN"] = (
            "Enabled" if self.user_specifies_san else "Disabled"
        )

        if self.security_descriptor is not None:
            # If security_descrtiptor is none, it is likely that it could not be
            # retrieved from remote registry

            ca_permissions = {}
            access_rights = {}

            ca_permissions["Owner"] = self.instance.translate_sid(
                self.security_descriptor.owner
            )

            for sid, rights in self.security_descriptor.aces.items():
                ca_rights = CERTIFICATION_AUTHORITY_RIGHTS(rights["rights"]).to_list()
                for ca_right in ca_rights:
                    if ca_right not in access_rights:
                        access_rights[ca_right] = [self.instance.translate_sid(sid)]
                    else:
                        access_rights[ca_right].append(self.instance.translate_sid(sid))

            ca_permissions["Access Rights"] = access_rights

            # TODO: Print enrollment agent restrictions from
            # self.enrollment_restrictions

            output["CA Permissions"] = ca_permissions

        return output


class CertificateTemplate:
    ATTRIBUTES = [
        "cn",
        "name",
        "pKIExpirationPeriod",
        "pKIOverlapPeriod",
        "msPKI-Certificate-Name-Flag",
        "msPKI-Enrollment-Flag",
        "msPKI-RA-Signature",
        "pKIExtendedKeyUsage",
        "nTSecurityDescriptor",
    ]

    def __init__(self, entry: LDAPEntry, instance: "Find"):
        self._is_vulnerable = None
        self._can_enroll = None
        self._has_vulnerable_acl = None
        self._vulnerable_reasons = []
        self._enrollee = None
        self._vulnerable_technique_ids = []
        self.entry = entry
        self.instance = instance

        self.cas = list(
            map(
                lambda x: x.ca_name,
                filter(
                    lambda x: entry.get("cn") in x.certificate_templates,
                    instance.enrollment_services,
                ),
            )
        )

        self.enabled = len(self.cas) > 0
        self.name = entry.get("name")

        self.validity_period = filetime_to_str(entry.get_raw("pKIExpirationPeriod"))
        self.renewal_period = filetime_to_str(entry.get_raw("pKIOverlapPeriod"))

        self.certificate_name_flag = MS_PKI_CERTIFICATE_NAME_FLAG(
            int(entry.get("msPKI-Certificate-Name-Flag"))
        )
        self.enrollment_flag = MS_PKI_ENROLLMENT_FLAG(
            int(entry.get("msPKI-Enrollment-Flag"))
        )

        self.authorized_signatures_required = int(entry.get("msPKI-RA-Signature"))

        eku = entry.get_raw("pKIExtendedKeyUsage")
        if not isinstance(eku, list):
            if eku is None:
                eku = []
            else:
                eku = [eku]

        eku = list(map(lambda x: x.decode(), eku))

        self.extended_key_usage = list(
            map(lambda x: OID_TO_STR_MAP[x] if x in OID_TO_STR_MAP else x, eku)
        )

        self.security_descriptor = ActiveDirectorySecurity(
            entry.get_raw("nTSecurityDescriptor")
        )

    def __repr__(self) -> str:
        return "<CertificateTemplate name=%s>" % repr(self.name)

    @property
    def can_enroll(self) -> bool:
        if self._can_enroll is not None:
            return self._can_enroll

        user_can_enroll = False

        aces = self.security_descriptor.aces
        for sid, rights in aces.items():
            if not is_low_priv_sid(sid) and sid not in self.instance.user_sids:
                continue

            if (
                EXTENDED_RIGHTS_NAME_MAP["All-Extended-Rights"]
                in rights["extended_rights"]
                or EXTENDED_RIGHTS_NAME_MAP["Certificate-Enrollment"]
                in rights["extended_rights"]
                or EXTENDED_RIGHTS_NAME_MAP["Certificate-AutoEnrollment"]
                in rights["extended_rights"]
            ):
                self._enrollee = self.instance.translate_sid(sid)
                user_can_enroll = True

        self._can_enroll = user_can_enroll
        return self._can_enroll

    @property
    def has_vulnerable_acl(self) -> bool:
        if self._has_vulnerable_acl is not None:
            return self._has_vulnerable_acl

        vulnerable_acl = False
        aces = self.security_descriptor.aces
        vulnerable_acl_sids = []
        for sid, rights in aces.items():
            if not is_low_priv_sid(sid) and sid not in self.instance.user_sids:
                continue

            ad_rights = rights["rights"]
            if any(
                right in ad_rights
                for right in [
                    ACTIVE_DIRECTORY_RIGHTS.GENERIC_ALL,
                    ACTIVE_DIRECTORY_RIGHTS.WRITE_OWNER,
                    ACTIVE_DIRECTORY_RIGHTS.WRITE_DACL,
                    ACTIVE_DIRECTORY_RIGHTS.WRITE_PROPERTY,
                ]
            ):
                vulnerable_acl_sids.append(repr(self.instance.translate_sid(sid)))
                vulnerable_acl = True
        if vulnerable_acl:
            self._vulnerable_reasons.append(
                "%s has dangerous permissions" % ' & '.join(vulnerable_acl_sids)
            )
        self._has_vulnerable_acl = vulnerable_acl
        return self._has_vulnerable_acl

    @property
    def has_authentication_eku(self) -> bool:
        return (
            any(
                eku in self.extended_key_usage
                for eku in [
                    "Client Authentication",
                    "Smart Card Logon",
                    "PKINIT Client Authentication",
                    "Any Purpose",
                ]
            )
            or len(self.extended_key_usage) == 0
        )

    @property
    def requires_manager_approval(self) -> bool:
        return MS_PKI_ENROLLMENT_FLAG.PEND_ALL_REQUESTS in self.enrollment_flag

    # https://github.com/GhostPack/Certify/blob/2b1530309c0c5eaf41b2505dfd5a68c83403d031/Certify/Commands/Find.cs#L581
    @property
    def is_vulnerable(self) -> bool:
        if self._is_vulnerable is not None:
            return self._is_vulnerable

        owner_sid = self.security_descriptor.owner

        if owner_sid in self.instance.user_sids or is_low_priv_sid(owner_sid):
            self._vulnerable_reasons.append(
                "Template is owned by %s" % repr(self.instance.translate_sid(owner_sid))
            )
            self._vulnerable_technique_ids.append("ESC4")
            self._is_vulnerable = True

        user_can_enroll = self.can_enroll
        vulnerable_acl = self.has_vulnerable_acl

        if vulnerable_acl:
            self._is_vulnerable = True
            self._vulnerable_technique_ids.append("ESC4")

        if self.requires_manager_approval:
            return False

        if self.authorized_signatures_required > 0:
            return False

        enrollee_supplies_subject = any(
            flag in self.certificate_name_flag
            for flag in [
                MS_PKI_CERTIFICATE_NAME_FLAG.ENROLLEE_SUPPLIES_SUBJECT,
                MS_PKI_CERTIFICATE_NAME_FLAG.ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME,
            ]
        )

        if (
            user_can_enroll
            and enrollee_supplies_subject
            and self.has_authentication_eku
        ):
            self._vulnerable_reasons.append(
                (
                    "%s can enroll, enrollee supplies subject and template allows "
                    "authentication" % repr(self._enrollee)
                )
            )
            self._vulnerable_technique_ids.append("ESC1")
            self._is_vulnerable = True

        has_dangerous_eku = (
            any(
                eku in self.extended_key_usage
                for eku in ["Any Purpose", "Certificate Request Agent"]
            )
            or len(self.extended_key_usage) == 0
        )

        if user_can_enroll and has_dangerous_eku:
            self._vulnerable_reasons.append(
                ("%s can enroll and template has dangerous EKU" % repr(self._enrollee))
            )
            self._vulnerable_technique_ids.append("ESC2")
            self._is_vulnerable = True

        return self._is_vulnerable

    def to_dict(self) -> dict:
        output = {}

        output["CAs"] = self.cas
        output["Template Name"] = self.name
        output["Validity Period"] = self.validity_period
        output["Renewal Period"] = self.renewal_period
        output["Certificate Name Flag"] = self.certificate_name_flag.to_str_list()
        output["Enrollment Flag"] = self.enrollment_flag.to_str_list()
        output["Authorized Signatures Required"] = self.authorized_signatures_required
        output["Extended Key Usage"] = self.extended_key_usage

        permissions = {}

        enrollment_permissions = {}

        enrollment_rights = []
        all_extended_rights = []

        for sid, rights in self.security_descriptor.aces.items():
            if (
                EXTENDED_RIGHTS_NAME_MAP["Certificate-Enrollment"]
                in rights["extended_rights"]
                or EXTENDED_RIGHTS_NAME_MAP["Certificate-AutoEnrollment"]
                in rights["extended_rights"]
            ):
                enrollment_rights.append(self.instance.translate_sid(sid))
            if (
                EXTENDED_RIGHTS_NAME_MAP["All-Extended-Rights"]
                in rights["extended_rights"]
            ):
                all_extended_rights.append(self.instance.translate_sid(sid))

        if len(enrollment_rights) > 0:
            enrollment_permissions["Enrollment Rights"] = enrollment_rights

        if len(all_extended_rights) > 0:
            enrollment_permissions["All Extended Rights"] = all_extended_rights

        if len(enrollment_permissions) > 0:
            permissions["Enrollment Permissions"] = enrollment_permissions

        object_control_permissions = {}
        object_control_permissions["Owner"] = self.instance.translate_sid(
            self.security_descriptor.owner
        )

        rights_mapping = [
            (ACTIVE_DIRECTORY_RIGHTS.GENERIC_ALL, [], "Full Control Principals"),
            (ACTIVE_DIRECTORY_RIGHTS.WRITE_OWNER, [], "Write Owner Principals"),
            (ACTIVE_DIRECTORY_RIGHTS.WRITE_DACL, [], "Write Dacl Principals"),
            (ACTIVE_DIRECTORY_RIGHTS.WRITE_PROPERTY, [], "Write Property Principals"),
        ]
        for sid, rights in self.security_descriptor.aces.items():
            rights = rights["rights"]
            sid = self.instance.translate_sid(sid)

            for (right, principal_list, _) in rights_mapping:
                if right in rights:
                    principal_list.append(sid)

        for _, rights, name in rights_mapping:
            if len(rights) > 0:
                object_control_permissions[name] = rights

        if len(object_control_permissions) > 0:
            permissions["Object Control Permissions"] = object_control_permissions

        if len(permissions) > 0:
            output["Permissions"] = permissions

        if len(self._vulnerable_reasons) > 0:
            output["Vulnerable Reasons"] = self._vulnerable_reasons
        if len(self._vulnerable_technique_ids) > 0:
            output["Vulnerable Technique IDs"] = self._vulnerable_technique_ids
        return output


class Find:
    def __init__(self, options: argparse.Namespace, target: Target = None):
        self.options = options
        if self.options.json:
            logging.getLogger().setLevel(logging.WARNING)
        if target is None:
            self.target = Target(options)
        else:
            self.target = target

        self.ldap_connection = None

        self._domain = None
        self._user_sids = None
        self._sid_map = {}
        self._user = None
        self._groups = None
        self._enrollment_services = None
        self._certificate_templates = None

        self.resolver = DnsResolver(options, self.target)

    def connect(self):
        self.ldap_connection = LDAPConnection(self.target, self.options.scheme)
        self.ldap_connection.connect()

    def search(self, *args, **kwargs) -> list["LDAPEntry"]:
        return self.ldap_connection.search(*args, **kwargs)

    def run(self, username: str = None):
        if username is None:
            username = self.options.user
            if username is None:
                username = self.target.username

        self.connect()

        if self.options.vulnerable:
            logging.info(
                "Finding vulnerable certificate templates for %s" % repr(username)
            )
        else:
            logging.info("Finding certificate templates for %s" % repr(username))

        output = {}

        user_info = {}
        user_info["Name"] = self.translate_sid(
            format_sid(self.user.get_raw("objectSid"))
        )

        user_info["Groups"] = list(
            map(
                lambda x: self.translate_sid(format_sid(x.get_raw("objectSid"))),
                self.groups,
            )
        )

        output["User"] = user_info

        if len(self.enrollment_services) == 0:
            output["Certificate Authorities"] = "[!] Could not find any CAs"
        else:
            output["Certificate Authorities"] = {}
            for i, enrollment_service in enumerate(self.enrollment_services):
                output["Certificate Authorities"][i] = enrollment_service.to_dict()

        certificate_templates = {}

        i = 0
        for _, certificate_template in enumerate(self.certificate_templates):
            if (certificate_template.enabled) and (
                (self.options.vulnerable and certificate_template.is_vulnerable)
                or not self.options.vulnerable
            ):
                certificate_templates[i] = certificate_template.to_dict()
                i += 1

        if self.options.vulnerable:
            if len(certificate_templates) == 0:
                output[
                    "Vulnerable Certificate Templates"
                ] = "[!] Could not find any vulnerable certificate templates"
            else:
                output["Vulnerable Certificate Templates"] = certificate_templates
        else:
            if len(certificate_templates) == 0:
                output[
                    "Certificate Templates"
                ] = "[!] Could not find any certificate templates"
            else:
                output["Certificate Templates"] = certificate_templates
        if self.options.json:
            print(json.dumps(output, indent=4))
        else:
            pretty_print(output)

    def translate_sid(self, sid: str) -> str:
        if sid in WELL_KNOWN_SIDS:
            return WELL_KNOWN_SIDS[sid]

        if sid in self._sid_map:
            return self._sid_map[sid]

        results = self.search(
            "(&(objectSid=%s)(|(objectClass=group)(objectClass=user)))" % sid,
            attributes=["name", "objectSid"],
        )

        if len(results) == 0:
            return sid

        result = results[0]

        self._sid_map[sid] = self.domain.get("name") + "\\" + result.get("name")

        return self._sid_map[sid]

    def get_ca_security(
        self, ca: LDAPEntry
    ) -> tuple[int, "ActiveDirectorySecurity", "ActiveDirectorySecurity"]:
        target = self.target
        target_name = ca.get("dNSHostName")
        ca_name = ca.get("cn")

        # Use SMBConnection for RPC since the SMBConnection supports both a target name
        # and target IP

        target_ip = self.resolver.resolve(target_name)

        logging.debug("Connecting to SMB at %s (%s)" % (repr(target_name), target_ip))
        smb_connection = SMBConnection(target_name, target_ip)

        if not target.do_kerberos:
            smb_connection.login(
                target.username,
                target.password,
                target.domain,
                target.lmhash,
                target.nthash,
            )
        else:
            smb_connection.kerberosLogin(
                target.username,
                target.password,
                target.domain,
                target.lmhash,
                target.nthash,
                kdcHost=target.dc_ip,
            )

        # TODO: Sometimes the named pipe is not available. Try to start the service
        # remotely
        rpc = transport.DCERPCTransportFactory("ncacn_np:445[\\pipe\\winreg]")
        rpc.set_smb_connection(smb_connection)

        dce = rpc.get_dce_rpc()

        # The remote registry service stops after not being used for 10 minutes.
        # It will automatically start when trying to connect to it
        for _ in range(3):
            try:
                dce.connect()
                dce.bind(rrp.MSRPC_UUID_RRP)
                logging.debug(
                    "Connected to remote registry at %s (%s)"
                    % (repr(target_name), target_ip)
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
            raise Exception("Failed to connect to remote registry")

        hklm = rrp.hOpenLocalMachine(dce)

        h_root_key = hklm["phKey"]

        policy_key = rrp.hBaseRegOpenKey(
            dce,
            h_root_key,
            (
                "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\%s\\"
                "PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy"
            )
            % ca_name,
        )

        _, edit_flags = rrp.hBaseRegQueryValue(
            dce, policy_key["phkResult"], "EditFlags"
        )

        configuration_key = rrp.hBaseRegOpenKey(
            dce,
            h_root_key,
            "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\%s" % ca_name,
        )

        _, security_descriptor = rrp.hBaseRegQueryValue(
            dce, configuration_key["phkResult"], "Security"
        )

        try:
            _, enrollment_restrictions = rrp.hBaseRegQueryValue(
                dce, configuration_key["phkResult"], "EnrollmentAgentRights"
            )

            enrollment_restrictions = ActiveDirectorySecurity(enrollment_restrictions)

        except rrp.DCERPCSessionError:
            enrollment_restrictions = None

        return (
            edit_flags,
            ActiveDirectorySecurity(
                security_descriptor,
            ),
            enrollment_restrictions,
        )

    @property
    def certificate_templates(self) -> list["LDAPEntry"]:
        if self._certificate_templates is not None:
            return self._certificate_templates

        self._certificate_templates = []

        controls = [
            *security_descriptor_control(
                sdflags=(
                    (
                        SecurityInformation.OWNER_SECURITY_INFORMATION
                        | SecurityInformation.GROUP_SECURITY_INFORMATION
                        | SecurityInformation.DACL_SECURITY_INFORMATION
                    ).value
                )
            ),
            *DEFAULT_CONTROL_FLAGS,
        ]
        certificate_templates = self.search(
            "(objectclass=pkicertificatetemplate)",
            attributes=CertificateTemplate.ATTRIBUTES,
            search_base=self.ldap_connection.configuration_path,
            controls=controls,
        )

        for certificate_template in certificate_templates:
            self._certificate_templates.append(
                CertificateTemplate(certificate_template, self)
            )

        return self._certificate_templates

    @property
    def enrollment_services(self) -> list["EnrollmentService"]:
        if self._enrollment_services is not None:
            return self._enrollment_services

        enrollment_services = self.search(
            "(objectClass=pKIEnrollmentService)",
            search_base=self.ldap_connection.configuration_path,
            attributes=EnrollmentService.ATTRIBUTES,
        )

        self._enrollment_services = []

        for enrollment_service in enrollment_services:
            try:
                (
                    edit_flags,
                    security_descriptor,
                    enrollment_restrictions,
                ) = self.get_ca_security(enrollment_service)
                logging.debug("Got CA permissions from remote registry")
            except Exception:
                logging.warning("Failed to get CA permissions from remote registry")
                (edit_flags, security_descriptor, enrollment_restrictions) = (
                    0,
                    None,
                    None,
                )

            self._enrollment_services.append(
                EnrollmentService(
                    enrollment_service,
                    self,
                    edit_flags,
                    security_descriptor,
                    enrollment_restrictions,
                )
            )

        return self._enrollment_services

    @property
    def domain(self) -> str:
        if self._domain is not None:
            return self._domain

        domains = self.search(
            "(&(objectClass=domain)(distinguishedName=%s))"
            % self.ldap_connection.root_name_path,
            attributes=["name"],
        )
        if len(domains) == 0:
            logging.debug(
                    "Could not find domain root domain %s, trying default %s" 
                    % (self.ldap_connection.root_name_path, 
                    self.ldap_connection.default_path)
                    )

            domains = self.search(
                "(&(objectClass=domain)(distinguishedName=%s))"
                % self.ldap_connection.default_path,
                attributes=["name"],
            )

            if len(domains) == 0:
                raise Exception(
                    "Could not find domains: %s and %s" 
                    % (self.ldap_connection.root_name_path,
                    self.ldap_connection.default_path)
                )

        self._domain = domains[0]

        return self._domain

    @property
    def user(self) -> LDAPEntry:
        if self._user is not None:
            return self._user

        if self.options.user is not None:
            username = self.options.user
        else:
            username = self.target.username

        users = self.search(
            "(&(objectclass=user)(sAMAccountName=%s))" % username,
            attributes=["objectSid", "distinguishedName"],
        )

        if len(users) == 0:
            raise Exception("Could not find user with account name: %s" % username)

        self._user = users[0]

        return self._user

    @property
    def groups(self) -> list["LDAPEntry"]:
        if self._groups is not None:
            return self._groups

        self._groups = self.search(
            "(member:1.2.840.113556.1.4.1941:=%s)" % self.user.get("distinguishedName"),
            attributes="objectSid",
        )

        return self._groups

    @property
    def user_sids(self) -> list[str]:
        """List of effective SIDs for user"""
        if self._user_sids is not None:
            return self._user_sids

        self._user_sids = list(
            map(
                lambda entry: format_sid(entry.get_raw("objectSid")),
                [*self.groups, self.user],
            )
        )

        return self._user_sids


def find(options: argparse.Namespace):
    f = Find(options)
    f.run()
