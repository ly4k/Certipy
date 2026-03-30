"""
BloodHound CE v6 JSON output formatter for Certipy.

This module converts Certipy's LDAP enumeration data into BloodHound CE v6
compatible JSON files that can be uploaded directly into BloodHound CE.

Supported data types:
- certtemplates: Certificate templates
- enterprisecas: Enterprise Certificate Authorities
- issuancepolicies: Issuance policies (OIDs)

Reference: https://github.com/SpecterOps/BloodHound (v6 fixture format)
"""

import json
import os
import zipfile
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from impacket.ldap import ldaptypes
from impacket.uuid import bin_to_string
from ldap3.protocol.formatters.formatters import format_sid

from certipy.lib.constants import (
    EXTENDED_RIGHTS_NAME_MAP,
    WELLKNOWN_SIDS,
    ActiveDirectoryRights,
    CertificateAuthorityRights,
    CertificateNameFlag,
    CertificateRights,
    EnrollmentFlag,
    IssuancePolicyRights,
    OID_TO_STR_MAP,
)
from certipy.lib.ldap import LDAPEntry
from certipy.lib.logger import logging
from certipy.lib.security import INHERITED_ACE, SE_DACL_PROTECTED
from certipy.lib.time import filetime_to_str

# BloodHound CE v6 format version
BH_VERSION = 6

# Collection method bitmask (matches SharpHound ADCS collection)
BH_METHODS_ADCS = 521215
BH_METHODS_ISSUANCE = 262144


def _get_object_identifier(entry: LDAPEntry) -> str:
    """Get the objectGUID as a string suitable for BloodHound CE."""
    guid = entry.get("objectGUID")
    if guid is None:
        return ""
    return str(guid).lstrip("{").rstrip("}").upper()


def _epoch_from_whencreated(entry: LDAPEntry) -> int:
    """Convert whenCreated to Unix epoch seconds."""
    when_created = entry.get("whenCreated")
    if when_created is None:
        return 0
    if isinstance(when_created, datetime):
        return int(when_created.replace(tzinfo=timezone.utc).timestamp())
    if isinstance(when_created, (int, float)):
        return int(when_created)
    try:
        dt = datetime.strptime(str(when_created), "%Y%m%d%H%M%S.0Z")
        return int(dt.replace(tzinfo=timezone.utc).timestamp())
    except (ValueError, TypeError):
        return 0


def _get_domain_upper(connection) -> str:
    """Get domain name in uppercase."""
    domain = getattr(connection, "domain", None)
    if domain:
        return domain.upper()
    return ""


def _get_domain_sid(connection) -> str:
    """Get the domain SID."""
    return getattr(connection, "domain_sid", None) or ""


def _get_dn_upper(entry: LDAPEntry) -> str:
    """Get the distinguishedName in uppercase."""
    dn = entry.get("distinguishedName")
    if dn is None:
        # Reconstruct from entry's raw_dn if available
        dn = entry.get("dn", "")
    return str(dn).upper() if dn else ""


def _format_bh_name(name: str, domain: str) -> str:
    """Format a name as NAME@DOMAIN for BloodHound CE."""
    if not name:
        return ""
    name = name.upper()
    domain = domain.upper()
    if "@" in name:
        return name
    return f"{name}@{domain}"


def _get_container_dn(entry: LDAPEntry) -> str:
    """Get the parent container DN from an entry's DN."""
    dn = _get_dn_upper(entry)
    if not dn:
        return ""
    parts = dn.split(",", 1)
    return parts[1] if len(parts) > 1 else ""


# =========================================================================
# ACE conversion
# =========================================================================


def _parse_sd_to_aces(
    security_descriptor: bytes,
    rights_type: str = "certificate",
) -> Tuple[List[Dict[str, Any]], str, bool]:
    """
    Parse a security descriptor into BloodHound CE ACE format.

    Args:
        security_descriptor: Raw binary security descriptor
        rights_type: One of "certificate", "issuance_policy", "ca"

    Returns:
        Tuple of (aces_list, owner_sid, is_acl_protected)
    """
    if security_descriptor is None:
        return [], "", False

    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd.fromString(security_descriptor)

    owner_sid = format_sid(sd["OwnerSid"].getData())
    is_acl_protected = bool(sd["Control"] & SE_DACL_PROTECTED)

    aces = []

    # Add owner ACE
    aces.append({
        "PrincipalSID": owner_sid,
        "PrincipalType": _resolve_principal_type(owner_sid),
        "RightName": "Owns",
        "IsInherited": False,
    })

    dacl_aces = sd["Dacl"]["Data"]

    for ace in dacl_aces:
        sid = format_sid(ace["Ace"]["Sid"].getData())
        inherited = bool(ace["AceFlags"] & INHERITED_ACE)
        principal_type = _resolve_principal_type(sid)

        if rights_type == "ca":
            _process_ca_ace(ace, sid, principal_type, inherited, aces)
        else:
            _process_certificate_ace(ace, sid, principal_type, inherited, aces)

    return aces, owner_sid, is_acl_protected


def _process_certificate_ace(
    ace, sid: str, principal_type: str, inherited: bool, aces: list
):
    """Process a certificate/issuance policy ACE into BH CE format."""
    if ace["AceType"] == ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
        mask = ace["Ace"]["Mask"]["Mask"]
        _add_rights_from_mask(mask, sid, principal_type, inherited, aces, "certificate")

        # Standard ACCESS_ALLOWED_ACE with control access bit = Enroll
        if mask & ActiveDirectoryRights.EXTENDED_RIGHT:
            aces.append({
                "PrincipalSID": sid,
                "PrincipalType": principal_type,
                "RightName": "Enroll",
                "IsInherited": inherited,
            })

    elif ace["AceType"] == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
        mask = ace["Ace"]["Mask"]["Mask"]
        _add_rights_from_mask(mask, sid, principal_type, inherited, aces, "certificate")

        if ace["Ace"]["Mask"].hasPriv(
            ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS
        ):
            if ace["Ace"].hasFlag(
                ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
            ):
                uuid = bin_to_string(ace["Ace"]["ObjectType"]).lower()
                enroll_guid = EXTENDED_RIGHTS_NAME_MAP.get("Enroll", "").lower()
                all_extended_guid = EXTENDED_RIGHTS_NAME_MAP.get(
                    "All-Extended-Rights", ""
                ).lower()

                if uuid == enroll_guid:
                    aces.append({
                        "PrincipalSID": sid,
                        "PrincipalType": principal_type,
                        "RightName": "Enroll",
                        "IsInherited": inherited,
                    })
                elif uuid == all_extended_guid:
                    aces.append({
                        "PrincipalSID": sid,
                        "PrincipalType": principal_type,
                        "RightName": "AllExtendedRights",
                        "IsInherited": inherited,
                    })
            else:
                # No ObjectType = all extended rights
                aces.append({
                    "PrincipalSID": sid,
                    "PrincipalType": principal_type,
                    "RightName": "AllExtendedRights",
                    "IsInherited": inherited,
                })


def _process_ca_ace(ace, sid: str, principal_type: str, inherited: bool, aces: list):
    """Process a CA security ACE into BH CE format."""
    if ace["AceType"] == ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
        mask = CertificateAuthorityRights(ace["Ace"]["Mask"]["Mask"])

        if CertificateAuthorityRights.MANAGE_CA in mask:
            aces.append({
                "PrincipalSID": sid,
                "PrincipalType": principal_type,
                "RightName": "ManageCA",
                "IsInherited": inherited,
            })

        if CertificateAuthorityRights.MANAGE_CERTIFICATES in mask:
            aces.append({
                "PrincipalSID": sid,
                "PrincipalType": principal_type,
                "RightName": "ManageCertificates",
                "IsInherited": inherited,
            })

        if CertificateAuthorityRights.ENROLL in mask:
            aces.append({
                "PrincipalSID": sid,
                "PrincipalType": principal_type,
                "RightName": "Enroll",
                "IsInherited": inherited,
            })


def _add_rights_from_mask(
    mask: int, sid: str, principal_type: str, inherited: bool, aces: list, context: str
):
    """Add generic AD rights (WriteDacl, WriteOwner, GenericAll, GenericWrite) from a mask."""
    rights = CertificateRights(mask)

    if CertificateRights.GENERIC_ALL in rights:
        aces.append({
            "PrincipalSID": sid,
            "PrincipalType": principal_type,
            "RightName": "GenericAll",
            "IsInherited": inherited,
        })
        return  # GenericAll encompasses everything

    if CertificateRights.WRITE_DACL in rights:
        aces.append({
            "PrincipalSID": sid,
            "PrincipalType": principal_type,
            "RightName": "WriteDacl",
            "IsInherited": inherited,
        })

    if CertificateRights.WRITE_OWNER in rights:
        aces.append({
            "PrincipalSID": sid,
            "PrincipalType": principal_type,
            "RightName": "WriteOwner",
            "IsInherited": inherited,
        })

    if CertificateRights.GENERIC_WRITE in rights:
        aces.append({
            "PrincipalSID": sid,
            "PrincipalType": principal_type,
            "RightName": "GenericWrite",
            "IsInherited": inherited,
        })


def _resolve_principal_type(sid: str) -> str:
    """Resolve a SID to a BloodHound principal type."""
    if sid in WELLKNOWN_SIDS:
        _, obj_type = WELLKNOWN_SIDS[sid]
        return _normalize_bh_type(obj_type)

    # Default heuristic: domain SIDs with certain RIDs
    parts = sid.rsplit("-", 1)
    if len(parts) == 2:
        try:
            rid = int(parts[1])
            # Well-known group RIDs
            if rid in (512, 513, 514, 515, 516, 517, 518, 519, 520, 521, 522, 526, 527, 553):
                return "Group"
            # Well-known user RIDs
            if rid in (500, 501, 502):
                return "User"
        except ValueError:
            pass

    # Default to Group (safest assumption for BH CE)
    return "Group"


def _normalize_bh_type(obj_type: str) -> str:
    """Normalize object type string to BH CE format."""
    obj_type = obj_type.upper()
    if obj_type in ("GROUP",):
        return "Group"
    if obj_type in ("USER",):
        return "User"
    if obj_type in ("COMPUTER",):
        return "Computer"
    return "Group"


# =========================================================================
# Certificate Template conversion
# =========================================================================


def convert_template(entry: LDAPEntry, connection) -> Dict[str, Any]:
    """
    Convert a Certipy certificate template LDAP entry to BH CE v6 format.

    Args:
        entry: Certificate template LDAP entry
        connection: LDAP/ADWS connection for domain info

    Returns:
        BloodHound CE v6 formatted certificate template object
    """
    domain = _get_domain_upper(connection)
    domain_sid = _get_domain_sid(connection)
    name = entry.get("cn") or entry.get("name") or ""

    # Parse security descriptor for ACEs
    sd_bytes = entry.get("nTSecurityDescriptor")
    aces, owner_sid, is_acl_protected = _parse_sd_to_aces(sd_bytes, "certificate")

    # Process flags
    enrollment_flag_raw = entry.get("msPKI-Enrollment-Flag")
    enrollment_flag_val = int(enrollment_flag_raw) if enrollment_flag_raw is not None else 0
    enrollment_flag = EnrollmentFlag(enrollment_flag_val)

    cert_name_flag_raw = entry.get("msPKI-Certificate-Name-Flag")
    cert_name_flag_val = int(cert_name_flag_raw) if cert_name_flag_raw is not None else 0
    cert_name_flag = CertificateNameFlag(cert_name_flag_val)

    schema_version = int(entry.get("msPKI-Template-Schema-Version") or 1)
    authorized_signatures = int(entry.get("msPKI-RA-Signature") or 0)

    # Process EKUs (keep as raw OIDs for BH CE)
    eku_raw = entry.get_raw("pKIExtendedKeyUsage")
    if not isinstance(eku_raw, list):
        eku_raw = [] if eku_raw is None else [eku_raw]
    ekus = [e.decode() if isinstance(e, bytes) else str(e) for e in eku_raw]

    # Process application policies
    app_policies_raw = entry.get_raw("msPKI-RA-Application-Policies")
    if not isinstance(app_policies_raw, list):
        app_policies_raw = [] if app_policies_raw is None else [app_policies_raw]
    application_policies = [
        p.decode() if isinstance(p, bytes) else str(p) for p in app_policies_raw
    ]

    # Process issuance policies
    issuance_policies = entry.get("msPKI-Certificate-Policy")
    if not isinstance(issuance_policies, list):
        issuance_policies = [] if issuance_policies is None else [issuance_policies]

    # Determine effective EKUs
    effective_ekus = ekus if ekus else []

    # Determine authentication capability
    auth_ekus = {
        "1.3.6.1.5.5.7.3.2",   # Client Authentication
        "1.3.6.1.4.1.311.20.2.2",  # Smart Card Logon
        "1.3.6.1.5.2.3.4",     # PKINIT Client Authentication
    }
    any_purpose = not ekus or "2.5.29.37.0" in ekus
    authentication_enabled = any_purpose or bool(set(ekus) & auth_ekus)

    enrollee_supplies_subject = bool(
        CertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT & cert_name_flag_val
    )

    subject_alt_require_upn = bool(
        CertificateNameFlag.SUBJECT_ALT_REQUIRE_UPN & cert_name_flag_val
    )

    requires_manager_approval = bool(
        EnrollmentFlag.PEND_ALL_REQUESTS & enrollment_flag_val
    )

    no_security_extension = bool(
        EnrollmentFlag.NO_SECURITY_EXTENSION & enrollment_flag_val
    )

    # Validity/renewal periods
    validity_period = entry.get("validity_period")
    if validity_period is None:
        exp_bytes = entry.get("pKIExpirationPeriod")
        validity_period = filetime_to_str(exp_bytes) if exp_bytes else "0"

    renewal_period = entry.get("renewal_period")
    if renewal_period is None:
        overlap_bytes = entry.get("pKIOverlapPeriod")
        renewal_period = filetime_to_str(overlap_bytes) if overlap_bytes else "0"

    # Build enrollment flag display string
    enrollment_flag_names = ", ".join(
        f.name for f in enrollment_flag.to_list() if f.name
    )
    cert_name_flag_names = ", ".join(
        f.name for f in cert_name_flag.to_list() if f.name
    )

    # OID for the template
    oid = entry.get("msPKI-Cert-Template-OID") or ""

    properties = {
        "domain": domain,
        "name": _format_bh_name(name, domain),
        "distinguishedname": _get_dn_upper(entry),
        "domainsid": domain_sid,
        "description": None,
        "whencreated": _epoch_from_whencreated(entry),
        "validityperiod": str(validity_period),
        "renewalperiod": str(renewal_period),
        "schemaversion": schema_version,
        "displayname": entry.get("displayName") or name,
        "oid": oid,
        "enrollmentflag": enrollment_flag_names,
        "requiresmanagerapproval": requires_manager_approval,
        "nosecurityextension": no_security_extension,
        "certificatenameflag": cert_name_flag_names,
        "enrolleesuppliessubject": enrollee_supplies_subject,
        "subjectaltrequireupn": subject_alt_require_upn,
        "ekus": ekus,
        "certificateapplicationpolicy": application_policies,
        "authorizedsignatures": authorized_signatures,
        "applicationpolicies": application_policies,
        "issuancepolicies": issuance_policies,
        "effectiveekus": effective_ekus,
        "authenticationenabled": authentication_enabled,
    }

    return {
        "Properties": properties,
        "Aces": aces,
        "ObjectIdentifier": _get_object_identifier(entry),
        "IsDeleted": False,
        "IsACLProtected": is_acl_protected,
        "ContainedBy": {
            "ObjectIdentifier": _get_container_dn(entry),
            "ObjectType": "Container",
        },
    }


# =========================================================================
# Enterprise CA conversion
# =========================================================================


def convert_enterprise_ca(
    entry: LDAPEntry,
    connection,
    templates: Optional[List[LDAPEntry]] = None,
) -> Dict[str, Any]:
    """
    Convert a Certipy CA LDAP entry to BH CE v6 Enterprise CA format.

    Args:
        entry: Certificate authority LDAP entry
        connection: LDAP/ADWS connection for domain info
        templates: List of all templates (to build EnabledCertTemplates)

    Returns:
        BloodHound CE v6 formatted enterprise CA object
    """
    domain = _get_domain_upper(connection)
    domain_sid = _get_domain_sid(connection)
    ca_name = entry.get("name") or entry.get("cn") or ""

    object_id = _get_object_identifier(entry)

    # Build properties
    dns_hostname = entry.get("dNSHostName") or ""

    # Certificate thumbprint
    cert_thumbprint = ""
    cert_chain = []
    has_basic_constraints = False
    basic_constraint_path_length = 0

    ca_cert_raw = entry.get("cACertificate")
    if ca_cert_raw and len(ca_cert_raw) > 0:
        try:
            from asn1crypto import x509
            import hashlib
            cert_data = ca_cert_raw[0] if isinstance(ca_cert_raw, list) else ca_cert_raw
            cert_thumbprint = hashlib.sha1(cert_data).hexdigest().upper()
            cert_chain = [cert_thumbprint]

            cert = x509.Certificate.load(cert_data)
            tbs = cert["tbs_certificate"]
            extensions = tbs["extensions"]
            if extensions:
                for ext in extensions:
                    if ext["extn_id"].dotted == "2.5.29.19":  # basicConstraints
                        has_basic_constraints = True
                        bc_value = ext["extn_value"].parsed
                        if bc_value and bc_value["path_len_constraint"].native is not None:
                            basic_constraint_path_length = bc_value["path_len_constraint"].native
        except Exception:
            pass

    # CA security from registry data
    ca_security_data = []
    ca_security_collected = False
    user_specifies_san = False
    user_specifies_san_collected = False

    ca_security = entry.get("security")
    if ca_security is not None:
        ca_security_collected = True
        # Owner ACE
        ca_security_data.append({
            "PrincipalSID": ca_security.owner,
            "PrincipalType": _resolve_principal_type(ca_security.owner),
            "RightName": "Owns",
            "IsInherited": False,
        })
        for sid, rights in ca_security.aces.items():
            principal_type = _resolve_principal_type(sid)
            ca_rights = rights["rights"]
            inherited = rights.get("inherited", False)

            if CertificateAuthorityRights.MANAGE_CA in ca_rights:
                ca_security_data.append({
                    "PrincipalSID": sid,
                    "PrincipalType": principal_type,
                    "RightName": "ManageCA",
                    "IsInherited": inherited,
                })
            if CertificateAuthorityRights.MANAGE_CERTIFICATES in ca_rights:
                ca_security_data.append({
                    "PrincipalSID": sid,
                    "PrincipalType": principal_type,
                    "RightName": "ManageCertificates",
                    "IsInherited": inherited,
                })
            if CertificateAuthorityRights.ENROLL in ca_rights:
                ca_security_data.append({
                    "PrincipalSID": sid,
                    "PrincipalType": principal_type,
                    "RightName": "Enroll",
                    "IsInherited": inherited,
                })

    # User Specified SAN
    user_specified_san = entry.get("user_specified_san")
    if user_specified_san is not None and user_specified_san != "Unknown":
        user_specifies_san_collected = True
        user_specifies_san = user_specified_san == "Enabled"

    # Build LDAP object ACEs (from the LDAP object itself, not CA registry)
    # Enterprise CAs in LDAP may not have nTSecurityDescriptor queried,
    # so we use an empty ACE list for the LDAP object ACEs
    ldap_aces = []

    # EnabledCertTemplates
    enabled_cert_templates = []
    ca_template_names = entry.get("certificateTemplates") or []
    if templates:
        for template in templates:
            t_name = template.get("name")
            if t_name in ca_template_names:
                t_guid = _get_object_identifier(template)
                enabled_cert_templates.append({
                    "ObjectIdentifier": t_guid,
                    "ObjectType": "CertTemplate",
                })

    # HostingComputer - we need the SID of the computer hosting the CA
    # We don't have this from Certipy's data, so use the DNS hostname as identifier
    hosting_computer = dns_hostname.upper()

    properties = {
        "domain": domain,
        "name": _format_bh_name(ca_name, domain),
        "distinguishedname": _get_dn_upper(entry),
        "domainsid": domain_sid,
        "description": None,
        "whencreated": _epoch_from_whencreated(entry),
        "flags": "",
        "caname": ca_name,
        "dnshostname": dns_hostname.upper(),
        "certthumbprint": cert_thumbprint,
        "certname": cert_thumbprint,
        "certchain": cert_chain,
        "hasbasicconstraints": has_basic_constraints,
        "basicconstraintpathlength": basic_constraint_path_length,
        "casecuritycollected": ca_security_collected,
        "enrollmentagentrestrictionscollected": False,
        "isuserspecifiessanenabledcollected": user_specifies_san_collected,
    }

    return {
        "Properties": properties,
        "Aces": ldap_aces,
        "ObjectIdentifier": object_id,
        "IsDeleted": False,
        "IsACLProtected": False,
        "ContainedBy": {
            "ObjectIdentifier": _get_container_dn(entry),
            "ObjectType": "Container",
        },
        "HostingComputer": hosting_computer,
        "CARegistryData": {
            "CASecurity": {
                "Data": ca_security_data,
                "Collected": ca_security_collected,
                "FailureReason": None,
            },
            "EnrollmentAgentRestrictions": {
                "Restrictions": [],
                "Collected": False,
                "FailureReason": None,
            },
            "IsUserSpecifiesSanEnabled": {
                "Value": user_specifies_san,
                "Collected": user_specifies_san_collected,
                "FailureReason": None,
            },
        },
        "EnabledCertTemplates": enabled_cert_templates,
    }


# =========================================================================
# Issuance Policy conversion
# =========================================================================


def convert_issuance_policy(entry: LDAPEntry, connection) -> Dict[str, Any]:
    """
    Convert a Certipy issuance policy LDAP entry to BH CE v6 format.

    Args:
        entry: Issuance policy LDAP entry
        connection: LDAP/ADWS connection for domain info

    Returns:
        BloodHound CE v6 formatted issuance policy object
    """
    domain = _get_domain_upper(connection)
    domain_sid = _get_domain_sid(connection)
    name = entry.get("cn") or entry.get("name") or ""
    display_name = entry.get("displayName") or name
    oid_value = entry.get("msPKI-Cert-Template-OID") or ""

    # Parse security descriptor
    sd_bytes = entry.get("nTSecurityDescriptor")
    aces, owner_sid, is_acl_protected = _parse_sd_to_aces(sd_bytes, "issuance_policy")

    # Group link
    linked_group = entry.get("msDS-OIDToGroupLink")
    if linked_group:
        # linked_group is a DN - we'd need the SID, but we may not have it
        # Use the DN as identifier
        group_link = {
            "ObjectIdentifier": str(linked_group),
            "ObjectType": "Group",
        }
    else:
        group_link = {
            "ObjectIdentifier": None,
            "ObjectType": "Base",
        }

    properties = {
        "domain": domain,
        "name": _format_bh_name(name, domain),
        "distinguishedname": _get_dn_upper(entry),
        "domainsid": domain_sid,
        "isaclprotected": is_acl_protected,
        "description": None,
        "whencreated": _epoch_from_whencreated(entry),
        "displayname": display_name,
        "oid": oid_value,
    }

    return {
        "Properties": properties,
        "Aces": aces,
        "ObjectIdentifier": _get_object_identifier(entry),
        "IsDeleted": False,
        "IsACLProtected": is_acl_protected,
        "ContainedBy": {
            "ObjectIdentifier": _get_container_dn(entry),
            "ObjectType": "Container",
        },
        "GroupLink": group_link,
    }


# =========================================================================
# Main output function
# =========================================================================


def _write_bh_json(data: List[Dict], meta_type: str, methods: int, output_path: str):
    """Write a single BloodHound CE v6 JSON file."""
    output = {
        "data": data,
        "meta": {
            "methods": methods,
            "type": meta_type,
            "count": len(data),
            "version": BH_VERSION,
        },
    }

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, default=str)


def generate_bloodhound_output(
    templates: List[LDAPEntry],
    cas: List[LDAPEntry],
    oids: List[LDAPEntry],
    connection,
    prefix: str,
) -> List[str]:
    """
    Generate BloodHound CE v6 compatible JSON files and package them into a zip.

    Args:
        templates: List of certificate template LDAP entries
        cas: List of certificate authority LDAP entries
        oids: List of issuance policy LDAP entries
        connection: LDAP/ADWS connection for domain info
        prefix: Output file prefix

    Returns:
        List of output file paths created
    """
    output_files = []

    # Convert certificate templates
    if templates:
        logging.info("Converting certificate templates to BloodHound CE format")
        bh_templates = []
        for template in templates:
            try:
                bh_templates.append(convert_template(template, connection))
            except Exception as e:
                t_name = template.get("cn") or template.get("name") or "Unknown"
                logging.warning(
                    f"Failed to convert template {t_name!r} to BloodHound CE format: {e}"
                )

        if bh_templates:
            path = f"{prefix}_certtemplates.json"
            _write_bh_json(bh_templates, "certtemplates", BH_METHODS_ADCS, path)
            output_files.append(path)
            logging.info(
                f"Wrote {len(bh_templates)} certificate templates to {path!r}"
            )

    # Convert enterprise CAs
    if cas:
        logging.info("Converting certificate authorities to BloodHound CE format")
        bh_cas = []
        for ca in cas:
            try:
                bh_cas.append(convert_enterprise_ca(ca, connection, templates))
            except Exception as e:
                ca_name = ca.get("name") or "Unknown"
                logging.warning(
                    f"Failed to convert CA {ca_name!r} to BloodHound CE format: {e}"
                )

        if bh_cas:
            path = f"{prefix}_enterprisecas.json"
            _write_bh_json(bh_cas, "enterprisecas", BH_METHODS_ADCS, path)
            output_files.append(path)
            logging.info(f"Wrote {len(bh_cas)} enterprise CAs to {path!r}")

    # Convert issuance policies
    if oids:
        logging.info("Converting issuance policies to BloodHound CE format")
        bh_oids = []
        for oid in oids:
            try:
                bh_oids.append(convert_issuance_policy(oid, connection))
            except Exception as e:
                oid_name = oid.get("cn") or "Unknown"
                logging.warning(
                    f"Failed to convert issuance policy {oid_name!r} to BloodHound CE format: {e}"
                )

        if bh_oids:
            path = f"{prefix}_issuancepolicies.json"
            _write_bh_json(bh_oids, "issuancepolicies", BH_METHODS_ISSUANCE, path)
            output_files.append(path)
            logging.info(f"Wrote {len(bh_oids)} issuance policies to {path!r}")

    # Package all JSON files into a zip for easy upload
    if output_files:
        zip_path = f"{prefix}_Certipy_BloodHound.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for fpath in output_files:
                zf.write(fpath, os.path.basename(fpath))
        logging.info(f"Packaged BloodHound CE files into {zip_path!r}")
        output_files.append(zip_path)

    return output_files
