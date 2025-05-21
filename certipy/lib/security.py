"""
Security module for parsing and interpreting Active Directory security descriptors.

This module provides classes for handling security descriptors related to:
- Active Directory objects
- Certificates
- Certificate Issuance Policies
- Certification Authorities
"""

import re
from typing import Any, Dict

from impacket.ldap import ldaptypes
from impacket.uuid import bin_to_string
from ldap3.protocol.formatters.formatters import format_sid

from certipy.lib.constants import (
    EXTENDED_RIGHTS_NAME_MAP,
    ActiveDirectoryRights,
    CertificateAuthorityRights,
    CertificateRights,
    IssuancePolicyRights,
)

# Access Control Entry flags
INHERITED_ACE = 0x10

SE_DACL_PRESENT = 0x0004
SE_DACL_AUTO_INHERITED = 0x0400
SE_SACL_AUTO_INHERITED = 0x0800
SE_DACL_PROTECTED = 0x1000
SE_SELF_RELATIVE = 0x8000


class SecurityDescriptorParser:
    """Base class for parsing security descriptors."""

    RIGHTS_TYPE = None  # Must be defined by subclasses

    def __init__(self, security_descriptor: bytes):
        """
        Initialize a security descriptor parser.

        Args:
            security_descriptor: Binary representation of a security descriptor
        """
        if self.RIGHTS_TYPE is None:
            raise NotImplementedError("Subclasses must define RIGHTS_TYPE")

        # Parse the security descriptor
        self.sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        self.sd.fromString(security_descriptor)

        # Extract owner SID
        self.owner = format_sid(self.sd["OwnerSid"].getData())

        # Dictionary to store access control entries by SID
        self.aces: Dict[str, Dict[str, Any]] = {}

        # Parse the ACEs
        self._parse_aces()

    def _parse_aces(self) -> None:
        """Parse the access control entries from the security descriptor."""
        pass  # To be implemented by subclasses


class ActiveDirectorySecurity(SecurityDescriptorParser):
    """Parser for Active Directory security descriptors."""

    RIGHTS_TYPE = ActiveDirectoryRights

    def _parse_aces(self) -> None:
        """
        Parse the access control entries from the security descriptor.

        This method extracts both standard rights and extended rights.
        """
        aces = self.sd["Dacl"]["Data"]

        # TODO: Handle DENIED ACEs

        for ace in aces:
            sid = format_sid(ace["Ace"]["Sid"].getData())

            # Initialize entry for this SID if not already present
            if sid not in self.aces:
                self.aces[sid] = {
                    "rights": self.RIGHTS_TYPE(0),
                    "extended_rights": [],
                    "inherited": bool(ace["AceFlags"] & INHERITED_ACE),
                }

            # Process standard access allowed ACE
            if ace["AceType"] == ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
                self.aces[sid]["rights"] |= self.RIGHTS_TYPE(ace["Ace"]["Mask"]["Mask"])

            # Process object-specific ACE (for extended rights)
            elif ace["AceType"] == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE and ace[
                "Ace"
            ]["Mask"].hasPriv(
                ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS
            ):

                self.aces[sid]["rights"] |= self.RIGHTS_TYPE(ace["Ace"]["Mask"]["Mask"])

                # Extract the specific extended right (identified by UUID)
                if ace["Ace"].hasFlag(
                    ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
                ):
                    uuid = bin_to_string(ace["Ace"]["ObjectType"]).lower()
                else:
                    # If no specific GUID is provided, this grants all extended rights
                    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb
                    uuid = EXTENDED_RIGHTS_NAME_MAP["All-Extended-Rights"]

                self.aces[sid]["extended_rights"].append(uuid)

    def to_bytes(self) -> bytes:
        """
        Convert the security descriptor to its binary representation.

        Returns:
            Binary representation of the security descriptor
        """
        return self.sd.getData()


class CertificateSecurity(ActiveDirectorySecurity):
    """Parser for certificate template security descriptors."""

    RIGHTS_TYPE = CertificateRights


class IssuancePolicySecurity(ActiveDirectorySecurity):
    """Parser for certificate issuance policy security descriptors."""

    RIGHTS_TYPE = IssuancePolicyRights


class CASecurity(SecurityDescriptorParser):
    """Parser for Certification Authority security descriptors."""

    RIGHTS_TYPE = CertificateAuthorityRights

    def _parse_aces(self) -> None:
        """
        Parse the access control entries from the security descriptor.

        CA security descriptors have a simpler structure than AD security descriptors.
        """
        aces = self.sd["Dacl"]["Data"]

        for ace in aces:
            sid = format_sid(ace["Ace"]["Sid"].getData())

            if sid not in self.aces:
                self.aces[sid] = {
                    "rights": self.RIGHTS_TYPE(0),
                    "extended_rights": [],  # CAs don't use extended rights, but keeping for consistency
                    "inherited": bool(ace["AceFlags"] & INHERITED_ACE),
                }

            if ace["AceType"] == ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
                mask = self.RIGHTS_TYPE(ace["Ace"]["Mask"]["Mask"])
                self.aces[sid]["rights"] |= mask


def is_admin_sid(sid: str) -> bool:
    """
    Check if a security identifier (SID) belongs to an administrative group.

    This function identifies built-in administrator accounts and groups by their well-known SIDs.

    Args:
        sid: The security identifier to check

    Returns:
        True if the SID belongs to an administrative group, False otherwise

    Common Admin SIDs:
    - S-1-5-21-*-498: Enterprise Read-Only Domain Controllers group
    - S-1-5-21-*-500: Built-in Administrator account
    - S-1-5-21-*-502: Krbtgt account
    - S-1-5-21-*-512: Domain Admins group
    - S-1-5-21-*-516: Domain Controllers group
    - S-1-5-21-*-518: Schema Admins group
    - S-1-5-21-*-519: Enterprise Admins group
    - S-1-5-21-*-521: Read-only Domain Controllers group
    - S-1-5-32-544: Built-in Administrators group
    - S-1-5-9: Enterprise Domain Controllers
    """
    admin_rid_pattern = "^S-1-5-21-.+-(498|500|502|512|516|518|519|521)$"
    builtin_admin_sids = ["S-1-5-9", "S-1-5-32-544"]

    return re.match(admin_rid_pattern, sid) is not None or sid in builtin_admin_sids


"""

def create_ace(sid, mask):
    nace = ACE()
    nace['AceType'] = ACCESS_ALLOWED_ACE.ACE_TYPE
    nace['AceFlags'] = 0x00
    acedata = ACCESS_ALLOWED_ACE()
    acedata['Mask'] = ACCESS_MASK()
    acedata['Mask']['Mask'] = mask
    acedata['Sid'] = LDAP_SID()
    acedata['Sid'].fromCanonical(sid)
    nace['Ace'] = acedata
    return nace

def create_sd(sid):
    sd = SR_SECURITY_DESCRIPTOR()
    sd['Revision'] = b'\x01'
    sd['Sbz1'] = b'\x00'
    sd['Control'] = 32772
    sd['OwnerSid'] = LDAP_SID()
    sd['OwnerSid'].fromCanonical('S-1-5-18')
    sd['GroupSid'] = LDAP_SID()
    sd['GroupSid'].fromCanonical('S-1-5-18')
    sd['Sacl'] = b''

    acl = ACL()
    acl['AclRevision'] = 2
    acl['Sbz1'] = 0
    acl['Sbz2'] = 0
    acl.aces = []
    acl.aces.append(create_ace(sid, 3))
    acl.aces.append(create_ace('S-1-1-0',2))
    sd['Dacl'] = acl
    return sd
"""


def create_authenticated_users_sd() -> ldaptypes.SR_SECURITY_DESCRIPTOR:
    """
    Create a security descriptor for the "Authenticated Users" group.
    This security descriptor grants the "Authenticated Users" group
    the right to read the object and its properties.
    """
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = (
        SE_DACL_PRESENT
        | SE_DACL_AUTO_INHERITED
        | SE_SACL_AUTO_INHERITED
        | SE_DACL_PROTECTED
        | SE_SELF_RELATIVE
    )
    sd["OwnerSid"] = ldaptypes.LDAP_SID()
    sd["OwnerSid"].fromCanonical("S-1-5-11")
    sd["GroupSid"] = b""
    sd["Sacl"] = b""

    ace = ldaptypes.ACE()
    ace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    ace["AceFlags"] = 0
    ace_data = ldaptypes.ACCESS_ALLOWED_ACE()
    ace_data["Mask"] = ldaptypes.ACCESS_MASK()
    ace_data["Mask"]["Mask"] = CertificateRights.GENERIC_ALL
    ace_data["Sid"] = ldaptypes.LDAP_SID()
    ace_data["Sid"].fromCanonical("S-1-5-11")
    ace["Ace"] = ace_data

    acl = ldaptypes.ACL()
    acl["AclRevision"] = 2
    acl["Sbz1"] = 0
    acl["Sbz2"] = 0
    acl.aces = []
    acl.aces.append(ace)
    sd["Dacl"] = acl

    # Convert aces to data
    sd_data = sd.getData()
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd.fromString(sd_data)

    return sd
