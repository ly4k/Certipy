import re

from impacket.ldap import ldaptypes
from impacket.uuid import bin_to_string
from ldap3.protocol.formatters.formatters import format_sid

INHERITED_ACE = 0x10

from certipy.lib.constants import (
    ACTIVE_DIRECTORY_RIGHTS,
    CERTIFICATE_RIGHTS,
    CERTIFICATION_AUTHORITY_RIGHTS,
    EXTENDED_RIGHTS_NAME_MAP,
    ISSUANCE_POLICY_RIGHTS,
)


class ActiveDirectorySecurity:
    RIGHTS_TYPE = ACTIVE_DIRECTORY_RIGHTS

    def __init__(
        self,
        security_descriptor: bytes,
    ):
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd.fromString(security_descriptor)
        self.sd = sd

        self.owner = format_sid(sd["OwnerSid"].getData())
        self.aces = {}

        aces = sd["Dacl"]["Data"]
        for ace in aces:
            sid = format_sid(ace["Ace"]["Sid"].getData())

            if sid not in self.aces:
                self.aces[sid] = {
                    "rights": self.RIGHTS_TYPE(0),
                    "extended_rights": [],
                    "inherited": ace["AceFlags"] & INHERITED_ACE == INHERITED_ACE,
                }

            mask = self.RIGHTS_TYPE(ace["Ace"]["Mask"]["Mask"])
            if ace["AceType"] == ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
                self.aces[sid]["rights"] |= mask

                if self.RIGHTS_TYPE.EXTENDED_RIGHT & mask:
                    self.aces[sid]["extended_rights"].append(EXTENDED_RIGHTS_NAME_MAP["All-Extended-Rights"])

            if ace["AceType"] == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE and \
               self.RIGHTS_TYPE.EXTENDED_RIGHT & mask and \
               ace['Ace'].hasFlag(ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):

                uuid = bin_to_string(ace["Ace"]["ObjectType"]).lower()
                self.aces[sid]["extended_rights"].append(uuid)


class CertifcateSecurity(ActiveDirectorySecurity):
    RIGHTS_TYPE = CERTIFICATE_RIGHTS

class IssuancePolicySecurity(ActiveDirectorySecurity):
    RIGHTS_TYPE = ISSUANCE_POLICY_RIGHTS


class CASecurity:
    RIGHTS_TYPE = CERTIFICATION_AUTHORITY_RIGHTS

    def __init__(
        self,
        security_descriptor: bytes,
    ):
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd.fromString(security_descriptor)
        self.sd = sd

        self.owner = format_sid(sd["OwnerSid"].getData())
        self.aces = {}

        aces = sd["Dacl"]["Data"]
        for ace in aces:
            sid = format_sid(ace["Ace"]["Sid"].getData())

            if sid not in self.aces:
                self.aces[sid] = {
                    "rights": self.RIGHTS_TYPE(0),
                    "extended_rights": [],
                    "inherited": ace["AceFlags"] & INHERITED_ACE == INHERITED_ACE,
                }

            mask = self.RIGHTS_TYPE(ace["Ace"]["Mask"]["Mask"])
            if ace["AceType"] == ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
                self.aces[sid]["rights"] |= mask


def is_admin_sid(sid: str):
    return (
        re.match("^S-1-5-21-.+-(498|500|502|512|516|518|519|521)$", sid) is not None
        or sid == "S-1-5-9"
        or sid == "S-1-5-32-544"
    )
