import re

from impacket.ldap import ldaptypes
from impacket.uuid import bin_to_string
from ldap3.protocol.formatters.formatters import format_sid

INHERITED_ACE = 0x10

from certipy.lib.constants import (
    ACTIVE_DIRECTORY_RIGHTS,
    CERTIFICATE_RIGHTS,
    CERTIFICATION_AUTHORITY_RIGHTS,
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

            if ace["AceType"] == ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
                self.aces[sid]["rights"] |= self.RIGHTS_TYPE(ace["Ace"]["Mask"]["Mask"])

            # Control permissions will not take effect if the ADS_RIGHT_DS_CONTROL_ACCESS flag is not set(preventing
            # false positive by checking this bit flag).
            #
            # InheritedObjectType means the type of child object that can inherit the ACE, not extended right, for
            # certificateTemplate object, the DACL flag bit SE_DACL_PROTECTED is set by default witch  prevents the
            # DACL of the security descriptor from being modified by inheritable ACEs, in that case, the
            # InheritedObjectType should be allways empty.
            # there might be false positive while denied permission is set, but that is complicated:<
            # TODO Add denied permission judgment
            if ace["AceType"] == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE \
                    and ace['Ace']['Mask'].hasPriv(ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS) \
                    and ace['Ace'].hasFlag(ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                uuid = bin_to_string(ace["Ace"]["ObjectType"]).lower()
                self.aces[sid]["extended_rights"].append(uuid)


class CASecurity(ActiveDirectorySecurity):
    RIGHTS_TYPE = CERTIFICATION_AUTHORITY_RIGHTS


class CertifcateSecurity(ActiveDirectorySecurity):
    RIGHTS_TYPE = CERTIFICATE_RIGHTS


def is_admin_sid(sid: str):
    return (
        re.match("^S-1-5-21-.+-(498|500|502|512|516|518|519|521)$", sid) is not None
        or sid == "S-1-5-9"
        or sid == "S-1-5-32-544"
    )
