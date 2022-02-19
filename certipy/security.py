from impacket.ldap import ldaptypes
from impacket.uuid import bin_to_string
from ldap3.protocol.formatters.formatters import format_sid

from certipy.constants import ACTIVE_DIRECTORY_RIGHTS


class ActiveDirectorySecurity:
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
                    "rights": ACTIVE_DIRECTORY_RIGHTS(0),
                    "extended_rights": [],
                }

            if ace["AceType"] == ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
                self.aces[sid]["rights"] |= ACTIVE_DIRECTORY_RIGHTS(
                    ace["Ace"]["Mask"]["Mask"]
                )

            if ace["AceType"] == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                if ace["Ace"]["ObjectTypeLen"] == 0:
                    uuid = bin_to_string(ace["Ace"]["InheritedObjectType"]).lower()
                else:
                    uuid = bin_to_string(ace["Ace"]["ObjectType"]).lower()

                self.aces[sid]["extended_rights"].append(uuid)
