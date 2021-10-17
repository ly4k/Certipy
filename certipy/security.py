# Certipy - Active Directory certificate abuse
#
# Description:
#   Various structures and helpers for AD security
#
# Authors:
#   @ly4k (https://github.com/ly4k)
#
# References:
#   https://github.com/GhostPack/Certify/blob/2b1530309c0c5eaf41b2505dfd5a68c83403d031/Certify/Lib/DisplayUtil.cs#L316
#   https://github.com/GhostPack/Certify/blob/2b1530309c0c5eaf41b2505dfd5a68c83403d031/Certify/Lib/DisplayUtil.cs#L323
#

import re

from impacket.ldap import ldaptypes
from impacket.uuid import bin_to_string
from ldap3.protocol.formatters.formatters import format_sid

from certipy.constants import ACTIVE_DIRECTORY_RIGHTS

LOW_PRIV_SID_REGEX = re.compile("^S-1-5-21-.+-(513|515|545)$")
ADMIN_SID_REGEX = re.compile("^S-1-5-21-.+-(498|500|502|512|516|518|519|521)$")


class ActiveDirectorySecurity:
    def __init__(
        self,
        security_descriptor: bytes,
    ):
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd.fromString(security_descriptor)
        self._sd = sd

        self._owner = format_sid(sd["OwnerSid"].getData())
        self._aces = {}

        aces = sd["Dacl"]["Data"]
        for ace in aces:
            sid = format_sid(ace["Ace"]["Sid"].getData())

            if sid not in self._aces:
                self._aces[sid] = {
                    "rights": ACTIVE_DIRECTORY_RIGHTS(0),
                    "extended_rights": [],
                }

            if ace["AceType"] == ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
                self._aces[sid]["rights"] |= ACTIVE_DIRECTORY_RIGHTS(
                    ace["Ace"]["Mask"]["Mask"]
                )

            if ace["AceType"] == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                if ace["Ace"]["ObjectTypeLen"] == 0:
                    uuid = bin_to_string(ace["Ace"]["InheritedObjectType"]).lower()
                else:
                    uuid = bin_to_string(ace["Ace"]["ObjectType"]).lower()

                self._aces[sid]["extended_rights"].append(uuid)

    @property
    def owner(self) -> str:
        return self._owner

    @property
    def aces(self) -> dict:
        return self._aces


# https://github.com/GhostPack/Certify/blob/2b1530309c0c5eaf41b2505dfd5a68c83403d031/Certify/Lib/DisplayUtil.cs#L316
def is_admin_sid(sid: str) -> bool:
    return (
        ADMIN_SID_REGEX.match(sid) is not None
        or sid == "S-1-5-9"
        or sid == "S-1-5-32-544"
    )


# https://github.com/GhostPack/Certify/blob/2b1530309c0c5eaf41b2505dfd5a68c83403d031/Certify/Lib/DisplayUtil.cs#L323
def is_low_priv_sid(sid: str) -> bool:
    return (
        LOW_PRIV_SID_REGEX.match(sid) is not None
        or sid == "S-1-1-0"
        or sid == "S-1-5-11"
    )
