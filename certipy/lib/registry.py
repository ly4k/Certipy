from typing import List
from certipy.lib.constants import WELLKNOWN_SIDS, WELLKNOWN_RIDS
from certipy.lib.ldap import LDAPEntry

class RegEntry(LDAPEntry):

    def __init__(self, **kwargs):
        super().__init__(self, **kwargs)
        if not 'attributes' in self:
            self['attributes'] = {}

    def get_raw(self, key):
        data = self.get(key)
        if isinstance(data, str):
            return s.encode()
        elif isinstance(data, list):
            return list(map(lambda x: x.encode(), data))
        return data

class RegConnection():

    def __init__(self, domain: str, sids: List[str], scheme: str = "file"):
        self.domain = domain
        self.sids = sids
        self.sid_map = {}

    def get_user_sids(self, username: str, user_sid: str = None, user_dn: str = None):
        return self.sids

    def lookup_sid(self, sid: str) -> RegEntry:
        if sid in self.sid_map:
            return self.sid_map[sid]

        if sid in WELLKNOWN_SIDS:
            return RegEntry(
                **{
                    "attributes": {
	                    "objectSid": "%s-%s" % (self.domain.upper(), sid),
	                    "objectType": WELLKNOWN_SIDS[sid][1].capitalize(),
	                    "name": "%s\\%s" % (self.domain, WELLKNOWN_SIDS[sid][0]),
                    }
                }
            )

        rid = sid.split("-")[-1]
        if rid in WELLKNOWN_RIDS:
            return RegEntry(
                **{
                    "attributes": {
	                    "objectSid": "%s-%s" % (self.domain.upper(), sid),
	                    "objectType": WELLKNOWN_RIDS[rid][1].capitalize(),
	                    "name": "%s\\%s" % (self.domain, WELLKNOWN_RIDS[rid][0]),
                    }
                }
            )

        entry = RegEntry(
            **{
                "attributes": {
                    "objectSid": sid,
                    "name": sid,
                    "objectType": "Base",
                }
            }
        )

        self.sid_map[sid] = entry

        return entry
