import ssl
from typing import Any, List, Union

import ldap3
from certipy.lib.constants import WELLKNOWN_SIDS
from certipy.lib.kerberos import get_kerberos_type1
from certipy.lib.logger import logging
from certipy.lib.target import Target
from ldap3.core.results import RESULT_STRONGER_AUTH_REQUIRED
from ldap3.protocol.microsoft import security_descriptor_control


# https://github.com/fox-it/BloodHound.py/blob/d665959c58d881900378040e6670fa12f801ccd4/bloodhound/ad/utils.py#L216
def get_account_type(entry: "LDAPEntry"):
    account_type = entry.get("sAMAccountType")
    if account_type in [268435456, 268435457, 536870912, 536870913]:
        return "Group"
    elif entry.get("msDS-GroupMSAMembership"):
        return "User"
    elif account_type in [805306369]:
        return "Computer"
    elif account_type in [805306368]:
        return "User"
    elif account_type in [805306370]:
        return "trustaccount"
    else:
        return "Domain"


class LDAPEntry(dict):
    def get(self, key):
        if key not in self.__getitem__("attributes").keys():
            return None
        item = self.__getitem__("attributes").__getitem__(key)

        if isinstance(item, list) and len(item) == 0:
            return None

        return item

    def set(self, key, value):
        return self.__getitem__("attributes").__setitem__(key, value)

    def get_raw(self, key):
        if key not in self.__getitem__("raw_attributes").keys():
            return None
        return self.__getitem__("raw_attributes").__getitem__(key)


class LDAPConnection:
    def __init__(self, target: Target, scheme: str = "ldaps"):
        self.target = target
        self.scheme = scheme
        if self.scheme == "ldap":
            self.port = 389
        elif self.scheme == "ldaps":
            self.port = 636

        self.default_path: str = None
        self.configuration_path: str = None
        self.ldap_server: ldap3.Server = None
        self.ldap_conn: ldap3.Connection = None
        self.domain: str = None

        self.sid_map = {}

        self._machine_account_quota = None
        self._domain_sid = None
        self._users = {}
        self._user_sids = {}

    def connect(self, version: ssl._SSLMethod = None) -> None:
        user = "%s\\%s" % (self.target.domain, self.target.username)

        if version is None:
            try:
                self.connect(version=ssl.PROTOCOL_TLSv1_2)
            except ldap3.core.exceptions.LDAPSocketOpenError as e:
                if self.scheme != "ldaps":
                    logging.warning(
                        "Got error while trying to connecto to LDAP: %s" % e
                    )
                self.connect(version=ssl.PROTOCOL_TLSv1)
            return
        else:
            if self.scheme == "ldaps":
                tls = ldap3.Tls(validate=ssl.CERT_NONE, version=version,
                                ciphers='ALL:@SECLEVEL=0')
                ldap_server = ldap3.Server(
                    self.target.target_ip,
                    use_ssl=True,
                    port=self.port,
                    get_info=ldap3.ALL,
                    tls=tls,
                    connect_timeout=self.target.timeout,
                )
            else:
                if self.target.ldap_channel_binding:
                    raise Exception("LDAP channel binding is only available with LDAPS")
                ldap_server = ldap3.Server(
                    self.target.target_ip,
                    use_ssl=False,
                    port=self.port,
                    get_info=ldap3.ALL,
                    connect_timeout=self.target.timeout,
                )

            logging.debug("Authenticating to LDAP server")

            if self.target.do_kerberos or self.target.use_sspi:
                ldap_conn = ldap3.Connection(
                    ldap_server, receive_timeout=self.target.timeout * 10,
                )
                self.LDAP3KerberosLogin(ldap_conn)
            else:
                if self.target.hashes is not None:
                    ldap_pass = "%s:%s" % (self.target.lmhash, self.target.nthash)
                else:
                    ldap_pass = self.target.password
                channel_binding = {}
                if self.target.ldap_channel_binding:
                    if not hasattr(ldap3, 'TLS_CHANNEL_BINDING'):
                        raise Exception("To use LDAP channel binding, install the patched ldap3 module: pip3 install git+https://github.com/ly4k/ldap3")
                    channel_binding["channel_binding"] = ldap3.TLS_CHANNEL_BINDING if self.target.ldap_channel_binding else None
                ldap_conn = ldap3.Connection(
                    ldap_server,
                    user=user,
                    password=ldap_pass,
                    authentication=ldap3.NTLM,
                    auto_referrals=False,
                    receive_timeout=self.target.timeout * 10,
                    **channel_binding
                )

        if not ldap_conn.bound:
            bind_result = ldap_conn.bind()
            if not bind_result:
                result = ldap_conn.result
                if (
                    result["result"] == RESULT_STRONGER_AUTH_REQUIRED
                    and self.scheme == "ldap"
                ):
                    logging.warning(
                        "LDAP Authentication is refused because LDAP signing is enabled. "
                        "Trying to connect over LDAPS instead..."
                    )
                    self.scheme = "ldaps"
                    self.port = 636
                    return self.connect()
                else:
                    if result["description"] == "invalidCredentials" and result["message"].split(":")[0] == "80090346":
                        raise Exception(
                            "Failed to bind to LDAP. LDAP channel binding or signing is required. Use -scheme ldaps -ldap-channel-binding"
                        )
                    raise Exception(
                        "Failed to authenticate to LDAP: (%s) %s"
                        % (result["description"], result["message"])
                    )

        if ldap_server.schema is None:
            ldap_server.get_info_from_server(ldap_conn)

            if ldap_conn.result["result"] != 0:
                if ldap_conn.result["message"].split(":")[0] == "000004DC":
                    raise Exception(
                        "Failed to bind to LDAP. This is most likely because of an invalid username specified for logon"
                    )

            if ldap_server.schema is None:
                raise Exception("Failed to get LDAP schema")

        logging.debug("Bound to %s" % ldap_server)

        self.ldap_conn = ldap_conn
        self.ldap_server = ldap_server

        self.default_path = self.ldap_server.info.other["defaultNamingContext"][0]
        self.configuration_path = self.ldap_server.info.other[
            "configurationNamingContext"
        ][0]

        logging.debug("Default path: %s" % self.default_path)
        logging.debug("Configuration path: %s" % self.configuration_path)
        self.domain = self.ldap_server.info.other["ldapServiceName"][0].split("@")[-1]

    def LDAP3KerberosLogin(self, connection: ldap3.Connection) -> bool:
        _, _, blob, username = get_kerberos_type1(
            self.target,
            target_name=self.target.remote_name,
        )

        request = ldap3.operation.bind.bind_operation(
            connection.version,
            ldap3.SASL,
            username,
            None,
            "GSS-SPNEGO",
            blob,
        )

        if connection.closed:
            connection.open(read_server_info=True)

        connection.sasl_in_progress = True
        response = connection.post_send_single_response(
            connection.send("bindRequest", request, None)
        )
        connection.sasl_in_progress = False
        if response[0]["result"] != 0:
            if response[0]["description"] == "invalidCredentials" and response[0]["message"].split(":")[0] == "80090346":
                raise Exception(
                    "Failed to bind to LDAP. LDAP channel binding or signing is required. Certipy only supports channel binding via NTLM authentication. Use -scheme ldaps -ldap-channel-binding and use a password or NTLM hash for authentication instead of Kerberos, if possible"
                )
            if response[0]["description"] == "strongerAuthRequired" and response[0]["message"].split(":")[0] == "00002028":
                raise Exception(
                    "Failed to bind to LDAP. LDAP signing is required but not supported by Certipy. Use -scheme ldaps -ldap-channel-binding and use a password or NTLM hash for authentication instead of Kerberos, if possible"
                )
            raise Exception(response)

        connection.bound = True

        return True

    def add(self, *args, **kwargs) -> Any:
        self.ldap_conn.add(*args, **kwargs)
        return self.ldap_conn.result

    def delete(self, *args, **kwargs) -> Any:
        self.ldap_conn.delete(*args, **kwargs)
        return self.ldap_conn.result

    def modify(self, *args, **kwargs) -> Any:
        self.ldap_conn.modify(*args, **kwargs)
        return self.ldap_conn.result

    def search(
        self,
        search_filter: str,
        attributes: Union[str, List[str]] = ldap3.ALL_ATTRIBUTES,
        search_base: str = None,
        query_sd: bool = False,
        **kwargs
    ) -> List["LDAPEntry"]:
        if search_base is None:
            search_base = self.default_path

        if query_sd:
            controls = security_descriptor_control(sdflags=0x5)
        else:
            controls = None

        results = self.ldap_conn.extend.standard.paged_search(
            search_base=search_base,
            search_filter=search_filter,
            attributes=attributes,
            controls=controls,
            paged_size=200,
            generator=True,
            **kwargs
        )

        if self.ldap_conn.result["result"] != 0:
            logging.warning(
                "LDAP search %s failed: (%s) %s"
                % (
                    repr(search_filter),
                    self.ldap_conn.result["description"],
                    self.ldap_conn.result["message"],
                )
            )
            return []

        entries = list(
            map(
                lambda entry: LDAPEntry(**entry),
                filter(
                    lambda entry: entry["type"] == "searchResEntry",
                    results,
                ),
            )
        )
        return entries

    def get_user(
        self, username: str, silent: bool = False, *args, **kwargs
    ) -> LDAPEntry:
        def _get_user(username, *args, **kwargs):
            sanitized_username = username.lower().strip()
            if sanitized_username in self._users:
                return self._users[sanitized_username]

            results = self.search("(sAMAccountName=%s)" % username, *args, **kwargs)
            if len(results) != 1:
                return None

            self._users[sanitized_username] = results[0]

            return results[0]

        user = _get_user(username, *args, **kwargs)
        if user is None:
            user = _get_user(username + "$")

        if user is None and silent is False:
            logging.error("Could not find user %s" % repr(username))

        return user

    @property
    def machine_account_quota(self):
        if self._machine_account_quota is not None:
            return self._machine_account_quota
        results = self.search(
            "(objectClass=domain)",
            attributes=[
                "ms-DS-MachineAccountQuota",
            ],
        )
        if len(results) != 1:
            return 0

        result = results[0]
        machine_account_quota = result.get("ms-DS-MachineAccountQuota")
        if machine_account_quota is None:
            machine_account_quota = 0

        self._machine_account_quota = machine_account_quota

        return machine_account_quota

    @property
    def domain_sid(self):
        if self._domain_sid is not None:
            return self._domain_sid

        results = self.search(
            "(objectClass=domain)",
            attributes=[
                "objectSid",
            ],
        )
        if len(results) != 1:
            return None

        result = results[0]
        domain_sid = result.get("objectSid")
        if domain_sid is None:
            domain_sid = None

        self._domain_sid = domain_sid

        return domain_sid

    def get_user_sids(self, username: str):
        sanitized_username = username.lower().strip()
        if sanitized_username in self._user_sids:
            return self._user_sids[sanitized_username]

        user = self.get_user(username)

        sids = set()

        sids.add(user.get("objectSid"))

        # Everyone, Authenticated Users, Users
        sids |= set(["S-1-1-0", "S-1-5-11", "S-1-5-32-545"])

        # Domain Users, Domain Computers, etc.
        primary_group_id = user.get("primaryGroupID")
        if primary_group_id is not None:
            sids.add("%s-%d" % (self.domain_sid, primary_group_id))

        # Add Domain Computers group
        logging.debug(
            "Adding Domain Computers to list of current user's SIDs"
        )
        sids.add("%s-515" % self.domain_sid)

        dns = [user.get("distinguishedName")]
        for sid in sids:
            object = self.lookup_sid(sid)
            if "dn" in object:
                dns.append(object["dn"])

        member_of_queries = []
        for dn in dns:
            member_of_queries.append("(member:1.2.840.113556.1.4.1941:=%s)" % dn)

        try:
            # Nested Group Membership
            groups = self.search(
                "(|%s)" % "".join(member_of_queries),
                attributes="objectSid",
            )
        except Exception as e:
            logging.warning("Failed to get user SIDs. Try increasing -timeout")
            return sids

        for group in groups:
            sid = group.get("objectSid")
            if sid is not None:
                sids.add(sid)

        self._user_sids[sanitized_username] = sids

        return sids

    def lookup_sid(self, sid: str) -> LDAPEntry:
        if sid in self.sid_map:
            return self.sid_map[sid]

        if sid in WELLKNOWN_SIDS:
            return LDAPEntry(
                **{
                    "attributes": {
                        "objectSid": "%s-%s" % (self.domain.upper(), sid),
                        "objectType": WELLKNOWN_SIDS[sid][1].capitalize(),
                        "name": "%s\\%s" % (self.domain, WELLKNOWN_SIDS[sid][0]),
                    }
                }
            )

        attributes = [
            "sAMAccountType",
            "name",
            "objectSid",
        ]
        # Only request msDS-GroupMSAMembership when it exists in the schema. Else the ldap3 module will return an LDAPAttributeError error.
        if self.ldap_conn.server.schema and "msDS-GroupMSAMembership" in self.ldap_conn.server.schema.attribute_types:
            attributes.append("msDS-GroupMSAMembership")
        results = self.search(
            "(objectSid=%s)" % sid,
            attributes=attributes,
        )

        if len(results) != 1:
            logging.warning("Failed to lookup user with SID %s" % repr(sid))
            entry = LDAPEntry(
                **{
                    "attributes": {
                        "objectSid": sid,
                        "name": sid,
                        "objectType": "Base",
                    }
                }
            )
        else:
            entry = results[0]
            entry.set("name", "%s\\%s" % (self.domain, entry.get("name")))
            entry.set("objectType", get_account_type(entry))

        self.sid_map[sid] = entry

        return entry
