# Certipy - Active Directory certificate abuse
#
# Description:
#   LDAP operations
#
# Authors:
#   @ly4k (https://github.com/ly4k)
#

import logging
from typing import Any

from impacket.ldap import ldap, ldapasn1
from impacket.ldap.ldapasn1 import Control

from certipy.structs import IntFlag
from certipy.target import Target


class SecurityInformation(IntFlag):
    OWNER_SECURITY_INFORMATION = 0x01
    GROUP_SECURITY_INFORMATION = 0x02
    DACL_SECURITY_INFORMATION = 0x04


DEFAULT_CONTROL_FLAGS: list["Control"] = [
    ldap.SimplePagedResultsControl(size=50),
]


class LDAPEntry:
    def __init__(self, search_entry: ldapasn1.SearchResultEntry):
        attributes = {}
        for attr in search_entry["attributes"]:
            vals = (
                list(map(lambda x: bytes(x), attr["vals"]))
                if len(attr["vals"]) > 1
                else bytes(attr["vals"][0])
            )
            attributes[str(attr["type"])] = vals
        self.attributes = attributes

    def get(self, key: str) -> str:
        value = self.get_raw(key)
        return value.decode() if value else None

    def get_raw(self, key: str) -> Any:
        if key not in self.attributes:
            return None
        return self.attributes[key]

    def __repr__(self) -> str:
        return "<LDAPEntry (%s)>" % repr(self.attributes)


class LDAPConnection:
    def __init__(self, target: Target, scheme: str = "ldaps"):
        self.target = target
        self.scheme = scheme
        self._root_name_path = None
        self._default_path = None
        self._configuration_path = None
        self._conn = None

    def connect(self) -> bool:
        target = self.target

        logging.debug(
            "Connecting to LDAP at %s (%s)"
            % (repr(target.remote_name), target.target_ip)
        )
        connection = ldap.LDAPConnection(
            "%s://%s" % (self.scheme, target.remote_name),
            "",
            target.target_ip,
        )

        logging.debug(
            "Connected to %s, port %d, SSL %s"
            % (target.target_ip, connection._dstPort, connection._SSL)
        )

        self._conn = connection

        try:
            if target.do_kerberos:
                return self._conn.kerberosLogin(
                    user=target.username,
                    password=target.password,
                    domain=target.domain,
                    lmhash=target.lmhash,
                    nthash=target.nthash,
                    kdcHost=target.dc_ip,
                )
            return self._conn.login(
                user=target.username,
                password=target.password,
                domain=target.domain,
                lmhash=target.lmhash,
                nthash=target.nthash,
            )
        except ldap.LDAPSessionError as e:
            if "invalidCredentials" in str(e):
                error_text = "Invalid credentials"
            else:
                error_text = str(e)

            logging.warning("Got error while connecting to LDAP: %s" % error_text)
            exit(1)

    def search(
        self,
        search_filter: str,
        *args,
        controls: list["Control"] = DEFAULT_CONTROL_FLAGS,
        search_base: str = None,
        **kwargs
    ) -> list["LDAPEntry"]:
        if search_base is None:
            search_base = self.default_path

        results = self._conn.search(
            *args,
            searchFilter=search_filter,
            searchControls=controls,
            searchBase=search_base,
            **kwargs
        )

        entries: list["LDAPEntry"] = list(
            map(
                lambda entry: LDAPEntry(entry),
                filter(
                    lambda entry: isinstance(entry, ldapasn1.SearchResultEntry), results
                ),
            )
        )

        return entries

    def _set_root_dse(self) -> None:
        dses = self.search(
            "(objectClass=*)",
            search_base="",
            attributes=[
                "rootDomainNamingContext",
                "defaultNamingContext",
                "configurationNamingContext",
            ],
            scope=ldapasn1.Scope("baseObject"),
        )

        assert len(dses) == 1

        dse = dses[0]

        self._root_name_path = dse.get("rootDomainNamingContext")
        self._default_path = dse.get("defaultNamingContext")
        self._configuration_path = dse.get("configurationNamingContext")

    @property
    def root_name_path(self) -> str:
        if self._root_name_path is not None:
            return self._root_name_path

        self._set_root_dse()

        return self._root_name_path

    @property
    def default_path(self) -> str:
        if self._default_path is not None:
            return self._default_path

        self._set_root_dse()

        return self._default_path

    @property
    def configuration_path(self) -> str:
        if self._configuration_path is not None:
            return self._configuration_path

        self._set_root_dse()

        return self._configuration_path
