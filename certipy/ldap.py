import logging
import ssl
from typing import Any, List, Union

import ldap3
from ldap3.core.results import RESULT_STRONGER_AUTH_REQUIRED
from ldap3.protocol.microsoft import security_descriptor_control

from certipy.kerberos import get_kerberos_type1
from certipy.target import Target


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
                tls = ldap3.Tls(validate=ssl.CERT_NONE, version=version)
                ldap_server = ldap3.Server(
                    self.target.target_ip,
                    use_ssl=True,
                    port=self.port,
                    get_info=ldap3.ALL,
                    tls=tls,
                    connect_timeout=self.target.timeout,
                )
            else:
                ldap_server = ldap3.Server(
                    self.target.target_ip,
                    use_ssl=False,
                    port=self.port,
                    get_info=ldap3.ALL,
                    connect_timeout=self.target.timeout,
                )

            logging.debug("Authenticating to LDAP server")

            if self.target.do_kerberos:
                ldap_conn = ldap3.Connection(ldap_server)
                self.LDAP3KerberosLogin(ldap_conn)
            else:
                if self.target.hashes is not None:
                    ldap_pass = "%s:%s" % (self.target.lmhash, self.target.nthash)
                else:
                    ldap_pass = self.target.password
                ldap_conn = ldap3.Connection(
                    ldap_server,
                    user=user,
                    password=ldap_pass,
                    authentication=ldap3.NTLM,
                    auto_referrals=False,
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
                    if result["description"] == "invalidCredentials":
                        raise Exception(
                            "Failed to authenticate to LDAP. Invalid credentials"
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
        target = self.target
        _, _, blob = get_kerberos_type1(
            target.username,
            target.password,
            target.domain,
            target.lmhash,
            target.nthash,
            target_name=target.remote_name,
            kdc_host=target.dc_ip,
        )

        request = ldap3.operation.bind.bind_operation(
            connection.version, ldap3.SASL, target.username, None, "GSS-SPNEGO", blob
        )

        if connection.closed:
            connection.open(read_server_info=True)

        connection.sasl_in_progress = True
        response = connection.post_send_single_response(
            connection.send("bindRequest", request, None)
        )
        connection.sasl_in_progress = False
        if response[0]["result"] != 0:
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
            results = self.search("(sAMAccountName=%s)" % username, *args, **kwargs)
            if len(results) != 1:
                return None
            return results[0]

        user = _get_user(username, *args, **kwargs)
        if user is None:
            user = _get_user(username + "$")

        if user is None and silent is False:
            logging.error("Could not find user %s" % repr(username))

        return user
