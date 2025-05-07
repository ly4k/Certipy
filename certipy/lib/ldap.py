"""
LDAP connection and query functionality for Certipy.

This module provides classes and methods for:
- Establishing LDAP/LDAPS connections to Active Directory
- Performing common search and modification operations
- Mapping between security identifiers (SIDs) and account objects
- Managing user and group membership information
- Handling various authentication methods (NTLM, Kerberos, simple bind)

Main components:
- LDAPEntry: Dictionary-like class for LDAP objects with attribute access methods
- LDAPConnection: Main class for connecting to and querying LDAP servers
"""

import ssl
from typing import Any, Dict, List, Optional, Set, Union, cast

import ldap3
from ldap3.core.exceptions import LDAPSocketOpenError
from ldap3.core.results import RESULT_STRONGER_AUTH_REQUIRED
from ldap3.operation.bind import bind_operation
from ldap3.protocol.microsoft import security_descriptor_control

from certipy.lib.constants import WELLKNOWN_SIDS
from certipy.lib.kerberos import get_kerberos_type1
from certipy.lib.logger import logging
from certipy.lib.target import Target


def get_account_type(entry: "LDAPEntry") -> str:
    """
    Determine the type of Active Directory account based on sAMAccountType and objectClass.

    Args:
        entry: LDAP entry containing account attributes

    Returns:
        Account type as string: "Group", "Computer", "User", "TrustAccount", or "Domain"
    """
    account_type = entry.get("sAMAccountType")
    object_class = entry.get("objectClass") or []

    # Group accounts
    if account_type in [268435456, 268435457, 536870912, 536870913]:
        return "Group"
    # Computer accounts
    elif account_type in [805306369]:
        return "Computer"
    # User accounts (including managed service accounts)
    elif (
        account_type in [805306368]
        or "msDS-GroupManagedServiceAccount" in object_class
        or "msDS-ManagedServiceAccount" in object_class
    ):
        return "User"
    # Trust accounts
    elif account_type in [805306370]:
        return "TrustAccount"
    # Default to Domain
    else:
        return "Domain"


class LDAPEntry(Dict[str, Any]):
    """
    Dictionary-like class representing an LDAP entry with helper methods.

    This class extends the standard dictionary to provide convenient access
    to LDAP attributes and raw attribute values.
    """

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get an attribute value from the LDAP entry with support for default values.

        This method provides convenient access to LDAP attributes and handles several
        special cases, including missing attributes and empty lists.

        Args:
            key: Attribute name to retrieve
            default: Value to return if attribute is missing or empty (default: None)

        Returns:
            Attribute value if present and not empty, otherwise the default value
        """
        if key not in self.__getitem__("attributes").keys():
            return default

        item = self.__getitem__("attributes").__getitem__(key)

        # Return default for empty lists
        if isinstance(item, list) and len(item) == 0:
            return default

        return item

    def set(self, key: str, value: Any) -> None:
        """
        Set an attribute value in the LDAP entry.

        Args:
            key: Attribute name to set
            value: Value to assign to the attribute
        """
        return self.__getitem__("attributes").__setitem__(key, value)

    def get_raw(self, key: str) -> Any:
        """
        Get the raw (unprocessed) attribute value from the LDAP entry.

        Args:
            key: Attribute name to retrieve

        Returns:
            Raw attribute value or None if not present
        """
        if key not in self.__getitem__("raw_attributes").keys():
            return None

        return self.__getitem__("raw_attributes").__getitem__(key)


class LDAPConnection:
    """
    Manages connections and operations to Active Directory via LDAP/LDAPS.

    This class handles authentication, searching, and modifying objects in
    Active Directory using the ldap3 library.
    """

    def __init__(self, target: Target) -> None:
        """
        Initialize an LDAP connection with the specified target and scheme.

        Args:
            target: Target object containing connection details
            scheme: Connection scheme, either "ldap" or "ldaps" (default)
        """
        self.target = target
        self.scheme = target.ldap_scheme

        # Determine port based on scheme and target configuration
        if self.scheme == "ldap":
            self.port = int(target.ldap_port) if target.ldap_port is not None else 389
        elif self.scheme == "ldaps":
            self.port = int(target.ldap_port) if target.ldap_port is not None else 636
        else:
            raise ValueError(f"Unsupported scheme: {self.scheme}")

        # Connection-related attributes
        self.default_path: Optional[str] = None
        self.configuration_path: Optional[str] = None
        self.ldap_server: Optional[ldap3.Server] = None
        self.ldap_conn: Optional[ldap3.Connection] = None
        self.domain: Optional[str] = None

        # Caching and tracking
        self.sid_map: Dict[str, LDAPEntry] = {}
        self._machine_account_quota: Optional[int] = None
        self._domain_sid: Optional[str] = None
        self._users: Dict[str, LDAPEntry] = {}
        self._user_sids: Dict[str, Set[str]] = {}
        self.warned_missing_domain_sid_lookup: bool = False

    def connect(self, version: Optional[ssl._SSLMethod] = None) -> None:
        """
        Connect to the LDAP server with the specified SSL/TLS version.

        Args:
            version: SSL/TLS protocol version to use, autodetected if None

        Raises:
            Exception: If connection or authentication fails
        """
        # Auto-detect TLS version if not specified
        if version is None:
            try:
                self.connect(version=ssl.PROTOCOL_TLSv1_2)
            except LDAPSocketOpenError as e:
                if self.scheme != "ldaps":
                    logging.warning(f"Got error while trying to connect to LDAP: {e}")
                self.connect(version=ssl.PROTOCOL_TLSv1)
            return

        if self.target.target_ip is None:
            raise Exception("Target IP is not set")

        # Format user credentials
        user = f"{self.target.domain}\\{self.target.username}"
        user_upn = f"{self.target.username}@{self.target.domain}"

        # Create server object based on scheme
        if self.scheme == "ldaps":
            # Configure TLS for LDAPS
            tls = ldap3.Tls(
                validate=ssl.CERT_NONE, version=version, ciphers="ALL:@SECLEVEL=0"
            )
            ldap_server = ldap3.Server(
                self.target.target_ip,
                use_ssl=True,
                port=self.port,
                get_info=ldap3.ALL,
                tls=tls,
                connect_timeout=self.target.timeout,
            )
        else:
            # LDAP (no TLS)
            if self.target.ldap_channel_binding:
                raise Exception("LDAP channel binding is only available with LDAPS")

            ldap_server = ldap3.Server(
                self.target.target_ip,
                use_ssl=False,
                port=self.port,
                get_info=ldap3.ALL,
                connect_timeout=self.target.timeout,
            )

        logging.debug(
            f"Authenticating to LDAP server{' using SIMPLE authentication' if self.target.do_simple else ''}"
        )

        # Authentication based on method
        if self.target.do_kerberos:
            # Kerberos authentication
            ldap_conn = ldap3.Connection(
                ldap_server,
                receive_timeout=self.target.timeout * 10,
            )
            self._kerberos_login(ldap_conn)
        else:
            # NTLM or simple authentication
            if self.target.hashes is not None:
                ldap_pass = f"{self.target.lmhash}:{self.target.nthash}"
            else:
                ldap_pass = self.target.password

            # Configure channel binding if requested
            channel_binding = {}
            if self.target.ldap_channel_binding:
                # Check for patched ldap3 module with channel binding support
                if not hasattr(ldap3, "TLS_CHANNEL_BINDING"):
                    raise Exception(
                        "To use LDAP channel binding, install the patched ldap3 module: "
                        "pip3 install git+https://github.com/ly4k/ldap3"
                    )
                channel_binding["channel_binding"] = (
                    cast(Any, ldap3).TLS_CHANNEL_BINDING
                    if self.target.ldap_channel_binding
                    else None
                )

            # Create connection
            ldap_conn = ldap3.Connection(
                ldap_server,
                user=user_upn if self.target.do_simple else user,
                password=ldap_pass,
                authentication=ldap3.SIMPLE if self.target.do_simple else ldap3.NTLM,
                auto_referrals=False,
                receive_timeout=self.target.timeout * 10,
                **channel_binding,
            )

        # Perform bind operation if not already bound
        if not ldap_conn.bound:
            bind_result = ldap_conn.bind()
            if not bind_result:
                result = ldap_conn.result
                if (
                    result["result"] == RESULT_STRONGER_AUTH_REQUIRED
                    and self.scheme == "ldap"
                ):
                    # Handle LDAP signing requirement by switching to LDAPS
                    logging.warning(
                        "LDAP Authentication is refused because LDAP signing is enabled. "
                        "Trying to connect over LDAPS instead..."
                    )
                    self.scheme = "ldaps"
                    self.port = (
                        int(self.target.ldap_port)
                        if self.target.ldap_port is not None
                        else 636
                    )
                    return self.connect()
                else:
                    # Handle other authentication failures
                    if (
                        result["description"] == "invalidCredentials"
                        and result["message"].split(":")[0] == "80090346"
                    ):
                        raise Exception(
                            "Failed to bind to LDAP. LDAP channel binding or signing is required. "
                            "Use -scheme ldaps -ldap-channel-binding or try with -simple-auth"
                        )
                    raise Exception(
                        f"Failed to authenticate to LDAP: ({result['description']}) {result['message']}"
                    )

        # Get schema information if not already available
        if ldap_server.schema is None:
            ldap_server.get_info_from_server(ldap_conn)

            if ldap_conn.result["result"] != 0:
                if ldap_conn.result["message"].split(":")[0] == "000004DC":
                    raise Exception(
                        "Failed to bind to LDAP. This is most likely because of an invalid username specified for logon"
                    )

            if ldap_server.schema is None:
                raise Exception("Failed to get LDAP schema")

        logging.debug(f"Bound to {ldap_server}")

        # Store connection objects and directory paths
        self.ldap_conn = ldap_conn
        self.ldap_server = ldap_server

        self.default_path = self.ldap_server.info.other["defaultNamingContext"][0]
        self.configuration_path = self.ldap_server.info.other[
            "configurationNamingContext"
        ][0]

        logging.debug(f"Default path: {self.default_path}")
        logging.debug(f"Configuration path: {self.configuration_path}")

        # Extract domain name from LDAP service name
        self.domain = self.ldap_server.info.other["ldapServiceName"][0].split("@")[-1]

    def _kerberos_login(self, connection: ldap3.Connection) -> None:
        """
        Perform Kerberos authentication to LDAP server.

        Args:
            connection: LDAP connection object

        Raises:
            Exception: If Kerberos authentication fails
        """
        # Get Kerberos Type 1 message
        _, _, blob, username = get_kerberos_type1(
            self.target,
            target_name=self.target.remote_name or "",
        )

        # Create SASL bind request
        request = bind_operation(
            connection.version,
            ldap3.SASL,
            username,
            None,
            "GSS-SPNEGO",
            blob,
        )

        # Ensure connection is open
        if connection.closed:
            connection.open(read_server_info=True)

        # Send bind request and process response
        connection.sasl_in_progress = True
        response = connection.post_send_single_response(
            connection.send("bindRequest", request, None)
        )
        connection.sasl_in_progress = False

        # Handle authentication errors
        if response[0]["result"] != 0:
            if (
                response[0]["description"] == "invalidCredentials"
                and response[0]["message"].split(":")[0] == "80090346"
            ):
                raise Exception(
                    "Failed to bind to LDAP. LDAP channel binding or signing is required. "
                    "Certipy only supports channel binding via NTLM authentication. "
                    "Use -scheme ldaps -ldap-channel-binding and use a password or NTLM hash "
                    "for authentication instead of Kerberos, if possible"
                )
            if (
                response[0]["description"] == "strongerAuthRequired"
                and response[0]["message"].split(":")[0] == "00002028"
            ):
                raise Exception(
                    "Failed to bind to LDAP. LDAP signing is required but not supported by Certipy. "
                    "Use -scheme ldaps -ldap-channel-binding and use a password or NTLM hash "
                    "for authentication instead of Kerberos, if possible"
                )
            raise Exception(response)

        connection.bound = True

    def add(self, *args: Any, **kwargs: Any) -> Any:
        """
        Add a new entry to the LDAP directory.

        Args:
            *args: Arguments to pass to the underlying LDAP add operation
            **kwargs: Keyword arguments to pass to the underlying LDAP add operation

        Returns:
            Result of the add operation

        Raises:
            Exception: If LDAP connection is not established
        """
        if not self.ldap_conn:
            raise Exception("LDAP connection is not established")

        self.ldap_conn.add(*args, **kwargs)
        return self.ldap_conn.result

    def delete(self, *args: Any, **kwargs: Any) -> Any:
        """
        Delete an entry from the LDAP directory.

        Args:
            *args: Arguments to pass to the underlying LDAP delete operation
            **kwargs: Keyword arguments to pass to the underlying LDAP delete operation

        Returns:
            Result of the delete operation

        Raises:
            Exception: If LDAP connection is not established
        """
        if not self.ldap_conn:
            raise Exception("LDAP connection is not established")

        self.ldap_conn.delete(*args, **kwargs)
        return self.ldap_conn.result

    def modify(self, *args: Any, **kwargs: Any) -> Any:
        """
        Modify an existing entry in the LDAP directory.

        Args:
            *args: Arguments to pass to the underlying LDAP modify operation
            **kwargs: Keyword arguments to pass to the underlying LDAP modify operation

        Returns:
            Result of the modify operation

        Raises:
            Exception: If LDAP connection is not established
        """
        if not self.ldap_conn:
            raise Exception("LDAP connection is not established")

        self.ldap_conn.modify(*args, **kwargs)
        return self.ldap_conn.result

    def search(
        self,
        search_filter: str,
        attributes: Union[str, List[str]] = ldap3.ALL_ATTRIBUTES,
        search_base: Optional[str] = None,
        query_sd: bool = False,
        **kwargs: Any,
    ) -> List[LDAPEntry]:
        """
        Search the LDAP directory with the given filter and return matching entries.

        Args:
            search_filter: LDAP search filter string
            attributes: List of attributes to retrieve or ldap3.ALL_ATTRIBUTES
            search_base: Base DN for the search, defaults to domain base
            query_sd: Whether to query security descriptors
            **kwargs: Additional arguments for the search operation

        Returns:
            List of matching LDAP entries

        Raises:
            Exception: If LDAP connection is not established
        """
        if search_base is None:
            search_base = self.default_path

        # Set security descriptor control if requested
        if query_sd:
            controls = security_descriptor_control(sdflags=0x5)
        else:
            controls = None

        if self.ldap_conn is None:
            raise Exception("LDAP connection is not established")

        # Perform paged search to handle large result sets
        results = self.ldap_conn.extend.standard.paged_search(
            search_base=search_base,
            search_filter=search_filter,
            attributes=attributes,
            controls=controls,
            paged_size=200,
            generator=True,
            **kwargs,
        )

        if self.ldap_conn.result["result"] != 0:
            logging.warning(
                f"LDAP search {search_filter!r} failed: "
                f"({self.ldap_conn.result['description']}) {self.ldap_conn.result['message']}"
            )
            return []

        # Convert search results to LDAPEntry objects
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
        self, username: str, silent: bool = False, *args: Any, **kwargs: Any
    ) -> Optional[LDAPEntry]:
        """
        Find a user by samAccountName.

        Args:
            username: Username to search for (samAccountName)
            silent: Whether to suppress error logging for missing users
            *args: Additional arguments for the search
            **kwargs: Additional keyword arguments for the search

        Returns:
            User entry or None if not found
        """

        def _get_user(username: str, *args: Any, **kwargs: Any) -> Optional[LDAPEntry]:
            """Helper function to search for a user, with caching."""
            sanitized_username = username.lower().strip()

            # Return cached result if available
            if sanitized_username in self._users:
                return self._users[sanitized_username]

            # Search for the user
            results = self.search(f"(sAMAccountName={username})", *args, **kwargs)
            if len(results) != 1:
                return None

            # Cache the result
            self._users[sanitized_username] = results[0]
            return results[0]

        # Try without $ suffix first
        user = _get_user(username, *args, **kwargs)

        # Try with $ suffix (for computer accounts)
        if user is None and not username.endswith("$"):
            user = _get_user(f"{username}$", *args, **kwargs)

        # Log error if user not found and silent mode is not enabled
        if user is None and not silent:
            logging.error(f"Could not find user {username!r}")

        return user

    @property
    def machine_account_quota(self) -> int:
        """
        Get the domain's machine account quota setting.

        Returns:
            Machine account quota value (or 0 if not found)
        """
        # Return cached value if available
        if self._machine_account_quota is not None:
            return self._machine_account_quota

        # Query domain object for quota setting
        results = self.search(
            "(objectClass=domain)",
            attributes=["ms-DS-MachineAccountQuota"],
        )

        if len(results) != 1:
            return 0

        result = results[0]
        machine_account_quota = result.get("ms-DS-MachineAccountQuota")
        if machine_account_quota is None:
            machine_account_quota = 0

        # Cache the result
        self._machine_account_quota = machine_account_quota
        return machine_account_quota

    @property
    def domain_sid(self) -> Optional[str]:
        """
        Get the domain's security identifier (SID).

        Returns:
            Domain SID or None if not found
        """
        # Return cached value if available
        if self._domain_sid is not None:
            return self._domain_sid

        # Query domain object for SID
        results = self.search(
            "(objectClass=domain)",
            attributes=["objectSid"],
        )

        if len(results) != 1:
            return None

        result = results[0]
        domain_sid = result.get("objectSid")

        # Cache the result
        self._domain_sid = domain_sid
        return domain_sid

    def get_user_sids(
        self,
        username: str,
        user_sid: Optional[str] = None,
        user_dn: Optional[str] = None,
    ) -> Set[str]:
        """
        Get all SIDs associated with a user, including groups.

        Args:
            username: Username to look up
            user_sid: Optional SID to use if user lookup fails
            user_dn: Optional DN to use if user lookup fails

        Returns:
            Set of SIDs the user belongs to
        """
        # Return cached value if available
        sanitized_username = username.lower().strip()
        if sanitized_username in self._user_sids:
            return self._user_sids[sanitized_username]

        # Get user object or create minimal one if not found
        user = self.get_user(username)
        if not user:
            user = {"objectSid": user_sid, "distinguishedName": user_dn}
            if not user_sid:
                logging.warning(
                    "User SID can't be retrieved, for more accurate results, add it manually with -sid"
                )

        # Start with basic SIDs
        sids: Set[str] = set()

        # Add user's own SID
        object_sid = user.get("objectSid")
        if object_sid:
            sids.add(object_sid)

        # Add well-known SIDs: Everyone, Authenticated Users, Users
        sids |= {"S-1-1-0", "S-1-5-11", "S-1-5-32-545"}

        # Add primary group (usually Domain Users)
        primary_group_id = user.get("primaryGroupID")
        if primary_group_id is not None and self.domain_sid:
            sids.add(f"{self.domain_sid}-{primary_group_id}")

        # Add Domain Users and Domain Computers group
        if self.domain_sid:
            logging.debug(
                "Adding Domain Users and Domain Computers to list of current user's SIDs"
            )
            sids.add(f"{self.domain_sid}-513")  # Domain Users
            sids.add(f"{self.domain_sid}-515")  # Domain Computers

        # Collect DNs to search for group membership
        dns = [user.get("distinguishedName")]
        for sid in sids:
            object_entry = self.lookup_sid(sid)
            if "dn" in object_entry:
                dns.append(object_entry["dn"])

        # Build LDAP query for nested group membership (LDAP_MATCHING_RULE_IN_CHAIN)
        member_of_queries = []
        for dn in dns:
            if dn:  # Skip None values
                member_of_queries.append(f"(member:1.2.840.113556.1.4.1941:={dn})")

        if member_of_queries:
            try:
                # Query for nested group membership
                groups = self.search(
                    f"(|{''.join(member_of_queries)})",
                    attributes="objectSid",
                )

                # Add all group SIDs to the set
                for group in groups:
                    sid = group.get("objectSid")
                    if sid is not None:
                        sids.add(sid)

            except Exception:
                logging.warning("Failed to get user SIDs. Try increasing -timeout")

        # Cache the results
        self._user_sids[sanitized_username] = sids
        return sids

    def lookup_sid(self, sid: str) -> LDAPEntry:
        """
        Look up an object by its SID.

        Args:
            sid: Security identifier to look up

        Returns:
            LDAPEntry for the object, or a synthetic entry for well-known SIDs
        """
        # Return cached value if available
        if sid in self.sid_map:
            return self.sid_map[sid]

        # Handle well-known SIDs
        if sid in WELLKNOWN_SIDS:
            if self.domain is None and not self.warned_missing_domain_sid_lookup:
                self.warned_missing_domain_sid_lookup = True
                logging.warning(
                    "Domain is not set for LDAP connection. This may cause issues when looking up SIDs"
                )

            # Create synthetic entry for well-known SID
            entry = LDAPEntry(
                **{
                    "attributes": {
                        "objectSid": f"{(self.domain or '').upper()}-{sid}",
                        "objectType": WELLKNOWN_SIDS[sid][1].capitalize(),
                        "name": f"{self.domain}\\{WELLKNOWN_SIDS[sid][0]}",
                    }
                }
            )
            self.sid_map[sid] = entry
            return entry

        # For regular SIDs, query the directory
        attributes = [
            "sAMAccountType",
            "name",
            "objectSid",
        ]

        if self.ldap_conn is None:
            raise Exception("LDAP connection is not established")

        # Only request msDS-GroupMSAMembership when it exists in the schema
        if (
            self.ldap_conn.server.schema
            and "msDS-GroupMSAMembership"
            in self.ldap_conn.server.schema.attribute_types
        ):
            attributes.append("msDS-GroupMSAMembership")

        # Search for object with the given SID
        results = self.search(
            f"(objectSid={sid})",
            attributes=attributes,
        )

        # Handle results
        if len(results) != 1:
            logging.warning(f"Failed to lookup object with SID {sid!r}")
            # Create synthetic entry for unknown SID
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
            # Process found entry
            entry = results[0]
            entry.set("name", f"{self.domain}\\{entry.get('name')}")
            entry.set("objectType", get_account_type(entry))

        # Cache the result
        self.sid_map[sid] = entry
        return entry
