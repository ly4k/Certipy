"""
ADWS (Active Directory Web Services) connection module for Certipy.

This module provides an ADWSConnection class that mirrors the LDAPConnection
interface but uses ADWS (port 9389) instead of LDAP (port 389/636).

ADWS provides the same data as LDAP but over a different protocol, which can
be useful for evasion as ADWS traffic is less commonly monitored.
"""

import logging
from base64 import b64decode
from typing import Any, Dict, List, Optional, Set
from xml.etree import ElementTree

from certipy.lib.constants import WELLKNOWN_SIDS
from certipy.lib.ldap import LDAPEntry, get_account_type
from certipy.lib.target import Target

from .soapy import ADWSConnect, NTLMAuth, KerberosAuth
from .soapy.soap_templates import NAMESPACES


class ADWSConnection:
    """
    Manages connections and operations to Active Directory via ADWS.

    This class provides the same interface as LDAPConnection but uses
    Active Directory Web Services (ADWS) on port 9389 instead of LDAP.
    """

    def __init__(self, target: Target) -> None:
        """
        Initialize an ADWS connection with the specified target.

        Args:
            target: Target object containing connection details
        """
        self.target = target

        # Connection-related attributes
        self.default_path: Optional[str] = None
        self.configuration_path: Optional[str] = None
        self.domain: Optional[str] = None

        # Internal ADWS client
        self._client: Optional[ADWSConnect] = None

        # Caching and tracking
        self.sid_map: Dict[str, LDAPEntry] = {}
        self._domain_sid: Optional[str] = None
        self._users: Dict[str, LDAPEntry] = {}
        self._user_sids: Dict[str, Set[str]] = {}
        self.warned_missing_domain_sid_lookup: bool = False

    def connect(self) -> None:
        """
        Connect to the ADWS server.

        This method establishes a connection to the ADWS server and handles
        authentication using the credentials from the target object.
        It supports both NTLM and Kerberos authentication.

        Raises:
            Exception: If connection or authentication fails
        """
        if self.target.target_ip is None:
            raise Exception("Target IP is not set")

        # Determine authentication method
        if self.target.do_kerberos:
            logging.debug("Authenticating to ADWS server using Kerberos authentication")
            auth = KerberosAuth(self.target)
        else:
            logging.debug("Authenticating to ADWS server using NTLM authentication")
            if self.target.hashes is not None:
                auth = NTLMAuth(hashes=self.target.nthash)
            else:
                auth = NTLMAuth(password=self.target.password)

        # Create ADWS client
        # Use target_ip or dc_ip as the server address
        server = self.target.target_ip or self.target.dc_ip
        if server is None:
            raise Exception("No server address available (target_ip or dc_ip)")

        logging.info(f"Connecting to ADWS at {server}:9389")

        self._client = ADWSConnect.pull_client(
            ip=server,
            domain=self.target.domain,
            username=self.target.username,
            auth=auth,
        )

        # Set up paths based on domain
        domain_parts = self.target.domain.split(".")
        self.default_path = ",".join([f"DC={part}" for part in domain_parts])
        self.configuration_path = f"CN=Configuration,{self.default_path}"
        self.domain = self.target.domain.upper()

        logging.debug(f"Default path: {self.default_path}")
        logging.debug(f"Configuration path: {self.configuration_path}")
        logging.info(f"Connected to ADWS server as {self.target.username}@{self.target.domain}")

    def search(
        self,
        search_filter: str,
        attributes: Any = None,
        search_base: Optional[str] = None,
        query_sd: bool = False,
        **kwargs: Any,
    ) -> List[LDAPEntry]:
        """
        Search the ADWS directory with the given filter and return matching entries.

        Args:
            search_filter: LDAP search filter string
            attributes: List of attributes to retrieve
            search_base: Base DN for the search, defaults to domain base
            query_sd: Whether to query security descriptors
            **kwargs: Additional arguments (ignored for ADWS compatibility)

        Returns:
            List of matching LDAP entries

        Raises:
            Exception: If ADWS connection is not established
        """
        if search_base is None:
            search_base = self.default_path

        if self._client is None:
            raise Exception("ADWS connection is not established")

        # Convert attributes to list if needed
        if attributes is None:
            attr_list = ["*"]
        elif isinstance(attributes, str):
            attr_list = [attributes]
        else:
            attr_list = list(attributes)

        # Add nTSecurityDescriptor if query_sd is requested
        if query_sd and "nTSecurityDescriptor" not in attr_list:
            attr_list.append("nTSecurityDescriptor")

        try:
            # Execute ADWS query
            results_xml = self._client.pull(
                query=search_filter,
                attributes=attr_list,
                search_base=search_base,
            )

            # Convert XML results to LDAPEntry objects
            entries = self._convert_xml_to_entries(results_xml)
            return entries

        except Exception as e:
            logging.warning(f"ADWS search {search_filter!r} failed: {e}")
            return []

    def _convert_xml_to_entries(self, xml_root: ElementTree.Element) -> List[LDAPEntry]:
        """
        Convert ADWS XML response to list of LDAPEntry objects.

        Args:
            xml_root: Root XML element from ADWS response

        Returns:
            List of LDAPEntry objects
        """
        entries = []

        # Find all items in the response
        for items in xml_root.findall(".//wsen:Items", namespaces=NAMESPACES):
            for item in items:
                entry = self._parse_xml_item(item)
                if entry is not None:
                    entries.append(entry)

        return entries

    def _parse_xml_item(self, item: ElementTree.Element) -> Optional[LDAPEntry]:
        """
        Parse a single ADWS XML item into an LDAPEntry.

        Args:
            item: XML element representing an AD object

        Returns:
            LDAPEntry object or None if parsing fails
        """
        attributes: Dict[str, Any] = {}
        raw_attributes: Dict[str, Any] = {}
        dn = None

        # Get the item tag name (without namespace) for type info
        tag_name = item.tag.split("}")[-1] if "}" in item.tag else item.tag

        # Parse all attributes in the item
        for attr in item:
            attr_name = attr.tag.split("}")[-1] if "}" in attr.tag else attr.tag

            # Skip synthetic attributes (those without LdapSyntax)
            ldap_syntax = attr.get("LdapSyntax", attr.attrib.get(
                "{http://schemas.microsoft.com/2008/1/ActiveDirectory}LdapSyntax"
            ))

            # Get all values for this attribute
            values = []
            raw_values = []
            for value_elem in attr.findall(".//ad:value", namespaces=NAMESPACES):
                if value_elem.text:
                    values.append(value_elem.text)
                    raw_values.append(value_elem.text)

            if not values:
                continue

            # Handle special attribute types
            if attr_name == "distinguishedName":
                dn = values[0]

            # Convert certain attributes from base64
            if ldap_syntax == "SidString" or attr_name in ["objectSid", "securityIdentifier"]:
                try:
                    from impacket.ldap.ldaptypes import LDAP_SID
                    decoded_values = []
                    for v in values:
                        sid = LDAP_SID(data=b64decode(v))
                        decoded_values.append(sid.formatCanonical())
                    values = decoded_values
                except Exception:
                    pass

            elif attr_name == "objectGUID":
                try:
                    from uuid import UUID
                    decoded_values = []
                    for v in values:
                        guid = UUID(bytes_le=b64decode(v))
                        decoded_values.append(str(guid))
                    values = decoded_values
                except Exception:
                    pass

            elif attr_name == "nTSecurityDescriptor":
                # Keep as raw bytes for security descriptor parsing
                try:
                    raw_values = [b64decode(v) for v in values]
                    values = raw_values
                except Exception:
                    pass

            # Store single value or list based on count
            if len(values) == 1:
                attributes[attr_name] = values[0]
            else:
                attributes[attr_name] = values

            raw_attributes[attr_name] = raw_values

        if not attributes:
            return None

        return LDAPEntry(
            dn=dn,
            attributes=attributes,
            raw_attributes=raw_attributes,
            type="searchResEntry",
        )

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
            user = LDAPEntry(
                attributes={"objectSid": user_sid, "distinguishedName": user_dn},
                raw_attributes={},
            )
            if not user_sid:
                logging.warning(
                    "User SID can't be retrieved. For more accurate results, add it manually with -sid"
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
                "Adding 'Domain Users' and 'Domain Computers' to list of current user's SIDs"
            )
            sids.add(f"{self.domain_sid}-513")  # Domain Users
            sids.add(f"{self.domain_sid}-515")  # Domain Computers

        # Collect DNs to search for group membership
        dns = [user.get("distinguishedName")]
        for sid in list(sids):
            object_entry = self.lookup_sid(sid)
            if object_entry.get("distinguishedName"):
                dns.append(object_entry.get("distinguishedName"))

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

            except Exception as e:
                logging.warning(f"Failed to get user SIDs: {e}")

        # Cache the results
        self._user_sids[sanitized_username] = sids

        # Debug output of collected SIDs
        logging.debug(f"User {username!r} has {len(sids)} SIDs:")
        for sid in sids:
            logging.debug(f"  {sid}")

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
                    "Domain is not set for ADWS connection. This may cause issues when looking up SIDs"
                )

            # Create synthetic entry for well-known SID
            entry = LDAPEntry(
                attributes={
                    "objectSid": f"{(self.domain or '').upper()}-{sid}",
                    "objectType": WELLKNOWN_SIDS[sid][1].capitalize(),
                    "name": f"{self.domain}\\{WELLKNOWN_SIDS[sid][0]}",
                },
                raw_attributes={},
            )
            self.sid_map[sid] = entry
            return entry

        # For regular SIDs, query the directory
        attributes = [
            "sAMAccountType",
            "name",
            "objectSid",
            "distinguishedName",
            "objectClass",
        ]

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
                attributes={
                    "objectSid": sid,
                    "name": sid,
                    "objectType": "Unknown",
                },
                raw_attributes={},
            )
        else:
            # Process found entry
            entry = results[0]
            entry.set("name", f"{self.domain}\\{entry.get('name')}")
            entry.set("objectType", get_account_type(entry))

        # Cache the result
        self.sid_map[sid] = entry
        return entry
