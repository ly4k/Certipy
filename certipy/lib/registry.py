"""
Registry module for Certipy.

This module provides functionality for working with registry-like entries and connections
that can map between security identifiers (SIDs) and their corresponding objects.
It supports:
- Looking up well-known SIDs and RIDs
- Tracking user security identifiers
- Mapping between SIDs and friendly names

The primary classes are:
- RegEntry: Represents a registry-like entry with attributes
- RegConnection: Manages SID resolution and mapping
"""

from typing import Dict, List, Optional, Union

from certipy.lib.constants import WELLKNOWN_RIDS, WELLKNOWN_SIDS
from certipy.lib.ldap import LDAPEntry


class RegEntry(LDAPEntry):
    """
    Registry entry class that extends LDAPEntry to provide registry-specific functionality.

    This class represents an object in the registry with attributes similar to LDAP entries.
    It handles data type conversions and provides attribute access methods.
    """

    def __init__(self, *args, **kwargs) -> None:  # type: ignore
        """
        Initialize a registry entry.

        Args:
            **kwargs: Key-value pairs to initialize the entry with
        """
        super().__init__(self, *args, **kwargs)
        if "attributes" not in self:
            self["attributes"] = {}

    def get_raw(self, key: str) -> Union[bytes, List[bytes], None]:
        """
        Get a raw (bytes) representation of an attribute value.

        Args:
            key: The attribute name to retrieve

        Returns:
            Raw data as bytes, list of bytes, or None if not found

        Notes:
            - String values are encoded to bytes
            - List values have each item encoded to bytes
            - Other values are returned as-is
        """
        data = self.get(key)

        if isinstance(data, str):
            return data.encode()
        elif isinstance(data, list):
            return [x.encode() if isinstance(x, str) else x for x in data]

        return data


class RegConnection:
    """
    Registry connection class that manages SID mapping and resolution.

    This class provides functionality to:
    - Track user SIDs
    - Look up SIDs to find corresponding objects
    - Map between SIDs and their friendly names
    """

    def __init__(self, domain: str, sids: List[str], scheme: str = "file") -> None:
        """
        Initialize a registry connection.

        Args:
            domain: Domain name for the connection
            sids: List of security identifiers to track
            scheme: Connection scheme, defaults to "file"
        """
        self.domain: str = domain
        self.sids: List[str] = sids
        self.sid_map: Dict[str, RegEntry] = {}
        self.scheme: str = scheme

    def get_user_sids(
        self,
        _username: str,
        _user_sid: Optional[str] = None,
        _user_dn: Optional[str] = None,
    ) -> List[str]:
        """
        Get user security identifiers.

        Args:
            _username: Username (not used in this implementation)
            _user_sid: User's primary SID (not used in this implementation)
            _user_dn: User's distinguished name (not used in this implementation)

        Returns:
            List of SIDs associated with this connection

        Notes:
            The parameters are kept for API compatibility but not used.
            This implementation simply returns the SIDs provided at initialization.
        """
        return self.sids

    def lookup_sid(self, sid: str) -> RegEntry:
        """
        Look up a security identifier and return corresponding registry entry.

        Args:
            sid: Security identifier to look up

        Returns:
            RegEntry object representing the SID

        Notes:
            - Checks cached entries first
            - Then checks well-known SIDs
            - Then checks well-known RIDs
            - Finally creates a base entry if not found elsewhere
        """
        # Check if we've already cached this SID
        if sid in self.sid_map:
            return self.sid_map[sid]

        # Check well-known SIDs
        if sid in WELLKNOWN_SIDS:
            name, obj_type = WELLKNOWN_SIDS[sid]
            entry = RegEntry(
                **{
                    "attributes": {
                        "objectSid": f"{self.domain.upper()}-{sid}",
                        "objectType": obj_type.capitalize(),
                        "name": f"{self.domain}\\{name}",
                    }
                }
            )
            self.sid_map[sid] = entry
            return entry

        # Check if this is a well-known RID
        rid = sid.split("-")[-1]
        if rid in WELLKNOWN_RIDS:
            name, obj_type = WELLKNOWN_RIDS[rid]
            entry = RegEntry(
                **{
                    "attributes": {
                        "objectSid": f"{self.domain.upper()}-{sid}",
                        "objectType": obj_type.capitalize(),
                        "name": f"{self.domain}\\{name}",
                    }
                }
            )
            self.sid_map[sid] = entry
            return entry

        # Create a generic entry for unknown SIDs
        entry = RegEntry(
            **{
                "attributes": {
                    "objectSid": sid,
                    "name": sid,
                    "objectType": "Base",
                }
            }
        )

        # Cache this entry for future lookups
        self.sid_map[sid] = entry

        return entry
