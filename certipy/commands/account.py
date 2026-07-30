"""
Active Directory Account Management Module for Certipy.

This module provides CRUD (Create, Read, Update, Delete) operations for Active Directory accounts,
primarily focusing on computer accounts. It allows:
- Creating new computer accounts
- Reading account attributes
- Updating account properties (password, SPNs, DNS names, etc.)
- Deleting accounts

CRUD operations use LDAP. Internal temporary-account creation can retain a SAMR handle for reliable cleanup.
"""

import argparse
import random
import string
from typing import Any, Dict, List, Optional, Tuple, cast

import ldap3
from impacket.dcerpc.v5 import epm, samr, transport
from ldap3.core.results import (
    RESULT_INSUFFICIENT_ACCESS_RIGHTS,
    RESULT_UNWILLING_TO_PERFORM,
)

from certipy.lib.formatting import pretty_print
from certipy.lib.ldap import LDAPConnection
from certipy.lib.logger import logging
from certipy.lib.target import Target


class Account:
    """
    Active Directory account management class.

    This class provides methods to create, read, update, and delete Active Directory accounts,
    with a focus on computer accounts which can be used for various authentication scenarios.
    """

    def __init__(
        self,
        target: Target,
        user: str,
        dns: Optional[str] = None,
        upn: Optional[str] = None,
        sam: Optional[str] = None,
        spns: Optional[str] = None,
        passw: Optional[str] = None,
        group: Optional[str] = None,
        connection: Optional[LDAPConnection] = None,
        timeout: int = 5,
        **kwargs,  # type: ignore
    ):
        """
        Initialize account management with target and account options.

        Args:
            target: Target environment information (domain, credentials)
            user: Username for the account to manage
            dns: DNS hostname for the account
            upn: UserPrincipalName to set
            sam: sAMAccountName to set
            spns: Service Principal Names to set (comma-separated)
            passw: Password for the account
            group: Distinguished name of the group to place the account in
            scheme: LDAP connection scheme (ldap or ldaps)
            connection: Existing LDAP connection to reuse
            timeout: Connection timeout in seconds
            **kwargs: Additional arguments
        """
        self.target = target
        self.user = user
        self.dns = dns
        self.upn = upn
        self.sam = sam
        self.spns = spns
        self.password = passw
        self.group = group
        self._connection = connection
        self.timeout = timeout
        self.kwargs = kwargs
        self._samr_dce: Optional[Any] = None
        self._samr_server_handle: Optional[Any] = None
        self._samr_domain_handle: Optional[Any] = None
        self._samr_user_handle: Optional[Any] = None

    @property
    def connection(self) -> LDAPConnection:
        """
        Get or establish an LDAP connection to the target.

        Returns:
            Active LDAP connection
        """
        if self._connection is not None:
            return self._connection

        self._connection = LDAPConnection(self.target)
        self._connection.connect()

        return self._connection

    def create_temporary(self) -> bool:
        """Create a computer through SAMR and retain a delete-capable handle."""
        if not self.target.dc_ip:
            raise RuntimeError("A DC IP is required to create a temporary account")
        if not self.password:
            raise RuntimeError("A password is required for a temporary account")

        username = self.user if self.user.endswith("$") else f"{self.user}$"
        binding = epm.hept_map(
            self.target.dc_ip, samr.MSRPC_UUID_SAMR, protocol="ncacn_np"
        )
        rpc_transport = transport.DCERPCTransportFactory(binding)
        rpc_transport.setRemoteHost(self.target.dc_ip)
        rpc_transport.set_credentials(
            self.target.username,
            self.target.password or "",
            self.target.domain,
            self.target.lmhash,
            self.target.nthash,
            self.target.aes or "",
        )
        rpc_transport.set_kerberos(self.target.do_kerberos, kdcHost=self.target.dc_ip)

        try:
            dce = rpc_transport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)
            self._samr_dce = dce
            response = samr.hSamrConnect5(
                dce,
                f"\\\\{self.target.dc_ip}\x00",
                samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN,
            )
            self._samr_server_handle = response["ServerHandle"]
            domains = cast(
                List[Any],
                samr.hSamrEnumerateDomainsInSamServer(dce, self._samr_server_handle)[
                    "Buffer"
                ]["Buffer"],
            )
            candidates = [
                domain["Name"]
                for domain in domains
                if domain["Name"].lower() != "builtin"
            ]
            netbios_name = self.target.domain.split(".")[0].lower()
            matches = [name for name in candidates if name.lower() == netbios_name]
            selected_domain = matches[0] if matches else candidates[0]
            domain_sid = samr.hSamrLookupDomainInSamServer(
                dce, self._samr_server_handle, selected_domain
            )["DomainId"]
            self._samr_domain_handle = samr.hSamrOpenDomain(
                dce,
                self._samr_server_handle,
                samr.DOMAIN_LOOKUP | samr.DOMAIN_CREATE_USER,
                domain_sid,
            )["DomainHandle"]
            desired_access = (
                samr.USER_FORCE_PASSWORD_CHANGE | samr.USER_WRITE_ACCOUNT | samr.DELETE
            )
            created = samr.hSamrCreateUser2InDomain(
                dce,
                self._samr_domain_handle,
                username,
                samr.USER_WORKSTATION_TRUST_ACCOUNT,
                desired_access,
            )
            self._samr_user_handle = created["UserHandle"]
            samr.hSamrSetPasswordInternal4New(
                dce, self._samr_user_handle, self.password
            )
            account_info = samr.SAMPR_USER_INFO_BUFFER()
            account_info["tag"] = samr.USER_INFORMATION_CLASS.UserControlInformation
            account_info["Control"][
                "UserAccountControl"
            ] = samr.USER_WORKSTATION_TRUST_ACCOUNT
            samr.hSamrSetInformationUser2(dce, self._samr_user_handle, account_info)
            logging.info(f"Successfully created temporary account {username!r}")
            return True
        except BaseException:
            try:
                self.close_temporary(delete=self._samr_user_handle is not None)
            except Exception as cleanup_error:
                logging.warning(
                    f"Could not clean up a partially created temporary account: "
                    f"{cleanup_error}"
                )
            raise

    def close_temporary(self, delete: bool) -> bool:
        """Close the retained SAMR session, optionally deleting the account."""
        removed = False
        try:
            if delete and self._samr_user_handle is not None:
                samr.hSamrDeleteUser(self._samr_dce, self._samr_user_handle)
                self._samr_user_handle = None
                removed = True
            elif self._samr_user_handle is not None:
                samr.hSamrCloseHandle(self._samr_dce, self._samr_user_handle)
                self._samr_user_handle = None
        finally:
            if self._samr_user_handle is not None:
                try:
                    samr.hSamrCloseHandle(self._samr_dce, self._samr_user_handle)
                except Exception:
                    pass
                finally:
                    self._samr_user_handle = None
            for attribute in ("_samr_domain_handle", "_samr_server_handle"):
                handle = getattr(self, attribute)
                if handle is not None:
                    try:
                        samr.hSamrCloseHandle(self._samr_dce, handle)
                    except Exception:
                        pass
                    finally:
                        setattr(self, attribute, None)
            if self._samr_dce is not None:
                try:
                    self._samr_dce.disconnect()
                except Exception:
                    pass
                finally:
                    self._samr_dce = None
        return removed

    def create(self) -> bool:
        """
        Create a new computer account in Active Directory.

        This method creates a computer account with the specified properties,
        or with reasonable defaults if not provided.

        Returns:
            True if account creation succeeded, False otherwise
        """
        # Determine username (sAMAccountName)
        username = self.user
        if self.sam is not None:
            logging.warning(
                "The parameter -sam overrides the -user parameter for the create operation"
            )
            res = input("Do you want to continue? (Y/n): ")
            if res.strip().lower() == "n":
                return False

            username = self.sam

        # Check if user already exists
        user = self.connection.get_user(username, silent=True)
        if user is not None:
            logging.error(
                f"User {user.get('sAMAccountName')!r} already exists. "
                f"If you want to update the user, specify the 'update' action"
            )
            return False

        # Set container group for the account
        group = self.group
        if group is None:
            group = f"CN=Computers,{self.connection.default_path}"

        # Ensure computer account name ends with $
        if username[-1] != "$":
            username += "$"

        # Generate random password if not provided
        password = self.password
        if password is None:
            password = "".join(
                random.choice(string.ascii_letters + string.digits) for _ in range(16)
            )
            self.password = password

        # Set DNS hostname if not provided
        dns = self.dns
        if dns is None:
            dns = f"{username.rstrip('$')}.{self.connection.domain}".lower()

        # Create DN for the new account
        hostname = username[:-1]
        dn = f"CN={hostname},{group}"

        # Set default SPNs if not provided
        spns = self.spns
        if spns is None:
            base_name = username.rstrip("$")
            spns = [
                f"HOST/{base_name}",
                f"RestrictedKrbHost/{base_name}",
            ]
        else:
            spns = [spn.strip() for spn in spns.split(",") if spn.strip()]

        # Prepare account attributes
        attributes: Dict[str, Any] = {
            "sAMAccountName": username,
            "unicodePwd": password,  # Just for the pretty print
            "userAccountControl": 0x1000,  # WORKSTATION_TRUST_ACCOUNT
            "servicePrincipalName": spns,
            "dnsHostName": dns,
        }

        logging.info("Creating new account:")
        pretty_print(attributes, indent=2)

        # Convert password to proper format for LDAP
        attributes["unicodePwd"] = ('"%s"' % password).encode("utf-16-le")

        # Add the account via LDAP
        result = self.connection.add(
            dn,
            ["top", "person", "organizationalPerson", "user", "computer"],
            attributes,
        )

        # Handle result
        if result["result"] == 0:
            logging.info(
                f"Successfully created account {username!r} with password {password!r}"
            )
            return True
        elif result["result"] == RESULT_INSUFFICIENT_ACCESS_RIGHTS:
            logging.error(
                f"User {self.target.username!r} doesn't have the right to create a machine account"
            )
        elif (
            result["result"] == RESULT_UNWILLING_TO_PERFORM
            and int(result["message"].split(":")[0].strip(), 16) == 0x216D
        ):
            logging.error(
                f"Machine account quota exceeded for {self.target.username!r}"
            )
        else:
            logging.error(
                f"Received error: ({result['description']}) {result['message']}"
            )

        return False

    def read(self) -> bool:
        """
        Read and display account attributes.

        This method retrieves and displays key attributes of the specified account.

        Returns:
            True if account was found and attributes read, False otherwise
        """
        # Get user object
        user = self.connection.get_user(self.user)
        if user is None:
            return False

        # Define attributes to display
        attributes = [
            "cn",
            "distinguishedName",
            "name",
            "objectSid",
            "sAMAccountName",
            "dNSHostName",
            "servicePrincipalName",
            "userPrincipalName",
            "userAccountControl",
            "whenCreated",
            "whenChanged",
        ]

        # Collect attribute values
        attribute_values = {}
        logging.info(f"Reading attributes for {user.get('sAMAccountName')!r}:")
        for attribute in attributes:
            value = user.get(attribute)
            if value is not None:
                attribute_values[attribute] = value

        # Display attributes
        pretty_print(attribute_values, indent=2)
        return True

    def update(self) -> bool:
        """
        Update an existing account's attributes.

        This method modifies specified attributes of an existing account.

        Returns:
            True if account was successfully updated, False otherwise
        """
        # Get user object
        user = self.connection.get_user(self.user)
        if user is None:
            return False

        # Prepare attribute changes
        changes: Dict[str, List[Tuple[Any, Any]]] = {}
        changes_formatted: Dict[str, Any] = {}

        # Define which attributes to update based on provided parameters
        attribute_mapping = {
            "unicodePwd": self.password,
            "dNSHostName": self.dns,
            "userPrincipalName": self.upn,
            "sAMAccountName": self.sam,
            "servicePrincipalName": (
                [spn.strip() for spn in self.spns.split(",") if spn.strip()]
                if self.spns is not None
                else None
            ),
        }

        # Process each attribute that needs to be updated
        for attribute, value in attribute_mapping.items():
            if value is None:
                continue

            if value == "" or (isinstance(value, list) and len(value) == 0):
                # Delete the attribute
                changes[attribute] = [(ldap3.MODIFY_DELETE, [])]
                changes_formatted[attribute] = "*DELETED*"
            else:
                # Replace the attribute with new value
                if attribute == "unicodePwd":
                    # Special handling for password
                    encoded_value = ('"%s"' % value).encode("utf-16-le")
                    changes_formatted[attribute] = value  # Show plaintext in output
                else:
                    if isinstance(value, list):
                        encoded_value = value
                    else:
                        encoded_value = [value]  # LDAP expects lists for attributes
                    changes_formatted[attribute] = value

                changes[attribute] = [(ldap3.MODIFY_REPLACE, encoded_value)]

        if not changes:
            logging.warning(f"No changes specified for {user.get('sAMAccountName')!r}")
            return False

        logging.info(f"Updating user {user.get('sAMAccountName')!r}:")
        pretty_print(changes_formatted, indent=2)

        # Apply changes via LDAP
        result = self.connection.modify(
            user.get("distinguishedName"),
            changes,
        )

        # Handle result
        if result["result"] == 0:
            logging.info(f"Successfully updated {user.get('sAMAccountName')!r}")
            return True
        elif result["result"] == RESULT_INSUFFICIENT_ACCESS_RIGHTS:
            logging.error(
                f"User {self.target.username!r} doesn't have permission to update "
                f"these attributes on {user.get('sAMAccountName')!r}"
            )
        else:
            logging.error(f"Received error: {result['message']}")

        return False

    def delete(self) -> bool:
        """
        Delete an account from Active Directory.

        This method permanently removes the specified account.

        Returns:
            True if account was successfully deleted, False otherwise
        """
        # Get user object
        user = self.connection.get_user(self.user)
        if user is None:
            return False

        # Confirm deletion
        account_name = user.get("sAMAccountName")
        logging.warning(f"You are about to delete {account_name!r}")
        res = input("Are you sure? (y/N): ")
        if res.strip().lower() != "y":
            logging.info("Deletion canceled")
            return False

        # Delete account via LDAP
        result = self.connection.delete(user.get("distinguishedName"))

        # Handle result
        if result["result"] == 0:
            logging.info(f"Successfully deleted {account_name!r}")
            return True
        elif result["result"] == RESULT_INSUFFICIENT_ACCESS_RIGHTS:
            logging.error(
                f"User {self.target.username!r} doesn't have permission to delete {account_name!r}"
            )
        else:
            logging.error(f"Received error: {result['message']}")

        return False


def entry(options: argparse.Namespace) -> None:
    """
    Entry point for the 'account' command.

    This function creates the Account object and dispatches to the appropriate method
    based on the specified action.

    Args:
        options: Command line options
    """
    # Create target from command line options
    target = Target.from_options(options, dc_as_target=True)
    options.__delattr__("target")

    # Create account manager
    account = Account(target, **vars(options))

    # Map actions to methods
    actions = {
        "create": account.create,
        "read": account.read,
        "update": account.update,
        "delete": account.delete,
    }

    # Validate action
    if options.account_action not in actions:
        logging.error(f"Unknown action: {options.account_action}")
        logging.info(f"Available actions: {', '.join(actions.keys())}")
        return

    # Execute the requested action
    result = actions[options.account_action]()

    # Set exit code based on result
    if result is False:
        import sys

        sys.exit(1)
