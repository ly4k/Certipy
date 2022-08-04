import argparse
import random
import string

import ldap3

from certipy.lib.formatting import pretty_print
from certipy.lib.ldap import LDAPConnection
from certipy.lib.logger import logging
from certipy.lib.target import Target


class Account:
    def __init__(
        self,
        target: Target,
        user: str,
        dns: str = None,
        upn: str = None,
        sam: str = None,
        spns: str = None,
        passw: str = None,
        group: str = None,
        scheme: str = "ldaps",
        connection: LDAPConnection = None,
        timeout: int = 5,
        debug: bool = False,
        **kwargs
    ):
        self.target = target
        self.user = user
        self.dns = dns
        self.upn = upn
        self.sam = sam
        self.spns = spns
        self.password = passw
        self.group = group
        self.scheme = scheme
        self._connection = connection
        self.timeout = timeout
        self.verbose = debug
        self.kwargs = kwargs

    @property
    def connection(self) -> LDAPConnection:
        if self._connection is not None:
            return self._connection

        self._connection = LDAPConnection(self.target, self.scheme)
        self._connection.connect()

        return self._connection

    def create(self):
        username = self.user
        if self.sam is not None:
            logging.warning(
                "The parameter -sam overrides the -user parameter for the create operation"
            )
            res = input("Do you want to continue? (Y/n) ").rstrip("\n")
            if res.lower() == "n":
                return False

            username = self.sam

        user = self.connection.get_user(username, silent=True)
        if user is not None:
            logging.error(
                "User %s already exists. If you want to update the user, specify the 'update' action"
                % repr(user.get("sAMAccountName"))
            )
            return False

        group = self.group
        if group is None:
            group = "CN=Computers," + self.connection.default_path

        if username[-1] != "$":
            username += "$"

        password = self.password
        if password is None:
            password = "".join(
                random.choice(string.ascii_letters + string.digits) for _ in range(16)
            )
            self.password = password

        dns = self.dns
        if dns is None:
            dns = (username.rstrip("$") + "." + self.connection.domain).lower()

        hostname = username[:-1]
        dn = "CN=%s,%s" % (hostname, group)

        spns = self.spns
        if spns is None:
            spns = [
                "HOST/%s" % username.rstrip("$"),
                "RestrictedKrbHost/%s" % username.rstrip("$"),
            ]
        else:
            spns = list(
                filter(
                    lambda x: len(x) > 0, map(lambda x: x.strip(), self.spns.split(","))
                )
            )

        attributes = {
            "sAMAccountName": username,
            "unicodePwd": password,  # just for the pretty print
            "userAccountControl": 0x1000,
            "servicePrincipalName": spns,
            "dnsHostName": dns,
        }

        logging.info("Creating new account:")
        pretty_print(attributes, indent=2)

        attributes["unicodePwd"] = ('"%s"' % password).encode("utf-16-le")

        result = self.connection.add(
            dn,
            ["top", "person", "organizationalPerson", "user", "computer"],
            attributes,
        )

        if result["result"] == 0:
            logging.info(
                "Successfully created account %s with password %s"
                % (repr(username), repr(password))
            )
            return True
        elif result["result"] == ldap3.core.results.RESULT_INSUFFICIENT_ACCESS_RIGHTS:
            logging.error(
                "User %s doesn't have the right to create a machine account"
                % repr(self.target.username)
            )
        elif (
            result["result"] == ldap3.core.results.RESULT_UNWILLING_TO_PERFORM
            and int(result["message"].split(":")[0].strip(), 16) == 0x216D
        ):
            logging.error(
                "Machine account quota exceeded for %s" % repr(self.target.username)
            )
        else:
            logging.error(
                "Received unknown error: (%s) %s"
                % (result["description"], result["message"])
            )

        return False

    def read(self):
        user = self.connection.get_user(self.user)
        if user is None:
            return False

        attribute_values = {}
        attributes = [
            "cn",
            "distinguishedName",
            "name",
            "objectSid",
            "sAMAccountName",
            "dNSHostName",
            "servicePrincipalName",
        ]

        logging.info("Reading attributes for %s:" % repr(user.get("sAMAccountName")))
        for attribute in attributes:
            value = user.get(attribute)
            if value is not None:
                attribute_values[attribute] = value
        pretty_print(attribute_values, indent=2)

    def update(self):
        user = self.connection.get_user(self.user)
        if user is None:
            return False

        changes = {}
        changes_formatted = {}

        attribute_mapping = {
            "unicodePwd": self.password,
            "dNSHostName": self.dns,
            "userPrincipalName": self.upn,
            "sAMAccountName": self.sam,
            "servicePrincipalName": list(
                filter(
                    lambda x: len(x) > 0, map(lambda x: x.strip(), self.spns.split(","))
                )
            )
            if self.spns is not None
            else None,
        }

        for attribute, value in attribute_mapping.items():
            if value is None:
                continue

            if value == "" or len(value) == 0:
                changes[attribute] = [
                    (
                        ldap3.MODIFY_DELETE,
                        [],
                    )
                ]
                changes_formatted[attribute] = "*DELETED*"
            else:
                if attribute == "unicodePwd":
                    encoded_value = ('"%s"' % value).encode("utf-16-le")
                    changes_formatted[attribute] = [value]
                else:
                    if isinstance(value, list):
                        encoded_value = value
                    else:
                        encoded_value = [value.encode("utf-8")]
                    changes_formatted[attribute] = value

                changes[attribute] = [
                    (
                        ldap3.MODIFY_REPLACE,
                        encoded_value,
                    )
                ]

        logging.info("Updating user %s:" % repr(user.get("sAMAccountName")))
        pretty_print(changes_formatted, indent=2)

        result = self.connection.modify(
            user.get("distinguishedName"),
            changes,
        )

        if result["result"] == 0:
            logging.info("Successfully updated %s" % repr(user.get("sAMAccountName")))
            return True
        elif result["result"] == ldap3.core.results.RESULT_INSUFFICIENT_ACCESS_RIGHTS:
            logging.error(
                "User %s doesn't have permission to update these attributes on %s"
                % (repr(self.target.username), repr(user.get("sAMAccountName")))
            )
        else:
            logging.error("Received error: %s" % result["message"])

        return False

    def delete(self):
        user = self.connection.get_user(self.user)
        if user is None:
            return False

        result = self.connection.delete(user.get("distinguishedName"))
        if result["result"] == 0:
            logging.info("Successfully deleted %s" % repr(user.get("sAMAccountName")))
            return True
        elif result["result"] == ldap3.core.results.RESULT_INSUFFICIENT_ACCESS_RIGHTS:
            logging.error(
                "User %s doesn't have permission to delete %s"
                % (repr(self.target.username), repr(user.get("sAMAccountName")))
            )
        else:
            logging.error("Received error: %s" % result["message"])


def entry(options: argparse.Namespace) -> None:
    target = Target.from_options(options, dc_as_target=True)
    del options.target

    account = Account(target, **vars(options))

    actions = {
        "create": account.create,
        "read": account.read,
        "update": account.update,
        "delete": account.delete,
    }

    actions[options.account_action]()
