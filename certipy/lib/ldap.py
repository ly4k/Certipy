"""
LDAP connection and query functionality for Certipy.

This module provides classes and methods for:
- Establishing LDAP/LDAPS connections to Active Directory
- Performing common search and modification operations
- Mapping between security identifiers (SIDs) and account objects
- Managing user and group membership information
- Handling various authentication methods (NTLM, Kerberos, simple bind)

Main components:
- LDAPEntry: Dictionary-like class for LDAP objects with attribute access methods
- LDAPConnection: Main class for connecting to and querying LDAP servers
- ExtendedLdapConnection: Extends ldap3 Connection with custom encryption support
- ExtendedStrategy: Custom LDAP strategy for handling secure communications
"""

import socket
import ssl
import tempfile
from typing import Any, Dict, List, Optional, Set, Tuple, Union, cast

import ldap3
import ldap3.strategy
import ldap3.strategy.sync
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from impacket.ntlm import NTLMSSP_NEGOTIATE_SEAL, NTLMAuthChallenge
from ldap3.core.exceptions import LDAPExceptionError
from ldap3.core.results import (
    RESULT_INVALID_CREDENTIALS,
    RESULT_STRONGER_AUTH_REQUIRED,
    RESULT_SUCCESS,
)
from ldap3.operation.bind import bind_operation
from ldap3.protocol import rfc4511
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.strategy.base import BaseStrategy
from ldap3.utils.asn1 import encode as _ldap3_encode  # type: ignore
from pyasn1.codec.ber.encoder import Encoder

ldap3_encode = cast(Encoder, _ldap3_encode)


from certipy.lib.certificate import cert_to_pem, key_to_pem, x509
from certipy.lib.channel_binding import get_channel_binding_data_from_ssl_socket
from certipy.lib.constants import WELLKNOWN_SIDS
from certipy.lib.errors import handle_error
from certipy.lib.kerberos import KerberosCipher, get_kerberos_type1
from certipy.lib.logger import logging
from certipy.lib.ntlm import NTLMCipher, ntlm_authenticate, ntlm_negotiate
from certipy.lib.target import Target


def get_account_type(entry: "LDAPEntry") -> str:
    """
    Determine the type of Active Directory account based on sAMAccountType and objectClass.

    Args:
        entry: LDAP entry containing account attributes

    Returns:
        Account type as string: "Group", "Computer", "User", "TrustAccount", or "Domain"
    """
    account_type = entry.get("sAMAccountType")
    object_class = entry.get("objectClass") or []

    # Group accounts
    if account_type in [268435456, 268435457, 536870912, 536870913]:
        return "Group"
    # Computer accounts
    elif account_type in [805306369]:
        return "Computer"
    # User accounts (including managed service accounts)
    elif (
        account_type in [805306368]
        or "msDS-GroupManagedServiceAccount" in object_class
        or "msDS-ManagedServiceAccount" in object_class
    ):
        return "User"
    # Trust accounts
    elif account_type in [805306370]:
        return "TrustAccount"
    # Default to Domain
    else:
        return "Domain"


class LDAPEntry(Dict[str, Any]):
    """
    Dictionary-like class representing an LDAP entry with helper methods.

    This class extends the standard dictionary to provide convenient access
    to LDAP attributes and raw attribute values.
    """

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get an attribute value from the LDAP entry with support for default values.

        This method provides convenient access to LDAP attributes and handles several
        special cases, including missing attributes and empty lists.

        Args:
            key: Attribute name to retrieve
            default: Value to return if attribute is missing or empty (default: None)

        Returns:
            Attribute value if present and not empty, otherwise the default value
        """
        if key not in self.__getitem__("attributes").keys():
            return default

        item = self.__getitem__("attributes").__getitem__(key)

        # Return default for empty lists
        if isinstance(item, list) and len(item) == 0:
            return default

        return item

    def set(self, key: str, value: Any) -> None:
        """
        Set an attribute value in the LDAP entry.

        Args:
            key: Attribute name to set
            value: Value to assign to the attribute
        """
        return self.__getitem__("attributes").__setitem__(key, value)

    def get_raw(self, key: str) -> Any:
        """
        Get the raw (unprocessed) attribute value from the LDAP entry.

        Args:
            key: Attribute name to retrieve

        Returns:
            Raw attribute value or None if not present
        """
        if key not in self.__getitem__("raw_attributes").keys():
            return None

        return self.__getitem__("raw_attributes").__getitem__(key)


class ExtendedStrategy(ldap3.strategy.sync.SyncStrategy):
    """
    Extended strategy class for LDAP connections with encryption support.

    This class extends the default SyncStrategy to provide custom
    sending and receiving methods for LDAP messages. It handles
    encryption and decryption of messages using NTLM or Kerberos
    ciphers, as well as custom error handling.
    """

    def __init__(self, connection: "ExtendedLdapConnection") -> None:
        """
        Initialize the extended strategy with a connection.

        Args:
            connection: The ExtendedLdapConnection to use
        """
        super().__init__(connection)
        self._connection = connection
        # Override the default receiving method to use the custom implementation
        self.receiving = self._receiving
        self.sequence_number = 0

    def sending(self, ldap_message: Any) -> None:
        """
        Send an LDAP message, optionally encrypting it first.

        Args:
            ldap_message: The LDAP message to send

        Raises:
            socket.error: If sending fails
        """
        try:
            encoded_message = cast(bytes, ldap3_encode(ldap_message))

            # Encrypt the message if required and not in SASL progress
            if self._connection.should_encrypt and not self.connection.sasl_in_progress:
                encoded_message = self._connection._encrypt(encoded_message)
                self.sequence_number += 1

            self.connection.socket.sendall(encoded_message)
        except socket.error as e:
            self.connection.last_error = f"socket sending error: {e}"
            logging.error(f"Failed to send LDAP message: {e}")
            handle_error()
            raise

        # Update usage statistics if enabled
        if self.connection.usage:
            self.connection._usage.update_transmitted_message(
                self.connection.request, len(encoded_message)
            )

    def _receiving(self) -> List[bytes]:  # type: ignore
        """
        Receive data over the socket and handle message encryption/decryption.

        Returns:
            List of received LDAP messages

        Raises:
            Exception: On socket or receive errors
        """
        messages = []
        receiving = True
        unprocessed = b""
        data = b""
        get_more_data = True
        sasl_total_bytes_received = 0
        sasl_received_data = b""
        sasl_next_packet = b""
        sasl_buffer_length = -1

        while receiving:
            if get_more_data:
                try:
                    data = self.connection.socket.recv(self.socket_size)
                except (OSError, socket.error, AttributeError) as e:
                    self.connection.last_error = f"error receiving data: {e}"
                    try:
                        self.close()
                    except (socket.error, LDAPExceptionError):
                        pass
                    logging.error(f"Failed to receive LDAP message: {e}")
                    handle_error()
                    raise

                # Handle encrypted messages (from NTLM or Kerberos)
                if (
                    self._connection.should_encrypt
                    and not self.connection.sasl_in_progress
                ):
                    data = sasl_next_packet + data

                    if sasl_received_data == b"" or sasl_next_packet:
                        # Get the size of the encrypted message
                        sasl_buffer_length = int.from_bytes(data[0:4], "big")
                        data = data[4:]
                    sasl_next_packet = b""
                    sasl_total_bytes_received += len(data)
                    sasl_received_data += data

                    # Check if we have received the complete encrypted message
                    if sasl_total_bytes_received >= sasl_buffer_length:
                        # Handle multi-packet SASL messages
                        # When the LDAP response is split across multiple TCP packets,
                        # the SASL buffer length might not match our socket buffer size
                        sasl_next_packet = sasl_received_data[sasl_buffer_length:]

                        # Decrypt the received message
                        sasl_received_data = self._connection._decrypt(
                            sasl_received_data[:sasl_buffer_length]
                        )
                        sasl_total_bytes_received = 0
                        unprocessed += sasl_received_data
                        sasl_received_data = b""
                else:
                    unprocessed += data

            if len(data) > 0:
                # Try to compute the message length
                length = BaseStrategy.compute_ldap_message_size(unprocessed)

                if length == -1:  # too few data to decode message length
                    get_more_data = True
                    continue

                if len(unprocessed) < length:
                    get_more_data = True
                else:
                    messages.append(unprocessed[:length])
                    unprocessed = unprocessed[length:]
                    get_more_data = False
                    if len(unprocessed) == 0:
                        receiving = False
            else:
                receiving = False

        return messages


class ExtendedLdapConnection(ldap3.Connection):
    """
    Extended LDAP connection class with support for secure communication.

    This class extends the ldap3.Connection class to provide additional
    functionality for LDAP operations, including support for NTLM and
    Kerberos encryption, channel binding, and custom error handling.
    """

    def __init__(
        self, target: Target, *args: Any, channel_binding: bool = True, **kwargs: Any
    ) -> None:
        """
        Initialize an extended LDAP connection with the specified target.

        Args:
            target: Target object containing connection details
            channel_binding: Whether to use channel binding (default: True)
            *args: Additional positional arguments for the parent class
            **kwargs: Additional keyword arguments for the parent class
        """
        super().__init__(*args, **kwargs)

        # Replace standard strategy with extended strategy
        self.strategy = ExtendedStrategy(self)

        # Store target and connection properties
        self.target = target
        self.channel_binding = channel_binding
        self.negotiated_flags = 0

        # Encryption-related attributes
        self.ntlm_cipher: Optional[NTLMCipher] = None
        self.kerberos_cipher: Optional[KerberosCipher] = None
        self.should_encrypt = False

        # Alias important methods from strategy for direct access
        self.send = self.strategy.send
        self.open = self.strategy.open
        self.get_response = self.strategy.get_response
        self.post_send_single_response = self.strategy.post_send_single_response
        self.post_send_search = self.strategy.post_send_search

    def _encrypt(self, data: bytes) -> bytes:
        """
        Encrypt LDAP message data using the appropriate cipher.

        Args:
            data: Plaintext data to encrypt

        Returns:
            Encrypted data with appropriate headers and signatures
        """
        if self.ntlm_cipher is not None:
            # NTLM encryption
            signature, data = self.ntlm_cipher.encrypt(data)
            data = signature.getData() + data
            data = len(data).to_bytes(4, byteorder="big", signed=False) + data
        elif self.kerberos_cipher is not None:
            # Kerberos encryption
            data, signature = self.kerberos_cipher.encrypt(
                data, self.strategy.sequence_number
            )
            data = signature + data
            data = len(data).to_bytes(4, byteorder="big", signed=False) + data

        return data

    def _decrypt(self, data: bytes) -> bytes:
        """
        Decrypt LDAP message data using the appropriate cipher.

        Args:
            data: Encrypted data to decrypt

        Returns:
            Decrypted plaintext data
        """
        if self.ntlm_cipher is not None:
            # NTLM decryption
            _, data = self.ntlm_cipher.decrypt(data)
        elif self.kerberos_cipher is not None:
            # Kerberos decryption
            data = self.kerberos_cipher.decrypt(data)

        return data

    def do_ntlm_bind(self, controls: Any) -> Dict[str, Any]:
        """
        Perform NTLM bind operation with optional controls.

        This method implements the complete NTLM authentication flow:
        1. Sicily package discovery to verify NTLM support
        2. NTLM negotiate message exchange
        3. Challenge/response handling with optional channel binding
        4. Session key establishment and encryption setup

        Args:
            controls: Optional LDAP controls to apply during the bind operation

        Returns:
            Result of the bind operation

        Raises:
            Exception: If NTLM authentication fails or is not supported
        """
        self.last_error = None  # type: ignore

        with self.connection_lock:
            if not self.sasl_in_progress:
                self.sasl_in_progress = True  # NTLM uses SASL-like authentication flow
                try:
                    # Step 1: Sicily package discovery to check for NTLM support
                    request = rfc4511.BindRequest()
                    request["version"] = rfc4511.Version(self.version)
                    request["name"] = ""
                    request[
                        "authentication"
                    ] = rfc4511.AuthenticationChoice().setComponentByName(
                        "sicilyPackageDiscovery", rfc4511.SicilyPackageDiscovery("")
                    )

                    response = self.post_send_single_response(
                        self.send("bindRequest", request, controls)
                    )

                    result = response[0]

                    if not "server_creds" in result:
                        raise Exception(
                            "Server did not return available authentication packages during discovery request"
                        )

                    # Check if NTLM is supported
                    sicily_packages = result["server_creds"].decode().split(";")
                    if not "NTLM" in sicily_packages:
                        logging.error(
                            f"NTLM authentication not available on server. Supported packages: {sicily_packages}"
                        )
                        raise Exception("NTLM not available on server")

                    # Step 2: Send NTLM negotiate message
                    use_signing = self.target.ldap_signing and not self.server.ssl
                    logging.debug(
                        f"Using NTLM signing: {use_signing} (LDAP signing: {self.target.ldap_signing}, SSL: {self.server.ssl})"
                    )
                    negotiate = ntlm_negotiate(use_signing)

                    request = rfc4511.BindRequest()
                    request["version"] = rfc4511.Version(self.version)
                    request["name"] = "NTLM"
                    request[
                        "authentication"
                    ] = rfc4511.AuthenticationChoice().setComponentByName(
                        "sicilyNegotiate", rfc4511.SicilyNegotiate(negotiate.getData())
                    )

                    response = self.post_send_single_response(
                        self.send("bindRequest", request, controls)
                    )

                    result = response[0]

                    if result["result"] != RESULT_SUCCESS:
                        logging.error(f"NTLM negotiate failed: {result}")
                        return result

                    if not "server_creds" in result:
                        logging.error(
                            "Server did not return NTLM challenge during bind request"
                        )
                        raise Exception(
                            "Server did not return NTLM challenge during bind request"
                        )

                    # Step 3: Process challenge and prepare authenticate response
                    challenge = NTLMAuthChallenge()
                    challenge.fromString(result["server_creds"])

                    channel_binding_data = None
                    use_channel_binding = (
                        self.target.ldap_channel_binding and self.server.ssl
                    )
                    logging.debug(
                        f"Using channel binding signing: {use_channel_binding} (LDAP channel binding: {self.target.ldap_channel_binding}, SSL: {self.server.ssl})"
                    )
                    if use_channel_binding:
                        if not isinstance(self.socket, ssl.SSLSocket):
                            raise Exception(
                                "LDAP server is using SSL but the connection is not an SSL socket"
                            )

                        logging.debug(
                            "Using LDAP channel binding for NTLM authentication"
                        )

                        # Extract channel binding data from SSL socket
                        channel_binding_data = get_channel_binding_data_from_ssl_socket(
                            self.socket
                        )

                    # Generate NTLM authenticate message
                    challenge_response, session_key, negotiated_flags = (
                        ntlm_authenticate(
                            negotiate,
                            challenge,
                            self.target.username,
                            self.target.password or "",
                            self.target.domain,
                            self.target.nthash,
                            channel_binding_data=channel_binding_data,
                        )
                    )

                    # Step 4: Set up encryption if negotiated
                    self.negotiated_flags = negotiated_flags
                    self.should_encrypt = (
                        negotiated_flags & NTLMSSP_NEGOTIATE_SEAL
                        == NTLMSSP_NEGOTIATE_SEAL
                    )

                    if self.should_encrypt:
                        self.ntlm_cipher = NTLMCipher(
                            negotiated_flags,
                            session_key,
                        )

                    # Step 5: Complete authentication with the NTLM authenticate message
                    request = rfc4511.BindRequest()
                    request["version"] = rfc4511.Version(self.version)
                    request["name"] = ""
                    request[
                        "authentication"
                    ] = rfc4511.AuthenticationChoice().setComponentByName(
                        "sicilyResponse",
                        rfc4511.SicilyResponse(challenge_response.getData()),
                    )

                    response = self.post_send_single_response(
                        self.send("bindRequest", request, controls)
                    )

                    result = response[0]

                    if result["result"] != RESULT_SUCCESS:
                        logging.error(f"LDAP NTLM authentication failed: {result}")
                    else:
                        logging.debug(f"LDAP NTLM authentication successful")

                    return result
                finally:
                    self.sasl_in_progress = False
            else:
                raise Exception("SASL authentication already in progress")


class LDAPConnection:
    """
    Manages connections and operations to Active Directory via LDAP/LDAPS.

    This class handles authentication, searching, and modifying objects in
    Active Directory using the ldap3 library with extended functionality
    for secure operations.
    """

    def __init__(
        self,
        target: Target,
        schannel_auth: Optional[Tuple[x509.Certificate, PrivateKeyTypes]] = None,
    ) -> None:
        """
        Initialize an LDAP connection with the specified target.

        Args:
            target: Target object containing connection details
            ldap_pfx: Optional tuple containing LDAP PFX file path and password
        """
        self.target = target
        self.schannel_auth = schannel_auth
        self.use_ssl = target.ldap_scheme == "ldaps"

        # Determine port based on scheme and target configuration
        if self.use_ssl:
            self.port = int(target.ldap_port) if target.ldap_port is not None else 636
        else:
            self.port = int(target.ldap_port) if target.ldap_port is not None else 389

        # Connection-related attributes
        self.default_path: Optional[str] = None
        self.configuration_path: Optional[str] = None
        self.ldap_server: Optional[ldap3.Server] = None
        self.ldap_conn: Optional[Union["ExtendedLdapConnection", ldap3.Connection]] = (
            None
        )
        self.domain: Optional[str] = None

        # Caching and tracking
        self.sid_map: Dict[str, LDAPEntry] = {}
        self._domain_sid: Optional[str] = None
        self._users: Dict[str, LDAPEntry] = {}
        self._user_sids: Dict[str, Set[str]] = {}
        self.warned_missing_domain_sid_lookup: bool = False

    def connect(self) -> None:
        """
        Connect to the LDAP server with the specified SSL/TLS version.

        This method establishes a connection to the LDAP server and handles
        authentication using the credentials from the target object.
        It supports multiple authentication methods:
        - Kerberos
        - NTLM
        - Simple bind

        Raises:
            Exception: If connection or authentication fails
        """
        if self.target.target_ip is None:
            raise Exception("Target IP is not set")

        if self.schannel_auth is not None:
            return self.schannel_connect()

        # Format user credentials
        user = f"{self.target.domain}\\{self.target.username}"
        user_upn = f"{self.target.username}@{self.target.domain}"

        # Create server object based on scheme
        if self.use_ssl:
            # Configure TLS for LDAPS
            tls = ldap3.Tls(
                validate=ssl.CERT_NONE,
                version=ssl.PROTOCOL_TLS_CLIENT,
                ciphers="ALL:@SECLEVEL=0",
                ssl_options=[ssl.OP_ALL],
            )
            ldap_server = ldap3.Server(
                self.target.target_ip,
                use_ssl=True,
                port=self.port,
                get_info=ldap3.ALL,
                tls=tls,
                connect_timeout=self.target.timeout,
            )
        else:
            ldap_server = ldap3.Server(
                self.target.target_ip,
                use_ssl=False,
                port=self.port,
                get_info=ldap3.ALL,
                connect_timeout=self.target.timeout,
            )

        # Authentication based on method
        if self.target.do_kerberos:
            logging.debug("Authenticating to LDAP server using Kerberos authentication")

            # Create connection for Kerberos authentication
            ldap_conn = ExtendedLdapConnection(
                self.target,
                ldap_server,
                receive_timeout=self.target.timeout * 10,
            )
            self._kerberos_login(ldap_conn)
        else:
            auth_method = "SIMPLE" if self.target.do_simple else "NTLM"
            logging.debug(
                f"Authenticating to LDAP server using {auth_method} authentication"
            )

            # Set up credentials for NTLM or simple authentication
            if self.target.hashes is not None:
                ldap_pass = f"{self.target.lmhash}:{self.target.nthash}"
            else:
                ldap_pass = self.target.password

            # Create connection
            ldap_conn = ExtendedLdapConnection(
                self.target,
                ldap_server,
                user=user_upn if self.target.do_simple else user,
                password=ldap_pass,
                authentication=ldap3.SIMPLE if self.target.do_simple else ldap3.NTLM,
                auto_referrals=False,
                receive_timeout=self.target.timeout * 10,
            )

        # Perform bind operation if not already bound
        if not ldap_conn.bound:
            bind_result = ldap_conn.bind()
            if not bind_result:
                result = ldap_conn.result

                self._check_ldap_result(result)

        # Get schema information if not already available
        if ldap_server.schema is None:
            ldap_server.get_info_from_server(ldap_conn)

            if ldap_conn.result["result"] != RESULT_SUCCESS:
                if ldap_conn.result["message"].split(":")[0] == "000004DC":
                    raise Exception(
                        "Failed to bind to LDAP. This is most likely due to an invalid username"
                    )

            if ldap_server.schema is None:
                raise Exception("Failed to get LDAP schema")

        logging.debug(f"Bound to {ldap_server}")

        # Store connection objects and directory paths
        self.ldap_conn = ldap_conn
        self.ldap_server = ldap_server

        self.default_path = self.ldap_server.info.other["defaultNamingContext"][0]
        self.configuration_path = self.ldap_server.info.other[
            "configurationNamingContext"
        ][0]

        logging.debug(f"Default path: {self.default_path}")
        logging.debug(f"Configuration path: {self.configuration_path}")

        # Extract domain name from LDAP service name
        self.domain = self.ldap_server.info.other["ldapServiceName"][0].split("@")[-1]

    def schannel_connect(self) -> None:
        if self.schannel_auth is None:
            raise Exception(
                "Schannel authentication requires a certificate and private key"
            )

        if self.target.target_ip is None:
            raise Exception("Target IP is not set")

        cert, key = self.schannel_auth

        # Create temporary files for certificate and key
        key_file = tempfile.NamedTemporaryFile(delete=False)
        _ = key_file.write(key_to_pem(key))
        key_file.close()

        cert_file = tempfile.NamedTemporaryFile(delete=False)
        _ = cert_file.write(cert_to_pem(cert))
        cert_file.close()

        # Configure TLS for LDAPS
        tls = ldap3.Tls(
            local_private_key_file=key_file.name,
            local_certificate_file=cert_file.name,
            validate=ssl.CERT_NONE,
            version=ssl.PROTOCOL_TLS_CLIENT,
            ciphers="ALL:@SECLEVEL=0",
            ssl_options=[ssl.OP_ALL],
        )

        ldap_server = ldap3.Server(
            self.target.target_ip,
            use_ssl=self.use_ssl,
            port=self.port,
            get_info=ldap3.ALL,
            tls=tls,
            connect_timeout=self.target.timeout,
        )

        logging.debug("Authenticating to LDAP server using Schannel authentication")
        logging.info(
            f"Connecting to {f'{self.target.ldap_scheme}://{self.target.target_ip}:{self.port}'!r}"
        )

        # Configure authentication parameters for non-SSL connections
        conn_kwargs = {}
        if not self.use_ssl:
            # Configure SASL credentials if user DN is specified
            sasl_credentials = None
            if self.target.ldap_user_dn:
                sasl_credentials = f"dn:{self.target.ldap_user_dn}"

            if sasl_credentials:
                logging.info(f"Using DN: {sasl_credentials!r}")
            else:
                logging.warning(
                    "No DN specified for LDAP authentication. "
                    "Try to use '-ldap-user-dn' to specify a user DN if authentication fails"
                )

            conn_kwargs = {
                "authentication": ldap3.SASL,
                "sasl_mechanism": ldap3.EXTERNAL,
                "auto_bind": ldap3.AUTO_BIND_TLS_BEFORE_BIND,
                "sasl_credentials": sasl_credentials,
            }

        # Create connection
        try:
            ldap_conn = ldap3.Connection(
                ldap_server,
                raise_exceptions=True,
                auto_referrals=False,
                receive_timeout=self.target.timeout * 10,
                **conn_kwargs,  # type: ignore
            )
        except Exception as e:
            logging.error(f"Failed to connect to LDAP server: {e}")
            raise

        # Open the connection if using SSL. Non-SSL connections are opened automatically.
        if self.use_ssl:
            ldap_conn.open()

        # Get authenticated identity
        who_am_i = ldap_conn.extend.standard.who_am_i()
        if not who_am_i:
            raise Exception(
                "Failed to authenticate to LDAP server. Server did not return an identity (whoAmI)"
            )

        logging.info(f"Authenticated to {self.target.target_ip!r} as: {who_am_i!r}")

        # Get schema information if not already available
        if ldap_server.schema is None:
            ldap_server.get_info_from_server(ldap_conn)

            if ldap_conn.result["result"] != RESULT_SUCCESS:
                if ldap_conn.result["message"].split(":")[0] == "000004DC":
                    raise Exception(
                        "Failed to bind to LDAP. This is most likely due to an invalid username"
                    )

            if ldap_server.schema is None:
                raise Exception("Failed to get LDAP schema")

        logging.debug(f"Bound to {ldap_server}")

        # Store connection objects and directory paths
        self.ldap_conn = ldap_conn
        self.ldap_server = ldap_server

        self.default_path = self.ldap_server.info.other["defaultNamingContext"][0]
        self.configuration_path = self.ldap_server.info.other[
            "configurationNamingContext"
        ][0]

        logging.debug(f"Default path: {self.default_path}")
        logging.debug(f"Configuration path: {self.configuration_path}")

        # Extract domain name from LDAP service name
        self.domain = self.ldap_server.info.other["ldapServiceName"][0].split("@")[-1]

    def _kerberos_login(self, connection: "ExtendedLdapConnection") -> None:
        """
        Perform Kerberos authentication to LDAP server.

        Args:
            connection: LDAP connection object

        Raises:
            Exception: If Kerberos authentication fails
        """

        # Ensure connection is open
        if connection.closed:
            connection.open(read_server_info=True)

        # Setup channel binding if enabled and using SSL
        channel_binding_data = None
        if self.target.ldap_channel_binding and connection.server.ssl:
            logging.debug("Using LDAP channel binding for Kerberos authentication")

            if not isinstance(connection.socket, ssl.SSLSocket):
                raise Exception(
                    "LDAP server is using SSL but the connection is not an SSL socket"
                )

            # Extract channel binding data from SSL socket
            channel_binding_data = get_channel_binding_data_from_ssl_socket(
                connection.socket
            )

        # Get Kerberos Type 1 message
        cipher, session_key, blob, username = get_kerberos_type1(
            self.target,
            target_name=self.target.remote_name or "",
            channel_binding_data=channel_binding_data,
            signing=self.target.ldap_signing and not connection.server.ssl,
        )

        # Create SASL bind request
        request = bind_operation(
            connection.version,
            ldap3.SASL,
            username,
            None,
            "GSS-SPNEGO",
            blob,
        )

        # Send bind request and process response
        connection.sasl_in_progress = True
        response = connection.post_send_single_response(
            connection.send("bindRequest", request, None)
        )
        connection.sasl_in_progress = False

        result = response[0]

        if result["result"] != RESULT_SUCCESS:
            logging.error(f"LDAP Kerberos authentication failed: {result}")
        else:
            logging.debug(f"LDAP Kerberos authentication successful")

        self._check_ldap_result(result)

        # Set up encryption if signing is requested
        if self.target.ldap_signing and not connection.server.ssl:
            connection.kerberos_cipher = KerberosCipher(cipher, session_key)
            connection.should_encrypt = self.target.ldap_signing

        connection.bound = True

    def _check_ldap_result(self, result: Dict[str, Any]) -> None:
        """
        Handle LDAP errors based on the result dictionary.

        Args:
            result: Result dictionary from the LDAP bind operation

        Raises:
            Exception: If an error occurs during the LDAP operation
        """
        if result["result"] != RESULT_SUCCESS:
            if (
                result["result"] == RESULT_INVALID_CREDENTIALS
                and result["message"].split(":")[0] == "80090346"
            ):
                raise Exception(
                    (
                        "LDAP authentication refused because channel binding policy was not satisfied. "
                        "Try one of these options:\n"
                        "- Remove '-no-ldap-channel-binding'\n"
                        "- Use '-ldap-scheme ldap' to disable TLS encryption\n"
                        "- Use '-ldap-simple-auth' for SIMPLE bind authentication"
                    )
                )
            elif (
                result["result"] == RESULT_STRONGER_AUTH_REQUIRED
                and result["message"].split(":")[0] == "00002028"
            ):
                raise Exception(
                    "LDAP authentication refused because LDAP signing is required. "
                    "Try one of these options:\n"
                    "- Remove '-no-ldap-signing' to enable LDAP signing\n"
                    "- Use '-ldap-scheme ldaps' to use TLS encryption\n"
                    "- Use '-ldap-simple-auth' for SIMPLE bind authentication"
                )
            raise Exception(f"Kerberos authentication failed: {result}")

    def add(self, *args: Any, **kwargs: Any) -> Any:
        """
        Add a new entry to the LDAP directory.

        Args:
            *args: Arguments to pass to the underlying LDAP add operation
            **kwargs: Keyword arguments to pass to the underlying LDAP add operation

        Returns:
            Result of the add operation

        Raises:
            Exception: If LDAP connection is not established
        """
        if not self.ldap_conn:
            raise Exception("LDAP connection is not established")

        self.ldap_conn.add(*args, **kwargs)
        return self.ldap_conn.result

    def delete(self, *args: Any, **kwargs: Any) -> Any:
        """
        Delete an entry from the LDAP directory.

        Args:
            *args: Arguments to pass to the underlying LDAP delete operation
            **kwargs: Keyword arguments to pass to the underlying LDAP delete operation

        Returns:
            Result of the delete operation

        Raises:
            Exception: If LDAP connection is not established
        """
        if not self.ldap_conn:
            raise Exception("LDAP connection is not established")

        self.ldap_conn.delete(*args, **kwargs)
        return self.ldap_conn.result

    def modify(self, *args: Any, **kwargs: Any) -> Any:
        """
        Modify an existing entry in the LDAP directory.

        Args:
            *args: Arguments to pass to the underlying LDAP modify operation
            **kwargs: Keyword arguments to pass to the underlying LDAP modify operation

        Returns:
            Result of the modify operation

        Raises:
            Exception: If LDAP connection is not established
        """
        if not self.ldap_conn:
            raise Exception("LDAP connection is not established")

        self.ldap_conn.modify(*args, **kwargs)
        return self.ldap_conn.result

    def search(
        self,
        search_filter: str,
        attributes: Union[str, List[str]] = ldap3.ALL_ATTRIBUTES,
        search_base: Optional[str] = None,
        query_sd: bool = False,
        **kwargs: Any,
    ) -> List[LDAPEntry]:
        """
        Search the LDAP directory with the given filter and return matching entries.

        Args:
            search_filter: LDAP search filter string
            attributes: List of attributes to retrieve or ldap3.ALL_ATTRIBUTES
            search_base: Base DN for the search, defaults to domain base
            query_sd: Whether to query security descriptors
            **kwargs: Additional arguments for the search operation

        Returns:
            List of matching LDAP entries

        Raises:
            Exception: If LDAP connection is not established
        """
        if search_base is None:
            search_base = self.default_path

        # Set security descriptor control if requested
        if query_sd:
            controls = security_descriptor_control(sdflags=0x5)
        else:
            controls = None

        if self.ldap_conn is None:
            raise Exception("LDAP connection is not established")

        # Perform paged search to handle large result sets
        results = self.ldap_conn.extend.standard.paged_search(
            search_base=search_base,
            search_filter=search_filter,
            attributes=attributes,
            controls=controls,
            paged_size=200,
            generator=True,
            **kwargs,
        )

        if self.ldap_conn.result["result"] != 0:
            logging.warning(
                f"LDAP search {search_filter!r} failed: "
                f"({self.ldap_conn.result['description']}) {self.ldap_conn.result['message']}"
            )
            return []

        # Convert search results to LDAPEntry objects
        entries = list(
            map(
                lambda entry: LDAPEntry(**entry),
                filter(
                    lambda entry: entry["type"] == "searchResEntry",
                    results,
                ),
            )
        )
        return entries

    def get_user(
        self, username: str, silent: bool = False, *args: Any, **kwargs: Any
    ) -> Optional[LDAPEntry]:
        """
        Find a user by samAccountName.

        This method searches for a user by samAccountName and automatically
        handles computer account naming ($) if needed.

        Args:
            username: Username to search for (samAccountName)
            silent: Whether to suppress error logging for missing users
            *args: Additional arguments for the search
            **kwargs: Additional keyword arguments for the search

        Returns:
            User entry or None if not found
        """

        def _get_user(username: str, *args: Any, **kwargs: Any) -> Optional[LDAPEntry]:
            """Helper function to search for a user, with caching."""
            sanitized_username = username.lower().strip()

            # Return cached result if available
            if sanitized_username in self._users:
                return self._users[sanitized_username]

            # Search for the user
            results = self.search(f"(sAMAccountName={username})", *args, **kwargs)
            if len(results) != 1:
                return None

            # Cache the result
            self._users[sanitized_username] = results[0]
            return results[0]

        # Try without $ suffix first
        user = _get_user(username, *args, **kwargs)

        # Try with $ suffix (for computer accounts)
        if user is None and not username.endswith("$"):
            user = _get_user(f"{username}$", *args, **kwargs)

        # Log error if user not found and silent mode is not enabled
        if user is None and not silent:
            logging.error(f"Could not find user {username!r}")

        return user

    @property
    def domain_sid(self) -> Optional[str]:
        """
        Get the domain's security identifier (SID).

        The domain SID is the base identifier used for all domain security principals.

        Returns:
            Domain SID or None if not found
        """
        # Return cached value if available
        if self._domain_sid is not None:
            return self._domain_sid

        # Query domain object for SID
        results = self.search(
            "(objectClass=domain)",
            attributes=["objectSid"],
        )

        if len(results) != 1:
            return None

        result = results[0]
        domain_sid = result.get("objectSid")

        # Cache the result
        self._domain_sid = domain_sid
        return domain_sid

    def get_user_sids(
        self,
        username: str,
        user_sid: Optional[str] = None,
        user_dn: Optional[str] = None,
    ) -> Set[str]:
        """
        Get all SIDs associated with a user, including groups.

        This method collects all security identifiers (SIDs) that apply to a user,
        including the user's personal SID, well-known SIDs, primary group SID,
        and all group memberships (direct and nested).

        Args:
            username: Username to look up
            user_sid: Optional SID to use if user lookup fails
            user_dn: Optional DN to use if user lookup fails

        Returns:
            Set of SIDs the user belongs to
        """
        # Return cached value if available
        sanitized_username = username.lower().strip()
        if sanitized_username in self._user_sids:
            return self._user_sids[sanitized_username]

        # Get user object or create minimal one if not found
        user = self.get_user(username)
        if not user:
            user = {"objectSid": user_sid, "distinguishedName": user_dn}
            if not user_sid:
                logging.warning(
                    "User SID can't be retrieved. For more accurate results, add it manually with -sid"
                )

        # Start with basic SIDs
        sids: Set[str] = set()

        # Add user's own SID
        object_sid = user.get("objectSid")
        if object_sid:
            sids.add(object_sid)

        # Add well-known SIDs: Everyone, Authenticated Users, Users
        sids |= {"S-1-1-0", "S-1-5-11", "S-1-5-32-545"}

        # Add primary group (usually Domain Users)
        primary_group_id = user.get("primaryGroupID")
        if primary_group_id is not None and self.domain_sid:
            sids.add(f"{self.domain_sid}-{primary_group_id}")

        # Add Domain Users and Domain Computers group
        if self.domain_sid:
            logging.debug(
                "Adding 'Domain Users' and 'Domain Computers' to list of current user's SIDs"
            )
            sids.add(f"{self.domain_sid}-513")  # Domain Users
            sids.add(f"{self.domain_sid}-515")  # Domain Computers

        # Collect DNs to search for group membership
        dns = [user.get("distinguishedName")]
        for sid in sids:
            object_entry = self.lookup_sid(sid)
            if "dn" in object_entry:
                dns.append(object_entry["dn"])

        # Build LDAP query for nested group membership (LDAP_MATCHING_RULE_IN_CHAIN)
        member_of_queries = []
        for dn in dns:
            if dn:  # Skip None values
                member_of_queries.append(f"(member:1.2.840.113556.1.4.1941:={dn})")

        if member_of_queries:
            try:
                # Query for nested group membership
                groups = self.search(
                    f"(|{''.join(member_of_queries)})",
                    attributes="objectSid",
                )

                # Add all group SIDs to the set
                for group in groups:
                    sid = group.get("objectSid")
                    if sid is not None:
                        sids.add(sid)

            except Exception as e:
                logging.warning(f"Failed to get user SIDs: {e}")
                logging.warning("Try increasing -timeout parameter value")
                handle_error(True)

        # Cache the results
        self._user_sids[sanitized_username] = sids

        # Debug output of collected SIDs
        logging.debug(f"User {username!r} has {len(sids)} SIDs:")
        for sid in sids:
            logging.debug(f"  {sid}")

        return sids

    def lookup_sid(self, sid: str) -> LDAPEntry:
        """
        Look up an object by its SID.

        This method finds an Active Directory object by its security identifier,
        or returns a synthetic entry for well-known SIDs.

        Args:
            sid: Security identifier to look up

        Returns:
            LDAPEntry for the object, or a synthetic entry for well-known SIDs

        Raises:
            Exception: If LDAP connection is not established
        """
        # Return cached value if available
        if sid in self.sid_map:
            return self.sid_map[sid]

        # Handle well-known SIDs
        if sid in WELLKNOWN_SIDS:
            if self.domain is None and not self.warned_missing_domain_sid_lookup:
                self.warned_missing_domain_sid_lookup = True
                logging.warning(
                    "Domain is not set for LDAP connection. This may cause issues when looking up SIDs"
                )

            # Create synthetic entry for well-known SID
            entry = LDAPEntry(
                **{
                    "attributes": {
                        "objectSid": f"{(self.domain or '').upper()}-{sid}",
                        "objectType": WELLKNOWN_SIDS[sid][1].capitalize(),
                        "name": f"{self.domain}\\{WELLKNOWN_SIDS[sid][0]}",
                    }
                }
            )
            self.sid_map[sid] = entry
            return entry

        # For regular SIDs, query the directory
        attributes = [
            "sAMAccountType",
            "name",
            "objectSid",
            "distinguishedName",
            "objectClass",
        ]

        if self.ldap_conn is None:
            raise Exception("LDAP connection is not established")

        # Only request msDS-GroupMSAMembership when it exists in the schema
        if (
            self.ldap_conn.server.schema
            and "msDS-GroupMSAMembership"
            in self.ldap_conn.server.schema.attribute_types
        ):
            attributes.append("msDS-GroupMSAMembership")

        # Search for object with the given SID
        results = self.search(
            f"(objectSid={sid})",
            attributes=attributes,
        )

        # Handle results
        if len(results) != 1:
            logging.warning(f"Failed to lookup object with SID {sid!r}")
            # Create synthetic entry for unknown SID
            entry = LDAPEntry(
                **{
                    "attributes": {
                        "objectSid": sid,
                        "name": sid,
                        "objectType": "Unknown",
                    }
                }
            )
        else:
            # Process found entry
            entry = results[0]
            entry.set("name", f"{self.domain}\\{entry.get('name')}")
            entry.set("objectType", get_account_type(entry))

        # Cache the result
        self.sid_map[sid] = entry
        return entry
