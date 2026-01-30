import logging
import socket
from typing import TYPE_CHECKING

import impacket.examples.logger
import impacket.ntlm
import impacket.spnego
import impacket.structure
from Cryptodome.Cipher import ARC4
from impacket.hresult_errors import ERROR_MESSAGES

from .encoder.records.utils import Net7BitInteger

# Type hints for Certipy types (avoid circular imports)
if TYPE_CHECKING:
    from certipy.lib.target import Target


def hexdump(data, length=16):
    def to_ascii(byte):
        if 32 <= byte <= 126:
            return chr(byte)
        else:
            return "."

    def format_line(offset, line_bytes):
        hex_part = " ".join(f"{byte:02X}" for byte in line_bytes)
        ascii_part = "".join(to_ascii(byte) for byte in line_bytes)
        return f"{offset:08X}  {hex_part:<{length*3}}  {ascii_part}"

    lines = []
    for i in range(0, len(data), length):
        line_bytes = data[i : i + length]
        lines.append(format_line(i, line_bytes))

    return "\n".join(lines)


class NNS_pkt(impacket.structure.Structure):
    structure: tuple[tuple[str, str], ...]

    def send(self, sock: socket.socket):
        sock.sendall(self.getData())


class NNS_handshake(NNS_pkt):
    structure = (
        ("message_id", ">B"),
        ("major_version", ">B"),
        ("minor_version", ">B"),
        ("payload_len", ">H-payload"),
        ("payload", ":"),
    )

    # During negotitiate, payload will be the GSSAPI, containing SPNEGO
    # w/ NTLMSSP for NTLM or
    # w/ krb5_blob for the AP REQ)

    # For NTLM
    # NNS Headers
    # |_ Payload ( GSS-API )
    #   |_ SPNEGO ( NegTokenInit )
    #     |_ NTLMSSP

    # For Kerberos
    # NNS Headers
    # |_ Payload ( GSS-API )
    #   |_ SPNEGO ( NegTokenInit )
    #     |_ krb5_blob
    #       |_ Kerberos ( AP REQ )

    ###

    # During challenge, payload will be the GSSAPI, containing SPNEGO
    # w/ NTLMSSP for NTLM or
    # w/ krb5_blob for the AP REQ)

    # For NTLM
    # NNS Headers
    # |_ Payload ( GSS-API, SPNEGO, no GSS-API headers )
    #     |_ NegTokenTarg ( NegTokenResp )
    #       |_ NTLMSSP

    def __init__(
        self, message_id: int, major_version: int, minor_version: int, payload: bytes
    ):
        impacket.structure.Structure.__init__(self)
        self["message_id"] = message_id
        self["major_version"] = major_version
        self["minor_version"] = minor_version
        self["payload"] = payload


class NNS_data(NNS_pkt):
    # NNS data message, used after auth is completed

    structure = (
        ("payload_size", "<L-payload"),
        ("payload", ":"),
    )


class NNS_Signed_payload(impacket.structure.Structure):
    structure = (
        ("signature", ":"),
        ("cipherText", ":"),
    )


class MessageID:
    IN_PROGRESS: int = 0x16
    ERROR: int = 0x15
    DONE: int = 0x14


class NNS:
    """[MS-NNS]: .NET NegotiateStream Protocol

    The .NET NegotiateStream Protocol provides mutually authenticated
    and confidential communication over a TCP connection.

    It defines a framing mechanism used to transfer (GSS-API) security tokens
    between a client and server. It also defines a framing mechanism used
    to transfer signed and/or encrypted application data once the GSS-API
    security context initialization has completed.
    """

    def __init__(
        self,
        socket: socket.socket,
        fqdn: str,
        domain: str,
        username: str,
        password: str | None = None,
        nt: str = "",
        lm: str = "",
        kerberos_target: "Target | None" = None,
    ):
        self._sock = socket

        self._nt = self._fix_hashes(nt)
        self._lm = self._fix_hashes(lm)

        self._username = username
        self._password = password

        self._domain = domain
        self._fqdn = fqdn

        self._session_key: bytes = b""
        self._flags: int = -1
        self._sequence: int = 0

        # Kerberos support
        self._kerberos_target = kerberos_target
        self._kerberos_cipher = None
        self._use_kerberos: bool = False

    def _fix_hashes(self, hash: str | bytes) -> bytes | str:
        """fixes up hash if present into bytes and
        ensures length is 32.

        If no hash is present, returns empty bytes

        Args:
            hash (str | bytes): nt or lm hash

        Returns:
            bytes: bytes version
        """

        if not hash:
            return ""

        if len(hash) % 2:
            hash = hash.zfill(32)

        return bytes.fromhex(hash) if isinstance(hash, str) else hash

    def seal(self, data: bytes) -> tuple[bytes, bytes]:
        """seals data with the current context

        Args:
            data (bytes): bytes to seal

        Returns:
            tuple[bytes, bytes]: output_data, signature
        """

        # Use Kerberos encryption if available
        if self._use_kerberos and self._kerberos_cipher is not None:
            output, sig = self._kerberos_cipher.encrypt(data, self._sequence)
            return output, sig

        # Fall back to NTLM encryption
        server = bool(
            self._flags & impacket.ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        )

        output, sig = impacket.ntlm.SEAL(
            self._flags,
            self._server_signing_key if server else self._client_signing_key,
            self._server_sealing_key if server else self._client_sealing_key,
            data,
            data,
            self._sequence,
            self._server_sealing_handle if server else self._client_sealing_handle,
        )

        return output, sig.getData()

    def recv(self, _: int = 0) -> bytes:
        """Recive an NNS packet and return the entire
        decrypted contents.

        The paramiter is used to allow interoperability with socket.socket.recv.
        Does not respect any passed buffer sizes.

        Args:
            _ (int, optional): For interoperability with socket.socket. Defaults to 0.

        Returns:
            bytes: unsealed nns message
        """
        first_pkt = self._recv()

        # if it isnt an envelope, throw it back
        if first_pkt[0] != 0x06:
            return first_pkt

        nmfsize, nmflenlen = Net7BitInteger.decode7bit(first_pkt[1:])

        # its all just one packet
        if nmfsize < 0xFC30:
            return first_pkt

        # otherwise, we have a multi part message
        pkt = first_pkt
        nmfsize -= len(first_pkt[nmflenlen:])

        while nmfsize > 0:
            thisFragment = self._recv()

            pkt += thisFragment
            nmfsize -= len(thisFragment)

        return pkt

    def _recv(self, _: int = 0) -> bytes:
        """Recive an NNS packet and return the entire
        decrypted contents.

        The paramiter is used to allow interoperability with socket.socket.recv.
        Does not respect any passed buffer sizes.
        """
        nns_data = NNS_data()
        size = int.from_bytes(self._sock.recv(4), "little")

        payload = b""
        while len(payload) != size:
            payload += self._sock.recv(size - len(payload))
        nns_data["payload"] = payload

        # Use Kerberos decryption if available
        if self._use_kerberos and self._kerberos_cipher is not None:
            # For Kerberos, the payload format may be different
            clearText = self._kerberos_cipher.decrypt(nns_data["payload"])
            return clearText

        # Fall back to NTLM decryption
        nns_signed_payload = NNS_Signed_payload()
        nns_signed_payload["signature"] = nns_data["payload"][0:16]
        nns_signed_payload["cipherText"] = nns_data["payload"][16:]

        clearText, sig = self.seal(nns_signed_payload["cipherText"])
        return clearText

    def sendall(self, data: bytes):
        """send to server in sealed NNS data packet via tcp socket.

        Supports both NTLM and Kerberos encryption based on authentication method.

        Args:
            data (bytes): utf-16le encoded payload data
        """
        # Use Kerberos encryption if available
        if self._use_kerberos and self._kerberos_cipher is not None:
            cipherText, sig = self._kerberos_cipher.encrypt(data, self._sequence)
        else:
            # Fall back to NTLM encryption
            cipherText, sig = impacket.ntlm.SEAL(
                self._flags,
                self._client_signing_key,
                self._client_sealing_key,
                data,
                data,
                self._sequence,
                self._client_sealing_handle,
            )

        # build the NNS data packet to use
        pkt = NNS_data()

        # then we build the payload, which is the signature prepended
        # on the actual ciphertext.  This goes in the payload of
        # the NNS data packet
        payload = NNS_Signed_payload()
        payload["signature"] = sig
        payload["cipherText"] = cipherText
        pkt["payload"] = payload.getData()

        self._sock.sendall(pkt.getData())

        # and we increment the sequence number after sending
        self._sequence += 1

    def auth_ntlm(self) -> None:
        """Authenticate to the dest with NTLMV2 authentication"""

        # Initial negotiation sent from client
        NegTokenInit: impacket.spnego.SPNEGO_NegTokenInit
        NtlmSSP_nego: impacket.ntlm.NTLMAuthNegotiate

        # Generate a NTLMSSP
        NtlmSSP_nego = impacket.ntlm.getNTLMSSPType1(
            workstation="",  # These fields don't get populated for some reason
            domain="",  # These fields don't get populated for some reason
            signingRequired=True,  # TODO: Somehow determine this; can we send a Negotiate Protocol Request and derive this dynamically?
            use_ntlmv2=True,  # TODO: See above comment
        )

        # Generate the NegTokenInit
        # Impacket has this inherit from GSSAPI, so we will also have the OID and other headers :D
        NegTokenInit = impacket.spnego.SPNEGO_NegTokenInit()
        NegTokenInit["MechTypes"] = [
            impacket.spnego.TypesMech[
                "NTLMSSP - Microsoft NTLM Security Support Provider"
            ],
            impacket.spnego.TypesMech["MS KRB5 - Microsoft Kerberos 5"],
            impacket.spnego.TypesMech["KRB5 - Kerberos 5"],
            impacket.spnego.TypesMech[
                "NEGOEX - SPNEGO Extended Negotiation Security Mechanism"
            ],
        ]
        NegTokenInit["MechToken"] = NtlmSSP_nego.getData()

        # Fit it all into an NNS NTLMSSP_NEGOTIATE Message
        # Begin authentication ( NTLMSSP_NEGOTIATE )
        NNS_handshake(
            message_id=MessageID.IN_PROGRESS,
            major_version=1,
            minor_version=0,
            payload=NegTokenInit.getData(),
        ).send(self._sock)

        # Response with challenge from server
        NNS_msg_chall: NNS_handshake
        s_NegTokenTarg: impacket.spnego.SPNEGO_NegTokenResp
        NTLMSSP_chall: impacket.ntlm.NTLMAuthChallenge

        # Receive the NNS NTLMSSP_Challenge
        NNS_msg_chall = NNS_handshake(
            message_id=int.from_bytes(self._sock.recv(1), "big"),
            major_version=int.from_bytes(self._sock.recv(1), "big"),
            minor_version=int.from_bytes(self._sock.recv(1), "big"),
            payload=self._sock.recv(int.from_bytes(self._sock.recv(2), "big")),
        )

        # Extract the NegTokenResp ( NegTokenTarg )
        # Note: Potentially consider SupportedMech from s_NegTokenTarg for determining stuff like signing?
        s_NegTokenTarg = impacket.spnego.SPNEGO_NegTokenResp(NNS_msg_chall["payload"])

        # Create an NtlmAuthChallenge from the NTLMSSP ( ResponseToken )
        NTLMSSP_chall = impacket.ntlm.NTLMAuthChallenge(s_NegTokenTarg["ResponseToken"])

        # TODO: see if this is relevant https://github.com/fortra/impacket/blob/15eff8805116007cfb59332a64194a5b9c8bcf25/impacket/smb3.py#L1015
        # if NTLMSSP_chall[ 'TargetInfoFields_len' ] > 0:
        #     av_pairs   = impacket.ntlm.AV_PAIRS( NTLMSSP_chall[ 'TargetInfoFields' ][ :NTLMSSP_chall[ 'TargetInfoFields_len' ] ] )
        #     if av_pairs[ impacket.ntlm.NTLMSSP_AV_HOSTNAME ] is not None:
        #         print( "TODO AV PAIRS IDK IF ITS RELEVANT" )

        # Response with authentication from client
        c_NegTokenTarg: impacket.spnego.SPNEGO_NegTokenResp
        NTLMSSP_chall_resp: impacket.ntlm.NTLMAuthChallengeResponse

        # Create the NTLMSSP challenge response
        # If password is used, then the lm and nt hashes must be pass
        # an empty str, NOT, empty byte str.......
        NTLMSSP_chall_resp, self._session_key = impacket.ntlm.getNTLMSSPType3(
            type1=NtlmSSP_nego,
            type2=NTLMSSP_chall.getData(),
            user=self._username,
            password=self._password,
            domain=self._domain,
            lmhash=self._lm,
            nthash=self._nt,
        )

        # set up info for crypto
        self._flags = NTLMSSP_chall_resp["flags"]
        self._sequence = 0

        if self._flags & impacket.ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
            logging.debug("We are doing extended ntlm security")
            self._client_signing_key = impacket.ntlm.SIGNKEY(
                self._flags, self._session_key
            )
            self._server_signing_key = impacket.ntlm.SIGNKEY(
                self._flags, self._session_key, "Server"
            )
            self._client_sealing_key = impacket.ntlm.SEALKEY(
                self._flags, self._session_key
            )
            self._server_sealing_key = impacket.ntlm.SEALKEY(
                self._flags, self._session_key, "Server"
            )

            # prepare keys to handle states
            cipher1 = ARC4.new(self._client_sealing_key)
            self._client_sealing_handle = cipher1.encrypt
            cipher2 = ARC4.new(self._server_sealing_key)
            self._server_sealing_handle = cipher2.encrypt

        else:
            logging.debug("We are doing basic ntlm auth")
            # same key for both ways
            self._client_signing_key = self._session_key
            self._server_signing_key = self._session_key
            self._client_sealing_key = self._session_key
            self._server_sealing_key = self._session_key
            cipher = ARC4.new(self._client_sealing_key)
            self._client_sealing_handle = cipher.encrypt
            self._server_sealing_handle = cipher.encrypt

        # Fit the challenge response into the ResponseToken of our NegTokenTarg
        c_NegTokenTarg = impacket.spnego.SPNEGO_NegTokenResp()
        c_NegTokenTarg["ResponseToken"] = NTLMSSP_chall_resp.getData()

        # Fit our challenge response into an NNS message
        # Send the NTLMSSP_AUTH ( challenge response )
        NNS_handshake(
            message_id=MessageID.IN_PROGRESS,
            major_version=1,
            minor_version=0,
            payload=c_NegTokenTarg.getData(),
        ).send(self._sock)

        # Response from server ending handshake
        NNS_msg_done: NNS_handshake

        # Check for success
        NNS_msg_done = NNS_handshake(
            message_id=int.from_bytes(self._sock.recv(1), "big"),
            major_version=int.from_bytes(self._sock.recv(1), "big"),
            minor_version=int.from_bytes(self._sock.recv(1), "big"),
            payload=self._sock.recv(int.from_bytes(self._sock.recv(2), "big")),
        )

        # check for errors
        if NNS_msg_done["message_id"] == 0x15:
            err_type, err_msg = ERROR_MESSAGES[
                int.from_bytes(NNS_msg_done["payload"], "big")
            ]
            raise SystemExit(f"[-] NTLM Auth Failed with error {err_type} {err_msg}")

    def auth_kerberos(self) -> None:
        """Authenticate using Kerberos via SPNEGO.

        Uses Certipy's existing Kerberos implementation to get a Kerberos
        AP_REQ blob and authenticate over the NNS protocol.
        """
        if self._kerberos_target is None:
            raise ValueError("Kerberos target not set - cannot perform Kerberos auth")

        from certipy.lib.kerberos import get_kerberos_type1, KerberosCipher

        # Get Kerberos AP_REQ blob using Certipy's existing function
        # Use ldap SPN for ADWS service - must use hostname, not IP for Kerberos
        # Pass service="ldap" separately since get_kerberos_type1 constructs SPN as {service}/{target_name}
        # Note: get_kerberos_type1 returns a complete SPNEGO NegTokenInit token, not raw AP_REQ
        kerberos_hostname = self._kerberos_target.remote_name or self._kerberos_target.dc_host or self._fqdn
        cipher, session_key, spnego_token, username = get_kerberos_type1(
            self._kerberos_target,
            target_name=kerberos_hostname,
            service="ldap",
            channel_binding_data=None,
            signing=True,
        )

        # Send NNS handshake with SPNEGO token
        # The spnego_token from get_kerberos_type1 is already a complete SPNEGO NegTokenInit
        NNS_handshake(
            message_id=MessageID.IN_PROGRESS,
            major_version=1,
            minor_version=0,
            payload=spnego_token,
        ).send(self._sock)

        # Receive response
        NNS_msg_done = NNS_handshake(
            message_id=int.from_bytes(self._sock.recv(1), "big"),
            major_version=int.from_bytes(self._sock.recv(1), "big"),
            minor_version=int.from_bytes(self._sock.recv(1), "big"),
            payload=self._sock.recv(int.from_bytes(self._sock.recv(2), "big")),
        )

        # Check for errors
        if NNS_msg_done["message_id"] == MessageID.ERROR:
            # Try to extract error details from payload
            try:
                err_code = int.from_bytes(NNS_msg_done["payload"], "big")
                if err_code in ERROR_MESSAGES:
                    err_type, err_msg = ERROR_MESSAGES[err_code]
                    raise SystemExit(f"[-] Kerberos Auth Failed with error {err_type}: {err_msg}")
                else:
                    raise SystemExit(f"[-] Kerberos Auth Failed with error code: 0x{err_code:08X}")
            except (ValueError, KeyError):
                raise SystemExit(f"[-] Kerberos Auth Failed")

        # Set up Kerberos cipher for encryption
        self._kerberos_cipher = KerberosCipher(cipher, session_key)
        self._use_kerberos = True
        self._sequence = 0

        logging.debug("Kerberos authentication successful")
