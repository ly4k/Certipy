from impacket.krb5.ccache import CCache

from .encryption import Key, _enctype_table
from .netsecapi import (
    ISC_REQ,
    SEC_E,
    SECPKG_ATTR,
    SECPKG_CRED,
    AcquireCredentialsHandle,
    InitializeSecurityContext,
    LsaCallAuthenticationPackage,
    LsaConnectUntrusted,
    LsaFreeReturnBuffer,
    LsaLookupAuthenticationPackage,
    QueryContextAttributes,
    SecPkgContext_SessionKey,
    extract_ticket,
    get_lsa_error,
    submit_tkt_helper,
)
from certipy.lib.structs import (
    AP_REQ,
    KRB_CRED,
    Authenticator,
    AuthenticatorChecksum,
    ChecksumFlags,
    EncryptedData,
    InitialContextToken,
)


def submit_ticket(ticket_data: bytes):
    lsa_handle = LsaConnectUntrusted()
    kerberos_package_id = LsaLookupAuthenticationPackage(lsa_handle, "kerberos")

    message = submit_tkt_helper(ticket_data, logonid=0)

    ret_msg, ret_status, free_ptr = LsaCallAuthenticationPackage(
        lsa_handle, kerberos_package_id, message
    )
    if ret_status != 0:
        raise get_lsa_error(ret_status)

    if len(ret_msg) > 0:
        LsaFreeReturnBuffer(free_ptr)

    return True


def get_tgt(target: str) -> CCache:
    ctx = AcquireCredentialsHandle(None, "kerberos", target, SECPKG_CRED.OUTBOUND)
    res, ctx, data, outputflags, expiry = InitializeSecurityContext(
        ctx,
        target,
        token=None,
        ctx=ctx,
        flags=ISC_REQ.DELEGATE | ISC_REQ.MUTUAL_AUTH | ISC_REQ.ALLOCATE_MEMORY,
    )

    if res == SEC_E.OK or res == SEC_E.CONTINUE_NEEDED:
        lsa_handle = LsaConnectUntrusted()

        kerberos_package_id = LsaLookupAuthenticationPackage(lsa_handle, "kerberos")

        raw_ticket = extract_ticket(lsa_handle, kerberos_package_id, 0, target)

        key = Key(raw_ticket["Key"]["KeyType"], raw_ticket["Key"]["Key"])
        token = InitialContextToken.load(data[0][1])

        ticket = AP_REQ(token.native["innerContextToken"]).native

        cipher = _enctype_table[ticket["authenticator"]["etype"]]
        dec_authenticator = cipher.decrypt(key, 11, ticket["authenticator"]["cipher"])
        authenticator = Authenticator.load(dec_authenticator).native
        if authenticator["cksum"]["cksumtype"] != 0x8003:
            raise Exception("Bad checksum")

        checksum_data = AuthenticatorChecksum.from_bytes(
            authenticator["cksum"]["checksum"]
        )
        if ChecksumFlags.GSS_C_DELEG_FLAG not in checksum_data.flags:
            raise Exception("Delegation flag not set")

        cred_orig = KRB_CRED.load(checksum_data.delegation_data).native
        dec_authenticator = cipher.decrypt(key, 14, cred_orig["enc-part"]["cipher"])

        # reconstructing kirbi with the unencrypted data
        te = {}
        te["etype"] = 0
        te["cipher"] = dec_authenticator
        ten = EncryptedData(te)

        t = {}
        t["pvno"] = cred_orig["pvno"]
        t["msg-type"] = cred_orig["msg-type"]
        t["tickets"] = cred_orig["tickets"]
        t["enc-part"] = ten

        krb_cred = KRB_CRED(t)

        ccache = CCache()
        ccache.fromKRBCRED(krb_cred.dump())

        return ccache


def get_tgs(target: str) -> CCache:
    ctx = AcquireCredentialsHandle(None, "kerberos", target, SECPKG_CRED.OUTBOUND)
    res, ctx, data, _, _ = InitializeSecurityContext(
        ctx,
        target,
        token=None,
        ctx=ctx,
        flags=ISC_REQ.ALLOCATE_MEMORY | ISC_REQ.CONNECTION,
    )
    if res == SEC_E.OK or res == SEC_E.CONTINUE_NEEDED:
        sec_struct = SecPkgContext_SessionKey()
        QueryContextAttributes(ctx, SECPKG_ATTR.SESSION_KEY, sec_struct)
        sec_struct.Buffer

        InitialContextToken.load(data[0][1]).native["innerContextToken"]

        lsa_handle = LsaConnectUntrusted()

        kerberos_package_id = LsaLookupAuthenticationPackage(lsa_handle, "kerberos")

        raw_ticket = extract_ticket(lsa_handle, kerberos_package_id, 0, target)

        krb_cred = KRB_CRED.load(raw_ticket["Ticket"])

        ccache = CCache()
        ccache.fromKRBCRED(krb_cred.dump())

        return ccache


"""

kerb = KerberosLive()
# ap_req, etype, key_value = kerb.get_apreq("ldap/dc.corp.local")
# ap_req, krb_cred, etype, key_value = kerb.get_apreq("ldap/dc.corp.local")
krb_cred = kerb.get_apreq("ldap/dc.corp.local")

ccache = CCache()
ccache.fromKRBCRED(krb_cred)
ccache.saveFile("check.ccache")

krb_cred = get_tgt("ldap/dc.corp.local")
ccache = CCache()
ccache.fromKRBCRED(krb_cred)
ccache.saveFile("check.ccache")

print(ccache.prettyPrint())

exit()
"""

# print(get_logon_info())
