from impacket import uuid
from impacket.dcerpc.v5 import epm, rpcrt, transport
from impacket.dcerpc.v5.dcomrt import DCOMConnection

from certipy.lib.kerberos import get_TGS
from certipy.lib.logger import logging
from certipy.lib.target import Target


def get_dcom_connection(target: Target) -> DCOMConnection:
    TGS = None

    logging.debug("Trying to get DCOM connection for: %s" % target.target_ip)
    username = target.username
    domain = target.domain

    if target.do_kerberos:
        tgs, cipher, session_key, username, domain = get_TGS(
            target,
            target_name=target.remote_name,
        )
        TGS = {"KDC_REP": tgs, "cipher": cipher, "sessionKey": session_key}

    dcom = DCOMConnection(
        target.target_ip,
        username=username,
        password=target.password,
        domain=domain,
        lmhash=target.lmhash,
        nthash=target.nthash,
        TGS=TGS,
        doKerberos=target.do_kerberos,
        kdcHost=target.dc_ip,
    )

    return dcom


def get_dce_rpc_from_string_binding(
    string_binding: str,
    target: Target,
    timeout: int = 5,
    target_ip: str = None,
    remote_name: str = None,
    auth_level: int = rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
) -> rpcrt.DCERPC_v5:
    if target_ip is None:
        target_ip = target.target_ip
    if remote_name is None:
        remote_name = target.remote_name

    rpctransport = transport.DCERPCTransportFactory(string_binding)

    rpctransport.setRemoteHost(target_ip)
    rpctransport.setRemoteName(remote_name)

    rpctransport.set_connect_timeout(timeout)
    rpctransport.set_kerberos(target.do_kerberos, kdcHost=target.dc_ip)

    username = target.username
    domain = target.domain

    TGS = None
    if target.do_kerberos:
        tgs, cipher, session_key, username, domain = get_TGS(
            target,
            target_name=remote_name,
        )
        TGS = {"KDC_REP": tgs, "cipher": cipher, "sessionKey": session_key}

    rpctransport.set_credentials(
        username,
        target.password,
        domain,
        target.lmhash,
        target.nthash,
        TGS=TGS,
    )

    dce = rpctransport.get_dce_rpc()
    dce.set_auth_level(auth_level)

    if target.do_kerberos is True:
        dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)

    return dce


def get_dynamic_endpoint(interface: bytes, target: str, timeout: int = 5) -> str:
    string_binding = r"ncacn_ip_tcp:%s[135]" % target
    rpctransport = transport.DCERPCTransportFactory(string_binding)
    rpctransport.set_connect_timeout(timeout)
    dce = rpctransport.get_dce_rpc()
    logging.debug(
        "Trying to resolve dynamic endpoint %s" % repr(uuid.bin_to_string(interface))
    )
    try:
        dce.connect()
    except Exception as e:
        logging.warning("Failed to connect to endpoint mapper: %s" % e)
        return None
    try:
        endpoint = epm.hept_map(target, interface, protocol="ncacn_ip_tcp", dce=dce)
        logging.debug(
            "Resolved dynamic endpoint %s to %s"
            % (repr(uuid.bin_to_string(interface)), repr(endpoint))
        )
        return endpoint
    except Exception:
        logging.debug(
            "Failed to resolve dynamic endpoint %s"
            % repr(uuid.bin_to_string(interface))
        )
        return None


def get_dce_rpc(
    interface: bytes,
    named_pipe: str,
    target: Target,
    timeout=5,
    dynamic=False,
    verbose=False,
    auth_level_np: int = rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
    auth_level_dyn: int = rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
) -> rpcrt.DCERPC_v5:
    def _try_binding(string_binding: str, auth_level: int) -> rpcrt.DCERPC_v5:
        dce = get_dce_rpc_from_string_binding(
            string_binding, target, timeout, auth_level=auth_level
        )

        logging.debug("Trying to connect to endpoint: %s" % string_binding)
        try:
            dce.connect()
        except Exception as e:
            if verbose:
                logging.warning(
                    "Failed to connect to endpoint %s: %s" % (string_binding, e)
                )
            return None

        logging.debug("Connected to endpoint: %s" % string_binding)

        dce.bind(interface)

        return dce

    def _try_np() -> rpcrt.DCERPC_v5:
        # Try named pipe
        string_binding = "ncacn_np:%s[%s]" % (target.target_ip, named_pipe)
        return _try_binding(string_binding, auth_level=auth_level_np)

    def _try_dyn() -> rpcrt.DCERPC_v5:
        string_binding = get_dynamic_endpoint(interface, target.target_ip, timeout)
        if string_binding is None:
            # Possible errors:
            # - TCP Port 135 is firewalled off
            # - CertSvc is not running
            logging.error("Failed to get dynamic TCP endpoint for CertSvc")
            return None

        dce = _try_binding(string_binding, auth_level=auth_level_dyn)
        return dce

    if dynamic:
        methods = [_try_dyn, _try_np]
    else:
        methods = [_try_np, _try_dyn]

    for method in methods:
        dce = method()
        if dce is not None:
            return dce

    return None
