"""
RPC (Remote Procedure Call) utilities for Certipy.

This module provides functions for establishing RPC connections to remote services,
including DCOM, named pipes, and dynamic endpoints. It supports various authentication
methods including Kerberos and NTLM.
"""

from typing import Optional

from impacket import uuid
from impacket.dcerpc.v5 import epm, rpcrt, transport
from impacket.dcerpc.v5.dcomrt import DCOMConnection

from certipy.lib.errors import handle_error
from certipy.lib.kerberos import get_tgs
from certipy.lib.logger import is_verbose, logging
from certipy.lib.target import Target


def get_dcom_connection(target: Target) -> DCOMConnection:
    """
    Establish a DCOM connection to the target.

    Args:
        target: Target object containing connection parameters

    Returns:
        DCOMConnection object for the target

    Notes:
        Uses Kerberos authentication if target.do_kerberos is True
    """
    tgs = None
    username = target.username
    domain = target.domain

    logging.debug(f"Trying to get DCOM connection for: {target.target_ip!r}")

    # Get Kerberos ticket if needed
    if target.do_kerberos:
        if not target.remote_name:
            logging.warning("Target remote name is not set.")

        kdc_rep, cipher, session_key, username, domain = get_tgs(
            target,
            target_name=target.remote_name,
        )
        tgs = {"KDC_REP": kdc_rep, "cipher": cipher, "sessionKey": session_key}

    # Create DCOM connection
    dcom = DCOMConnection(
        target.target_ip,
        username=username,
        password=target.password or "",
        domain=domain,
        lmhash=target.lmhash,
        nthash=target.nthash,
        TGS=tgs,
        doKerberos=target.do_kerberos,
        kdcHost=target.dc_ip,
    )

    return dcom


def get_dce_rpc_from_string_binding(
    string_binding: str,
    target: Target,
    timeout: int = 5,
    target_ip: Optional[str] = None,
    remote_name: Optional[str] = None,
    auth_level: int = rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
) -> rpcrt.DCERPC_v5:
    """
    Create a DCE RPC connection from a string binding.

    Args:
        string_binding: The RPC string binding (e.g., "ncacn_np:server[pipe]")
        target: Target object containing authentication parameters
        timeout: Connection timeout in seconds
        target_ip: Override target IP address (uses target.target_ip if None)
        remote_name: Override remote name (uses target.remote_name if None)
        auth_level: Authentication level for the connection

    Returns:
        Configured DCERPC_v5 object (not connected)

    Notes:
        The returned object needs to be connected with dce.connect()
    """
    if target_ip is None:
        target_ip = target.target_ip or ""
    if remote_name is None:
        remote_name = target.remote_name

    # Create RPC transport
    rpctransport = transport.DCERPCTransportFactory(string_binding)
    rpctransport.setRemoteHost(target_ip)
    rpctransport.setRemoteName(remote_name)
    rpctransport.set_connect_timeout(timeout)
    rpctransport.set_kerberos(target.do_kerberos, kdcHost=target.dc_ip)

    username = target.username
    domain = target.domain
    tgs = None

    # Get Kerberos ticket if needed
    if target.do_kerberos:
        if not remote_name:
            logging.warning("Target remote name is not set.")

        kdc_rep, cipher, session_key, username, domain = get_tgs(
            target,
            target_name=remote_name,
        )
        tgs = {"KDC_REP": kdc_rep, "cipher": cipher, "sessionKey": session_key}

    # Set credentials on the transport
    rpctransport.set_credentials(
        username,
        target.password,
        domain,
        target.lmhash,
        target.nthash,
        TGS=tgs,
    )

    # Get DCE RPC object and configure it
    dce = rpctransport.get_dce_rpc()
    dce.set_auth_level(auth_level)

    if target.do_kerberos:
        dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)

    return dce


def get_dynamic_endpoint(
    interface: bytes, target: str, timeout: int = 5
) -> Optional[str]:
    """
    Resolve a dynamic endpoint for an RPC interface.

    Args:
        interface: RPC interface identifier (UUID)
        target: Target hostname or IP address
        timeout: Connection timeout in seconds

    Returns:
        Resolved endpoint string or None if resolution fails

    Notes:
        Uses the endpoint mapper (port 135) to resolve the dynamic endpoint
    """
    string_binding = f"ncacn_ip_tcp:{target}[135]"
    rpctransport = transport.DCERPCTransportFactory(string_binding)
    rpctransport.set_connect_timeout(timeout)
    dce = rpctransport.get_dce_rpc()

    interface_str = uuid.bin_to_string(interface)
    logging.debug(f"Trying to resolve dynamic endpoint {interface_str}")

    # Connect to endpoint mapper
    try:
        dce.connect()
    except Exception as e:
        logging.warning(f"Failed to connect to endpoint mapper: {e}")
        handle_error(True)
        return None

    # Try to resolve endpoint
    try:
        endpoint = epm.hept_map(target, interface, protocol="ncacn_ip_tcp", dce=dce)
        logging.debug(f"Resolved dynamic endpoint {interface_str} to {endpoint}")
        return endpoint
    except Exception as e:
        logging.warning(f"Failed to resolve dynamic endpoint {interface_str}: {e}")
        handle_error(True)
        return None


def get_dce_rpc(
    interface: bytes,
    named_pipe: str,
    target: Target,
    timeout: int = 5,
    dynamic: bool = False,
    auth_level_np: int = rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
    auth_level_dyn: int = rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
) -> Optional[rpcrt.DCERPC_v5]:
    """
    Get a connected DCE RPC interface.

    This function attempts to connect to an RPC interface using either named pipes
    or dynamic endpoints. It will try multiple methods if the first fails.

    Args:
        interface: RPC interface identifier (UUID)
        named_pipe: Named pipe path to connect to
        target: Target object containing connection parameters
        timeout: Connection timeout in seconds
        dynamic: If True, try dynamic endpoint first, otherwise try named pipe first
        auth_level_np: Authentication level for named pipe connections
        auth_level_dyn: Authentication level for dynamic endpoint connections

    Returns:
        Connected DCERPC_v5 object or None if all connection attempts fail
    """

    def _try_binding(string_binding: str, auth_level: int) -> Optional[rpcrt.DCERPC_v5]:
        """Try to connect to a specific string binding."""
        dce = get_dce_rpc_from_string_binding(
            string_binding, target, timeout, auth_level=auth_level
        )

        logging.debug(f"Trying to connect to endpoint: {string_binding}")
        try:
            dce.connect()
        except Exception as e:
            if is_verbose():
                logging.warning(f"Failed to connect to endpoint {string_binding}: {e}")
                handle_error(True)
            return None

        logging.debug(f"Connected to endpoint: {string_binding}")

        # Bind to the interface
        try:
            _ = dce.bind(interface)
            return dce
        except Exception as e:
            if is_verbose():
                logging.warning(f"Failed to bind to interface: {e}")
                handle_error(True)
            return None

    def _try_np() -> Optional[rpcrt.DCERPC_v5]:
        """Try named pipe connection."""
        if not target.target_ip:
            logging.error("Target IP is not set")
            return None

        string_binding = f"ncacn_np:{target.target_ip}[{named_pipe}]"
        return _try_binding(string_binding, auth_level=auth_level_np)

    def _try_dyn() -> Optional[rpcrt.DCERPC_v5]:
        """Try dynamic endpoint connection."""
        if not target.target_ip:
            logging.error("Target IP is not set")
            return None

        string_binding = get_dynamic_endpoint(interface, target.target_ip, timeout)
        if string_binding is None:
            # Possible errors:
            # - TCP Port 135 is firewalled off
            # - Service is not running
            logging.error(
                f"Failed to get dynamic TCP endpoint for {uuid.bin_to_string(interface)}"
            )
            return None

        return _try_binding(string_binding, auth_level=auth_level_dyn)

    # Determine which method to try first
    methods = [_try_dyn, _try_np] if dynamic else [_try_np, _try_dyn]

    # Try connection methods in order
    for method in methods:
        dce = method()
        if dce is not None:
            return dce

    return None
