"""
Automatic object SID lookup for certificate requests.

Strong certificate mapping (KB5014754) requires the target principal's SID in
certificates that name another account through the SAN. When a request sets
-upn or -dns without -sid, this module looks the SID up over LDAP using the
operator's credentials so it doesn't have to be found and passed by hand.
"""

import copy
from typing import Optional

from ldap3.utils.conv import escape_filter_chars

from certipy.lib.ldap import LDAPConnection
from certipy.lib.logger import logging
from certipy.lib.target import Target


def lookup_object_sid(
    connection: LDAPConnection,
    upn: Optional[str] = None,
    dns: Optional[str] = None,
) -> Optional[str]:
    """
    Look up the objectSid of the principal named by a UPN or DNS host name.

    The UPN is matched against userPrincipalName first and then, using the
    part before '@', against sAMAccountName. The DNS name is matched against
    the dNSHostName of computer objects. If both are given, the UPN wins.

    Args:
        connection: Connected LDAP connection
        upn: User principal name from -upn
        dns: DNS host name from -dns

    Returns:
        The object SID, or None if nothing was given or nothing matched
    """
    if upn:
        name = upn
        results = connection.search(
            f"(userPrincipalName={escape_filter_chars(upn)})",
            attributes=["objectSid"],
        )
        if len(results) == 1:
            entry = results[0]
        else:
            sam_account_name = escape_filter_chars(upn.split("@")[0])
            entry = connection.get_user(sam_account_name, silent=True)
    elif dns:
        name = dns
        results = connection.search(
            f"(&(objectClass=computer)(dNSHostName={escape_filter_chars(dns)}))",
            attributes=["objectSid"],
        )
        entry = results[0] if len(results) == 1 else None
    else:
        return None

    sid = entry.get("objectSid") if entry is not None else None
    if not sid:
        logging.warning(f"Could not find an object SID for {name!r}")
        return None

    logging.info(f"Found object SID {sid!r} for {name!r}")
    return sid


def dc_target(target: Target) -> Target:
    """
    Copy a target and point the copy at the domain controller.

    Args:
        target: Target carrying the operator's credentials

    Returns:
        A copy of the target whose remote name and IP are the DC's
    """
    dc = copy.copy(target)
    dc.remote_name = target.dc_host or target.domain
    dc.target_ip = target.dc_ip or target.resolve_hostname(dc.remote_name)
    return dc


def resolve_alt_sid(
    target: Optional[Target],
    upn: Optional[str],
    dns: Optional[str],
    sid: Optional[str],
) -> Optional[str]:
    """
    Decide the SID to put in a certificate request.

    An explicit -sid is returned as is. Otherwise, when -upn or -dns names
    another principal and credentials are available, the SID is looked up
    over LDAP. Lookup failures are logged and the request goes ahead without
    a SID.

    Args:
        target: Target carrying the operator's credentials, if any
        upn: User principal name from -upn
        dns: DNS host name from -dns
        sid: Explicit SID from -sid

    Returns:
        The SID to request, or None
    """
    if sid:
        return sid
    if not upn and not dns:
        return None
    if target is None or not (target.username or target.do_kerberos):
        return None

    logging.info(f"Looking up object SID for {upn or dns!r} over LDAP")
    try:
        connection = LDAPConnection(dc_target(target))
        connection.connect()
        return lookup_object_sid(connection, upn=upn, dns=dns)
    except Exception as e:
        logging.warning(
            f"Object SID lookup failed: {e}. Continuing without a SID "
            "(use -sid to set it manually)"
        )
        return None
