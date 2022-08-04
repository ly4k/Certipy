NAME = "ptt"

import argparse
import base64
import platform

from impacket.krb5 import constants
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.types import Principal

from certipy.lib.logger import logging
from certipy.lib.target import Target


def load_ticket(ticket: bytes, decode: bool = False) -> CCache:
    if decode:
        try:
            logging.debug("Trying to base64-decode ticket")
            if type(ticket) == bytes:
                ticket = ticket.decode()
            ticket = base64.b64decode(ticket)
        except:
            return None

    try:
        logging.debug("Trying to load ticket as CCache")
        ccache = CCache(ticket)
        logging.debug("Loaded ticket as CCache")
    except:
        logging.debug("Failed to load ticket as CCache")
        logging.debug("Trying to load ticket as Kirbi")
        ccache = CCache()

        try:
            ccache.fromKRBCRED(ticket)
            logging.debug("Loaded ticket as Kirbi")
        except:
            return None

    return ccache


def entry(options: argparse.Namespace):

    if options.ticket and options.ticket_file:
        logging.warning("Both -ticket and -ticket-file specified. Using -ticket")

    ticket = None
    if options.ticket:
        ticket = options.ticket
    elif options.ticket_file:
        with open(options.ticket_file, "rb") as f:
            ticket = f.read()

    if not ticket and not options.req:
        logging.error("Not ticket specified and -req was not specified")
        return

    ccache = None
    if ticket:
        ccache = load_ticket(ticket, True)
        if ccache is None:
            ccache = load_ticket(ticket)
        if ccache is None:
            logging.error("Failed to load ticket")
            return None
    elif options.req:
        target = Target.from_options(options, ptt=True)

        username = Principal(
            target.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )
        tgt, _, oldSessionKey, _ = getKerberosTGT(
            username,
            target.password,
            target.domain,
            bytes.fromhex(target.lmhash),
            bytes.fromhex(target.nthash),
            target.aes,
            target.dc_ip,
        )

        ccache = CCache()
        ccache.fromTGT(tgt, oldSessionKey, oldSessionKey)

    if not ccache:
        logging.error("Failed to get ticket")
        return

    logging.info("Got ticket")
    if options.debug:
        logging.debug("Ticket:")
        ccache.credentials[0].prettyPrint()

    krb_cred = ccache.toKRBCRED()
    logging.info("Trying to inject ticket into session")

    if platform.system().lower() != "windows":
        logging.error("Not running on Windows platform. Aborting")
        return

    try:
        from certipy.lib import sspi

        res = sspi.submit_ticket(krb_cred)
        if res:
            logging.info("Successfully injected ticket into session")
    except Exception as e:
        logging.error("Failed to inject ticket into session: %s" % str(e))
