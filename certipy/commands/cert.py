import argparse
import sys

from certipy.lib.certificate import (
    cert_to_pem,
    create_pfx,
    der_to_cert,
    der_to_key,
    key_to_pem,
    load_pfx,
    pem_to_cert,
    pem_to_key,
)
from certipy.lib.logger import logging


def entry(options: argparse.Namespace) -> None:
    cert, key = None, None

    if not any([options.pfx, options.cert, options.key]):
        logging.error("-pfx, -cert, or -key is required")
        return

    if options.pfx:
        password = None
        if options.password:
            logging.debug(
                "Loading PFX %s with password %s" % (repr(options.pfx), password)
            )
            password = options.password.encode()
        else:
            logging.debug("Loading PFX %s without password" % repr(options.pfx))

        with open(options.pfx, "rb") as f:
            pfx = f.read()

        key, cert = load_pfx(pfx, password)

    if options.cert:
        logging.debug("Loading certificate from %s" % repr(options.cert))

        with open(options.cert, "rb") as f:
            cert = f.read()
        try:
            cert = pem_to_cert(cert)
        except Exception:
            cert = der_to_cert(cert)

    if options.key:
        logging.debug("Loading private key from %s" % repr(options.cert))

        with open(options.key, "rb") as f:
            key = f.read()
        try:
            key = pem_to_key(key)
        except Exception:
            key = der_to_key(key)

    if options.export:
        pfx = create_pfx(key, cert)
        if options.out:
            logging.info("Writing PFX to %s" % repr(options.out))

            with open(options.out, "wb") as f:
                f.write(pfx)
        else:
            sys.stdout.buffer.write(pfx)
    else:
        output = ""
        log_str = ""
        if cert and not options.nocert:
            output += cert_to_pem(cert).decode()
            log_str += "certificate"
            if key:
                log_str += " and "

        if key and not options.nokey:
            output += key_to_pem(key).decode()
            log_str += "private key"

        if len(output) == 0:
            logging.error("Output is empty")
            return

        if options.out:
            logging.info("Writing %s to %s" % (log_str, repr(options.out)))

            with open(options.out, "w") as f:
                f.write(output)
        else:
            print(output)
