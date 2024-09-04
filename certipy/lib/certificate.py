import argparse
import base64
import math
import os
import struct
import sys
from typing import List, Tuple

from asn1crypto import cms as asn1cms
from asn1crypto import core as asn1core
from asn1crypto import csr as asn1csr
from asn1crypto import x509 as asn1x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    pkcs12,
)
from cryptography.x509 import SubjectKeyIdentifier
from cryptography.x509.oid import ExtensionOID, NameOID
from impacket.dcerpc.v5.nrpc import checkNullString
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.char import UTF8String

from certipy.lib.logger import logging

DN_MAP = {
    "CN": NameOID.COMMON_NAME,
    "SN": NameOID.SURNAME,
    "SERIALNUMBER": NameOID.SERIAL_NUMBER,
    "C": NameOID.COUNTRY_NAME,
    "L": NameOID.LOCALITY_NAME,
    "S": NameOID.STATE_OR_PROVINCE_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "STREET": NameOID.STREET_ADDRESS,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "T": NameOID.TITLE,
    "TITLE": NameOID.TITLE,
    "G": NameOID.GIVEN_NAME,
    "GN": NameOID.GIVEN_NAME,
    "E": NameOID.EMAIL_ADDRESS,
    "UID": NameOID.USER_ID,
    "DC": NameOID.DOMAIN_COMPONENT,
}

asn1x509.ExtensionId._map.update(
    {
        "1.3.6.1.4.1.311.25.2": "security_ext",
    }
)

asn1x509.Extension._oid_specs.update(
    {
        "security_ext": asn1x509.GeneralNames,
    }
)

PRINCIPAL_NAME = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
NTDS_CA_SECURITY_EXT = x509.ObjectIdentifier("1.3.6.1.4.1.311.25.2")
NTDS_OBJECTSID = x509.ObjectIdentifier("1.3.6.1.4.1.311.25.2.1")

szOID_RENEWAL_CERTIFICATE = asn1cms.ObjectIdentifier("1.3.6.1.4.1.311.13.1")
szOID_ENCRYPTED_KEY_HASH = asn1cms.ObjectIdentifier("1.3.6.1.4.1.311.21.21")
szOID_PRINCIPAL_NAME = asn1cms.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
szOID_ENCRYPTED_KEY_HASH = asn1cms.ObjectIdentifier("1.3.6.1.4.1.311.21.21")
szOID_CMC_ADD_ATTRIBUTES = asn1cms.ObjectIdentifier("1.3.6.1.4.1.311.10.10.1")
szOID_NTDS_CA_SECURITY_EXT = asn1cms.ObjectIdentifier("1.3.6.1.4.1.311.25.2")
szOID_NTDS_OBJECTSID = asn1cms.ObjectIdentifier("1.3.6.1.4.1.311.25.2.1")

class TaggedCertificationRequest(asn1core.Sequence):
    _fields = [
        ("bodyPartID", asn1core.Integer),
        ("certificationRequest", asn1csr.CertificationRequest),
    ]


class TaggedRequest(asn1core.Choice):
    _alternatives = [
        ("tcr", TaggedCertificationRequest, {"implicit": 0}),
        ("crm", asn1core.Any, {"implicit": 1}),
        ("orm", asn1core.Any, {"implicit": 2}),
    ]


class TaggedAttribute(asn1core.Sequence):
    _fields = [
        ("bodyPartID", asn1core.Integer),
        ("attrType", asn1core.ObjectIdentifier),
        ("attrValues", asn1cms.SetOfAny),
    ]


class TaggedAttributes(asn1core.SequenceOf):
    _child_spec = TaggedAttribute


class TaggedRequests(asn1core.SequenceOf):
    _child_spec = TaggedRequest


class TaggedContentInfos(asn1core.SequenceOf):
    _child_spec = asn1core.Any  # not implemented


class OtherMsgs(asn1core.SequenceOf):
    _child_spec = asn1core.Any  # not implemented


class PKIData(asn1core.Sequence):
    _fields = [
        ("controlSequence", TaggedAttributes),
        ("reqSequence", TaggedRequests),
        ("cmsSequence", TaggedContentInfos),
        ("otherMsgSequence", OtherMsgs),
    ]


class CertReference(asn1core.SequenceOf):
    _child_spec = asn1core.Integer


class CMCAddAttributesInfo(asn1core.Sequence):
    _fields = [
        ("data_reference", asn1core.Integer),
        ("cert_reference", CertReference),
        ("attributes", asn1csr.SetOfAttributes),
    ]


class EnrollmentNameValuePair(asn1core.Sequence):
    _fields = [
        ("name", asn1core.BMPString),
        ("value", asn1core.BMPString),
    ]


class EnrollmentNameValuePairs(asn1core.SetOf):
    _child_spec = EnrollmentNameValuePair


def cert_id_to_parts(identifications: List[Tuple[str, str]]) -> Tuple[str, str]:
    usernames = []
    domains = []

    if len(identifications) == 0:
        return (None, None)

    for id_type, identification in identifications:
        if id_type != "DNS Host Name" and id_type != "UPN":
            continue

        if id_type == "DNS Host Name":
            parts = identification.split(".")
            if len(parts) == 1:
                cert_username = identification
                cert_domain = ""
            else:
                cert_username = parts[0] + "$"
                cert_domain = ".".join(parts[1:])
        elif id_type == "UPN":
            parts = identification.split("@")
            if len(parts) == 1:
                cert_username = identification
                cert_domain = ""
            else:
                cert_username = "@".join(parts[:-1])
                cert_domain = parts[-1]

        usernames.append(cert_username)
        domains.append(cert_domain)
    return ("_".join(usernames), "_".join(domains))


def csr_to_der(csr: x509.CertificateSigningRequest) -> bytes:
    return csr.public_bytes(Encoding.DER)


def csr_to_pem(csr: x509.CertificateSigningRequest) -> bytes:
    pem = csr.public_bytes(Encoding.PEM)
    return csr.public_bytes(Encoding.PEM)


def cert_to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(Encoding.PEM)


def cert_to_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(Encoding.DER)


def key_to_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
    )


def key_to_der(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        Encoding.DER, PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
    )


def der_to_pem(der: bytes, pem_type: str) -> bytes:
    pem_type = pem_type.upper()
    b64_data = base64.b64encode(der).decode()
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (
        pem_type,
        "\n".join([b64_data[i : i + 64] for i in range(0, len(b64_data), 64)]),
        pem_type,
    )


def der_to_csr(csr: bytes) -> x509.CertificateSigningRequest:
    return x509.load_der_x509_csr(csr)

def pem_to_csr(csr: bytes) -> x509.CertificateSigningRequest:
    return x509.load_pem_x509_csr(csr)

def der_to_key(key: bytes) -> rsa.RSAPrivateKey:
    return serialization.load_der_private_key(key, None)


def pem_to_key(key: bytes) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(key, None)


def der_to_cert(certificate: bytes) -> x509.Certificate:
    return x509.load_der_x509_certificate(certificate)


def pem_to_cert(certificate: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(certificate)


def private_key_to_ms_blob(private_key: rsa.RSAPrivateKey):
    bitlen = private_key.key_size
    private_numbers = private_key.private_numbers()
    public_numbers = private_numbers.public_numbers

    bitlen8 = math.ceil(bitlen / 8)
    bitlen16 = math.ceil(bitlen / 16)

    return struct.pack(
        "<bbHI4sII%ds%ds%ds%ds%ds%ds%ds"
        % (bitlen8, bitlen16, bitlen16, bitlen16, bitlen16, bitlen16, bitlen8),
        7,
        2,
        0,
        41984,
        b"RSA2",
        bitlen,
        public_numbers.e,
        public_numbers.n.to_bytes(bitlen8, "little"),
        private_numbers.p.to_bytes(bitlen16, "little"),
        private_numbers.q.to_bytes(bitlen16, "little"),
        private_numbers.dmp1.to_bytes(bitlen16, "little"),
        private_numbers.dmq1.to_bytes(bitlen16, "little"),
        private_numbers.iqmp.to_bytes(bitlen16, "little"),
        private_numbers.d.to_bytes(bitlen8, "little"),
    )


def get_identifications_from_certificate(
    certificate: x509.Certificate,
) -> Tuple[str, str]:
    identifications = []
    try:
        san = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )

        for name in san.value.get_values_for_type(x509.OtherName):
            if name.type_id == PRINCIPAL_NAME:
                identifications.append(
                    (
                        "UPN",
                        decoder.decode(name.value, asn1Spec=UTF8String)[0].decode(),
                    )
                )

        for name in san.value.get_values_for_type(x509.DNSName):
            identifications.append(("DNS Host Name", name))
    except:
        pass

    return identifications


def get_object_sid_from_certificate(
    certificate: x509.Certificate,
) -> str:
    try:
        object_sid = certificate.extensions.get_extension_for_oid(NTDS_CA_SECURITY_EXT)

        sid = object_sid.value.value
        return sid[sid.find(b"S-1-5") :].decode()
    except:
        pass

    return None


def create_pfx(key: rsa.RSAPrivateKey, cert: x509.Certificate) -> bytes:
    return pkcs12.serialize_key_and_certificates(
        name=b"",
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=NoEncryption(),
    )


def load_pfx(
    pfx: bytes, password: bytes = None
) -> Tuple[rsa.RSAPrivateKey, x509.Certificate, None]:
    return pkcs12.load_key_and_certificates(pfx, password)[:-1]


def generate_rsa_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=0x10001, key_size=key_size)


def create_csr(
    username: str,
    alt_dns: bytes = None,
    alt_upn: bytes = None,
    alt_sid: bytes = None,
    key: rsa.RSAPrivateKey = None,
    key_size: int = 2048,
    subject: str = None,
    renewal_cert: x509.Certificate = None,
) -> Tuple[x509.CertificateSigningRequest, rsa.RSAPrivateKey]:
    if key is None:
        logging.debug("Generating RSA key")
        key = generate_rsa_key(key_size)

    # csr = asn1csr.CertificationRequest()
    certification_request_info = asn1csr.CertificationRequestInfo()
    certification_request_info["version"] = "v1"
    # csr = x509.CertificateSigningRequestBuilder()

    if subject:
        subject_name = get_subject_from_str(subject)
    else:
        subject_name = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, username.capitalize()),
            ]
        )

    certification_request_info["subject"] = asn1csr.Name.load(
        subject_name.public_bytes()
    )

    public_key = key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )

    subject_pk_info = asn1csr.PublicKeyInfo.load(public_key)
    certification_request_info["subject_pk_info"] = subject_pk_info

    cri_attributes = []
    if alt_dns or alt_upn:
        general_names = []

        if alt_dns:
            if type(alt_dns) == bytes:
                alt_dns = alt_dns.decode()
            general_names.append(asn1x509.GeneralName({"dns_name": alt_dns}))

        if alt_upn:
            if type(alt_upn) == bytes:
                alt_upn = alt_upn.decode()

            general_names.append(
                asn1x509.GeneralName(
                    {
                        "other_name": asn1x509.AnotherName(
                            {
                                "type_id": szOID_PRINCIPAL_NAME,
                                "value": asn1x509.UTF8String(alt_upn).retag(
                                    {"explicit": 0}
                                ),
                            }
                        )
                    }
                )
            )

        san_extension = asn1x509.Extension(
            {"extn_id": "subject_alt_name", "extn_value": general_names}
        )

        set_of_extensions = asn1csr.SetOfExtensions([[san_extension]])

        cri_attribute = asn1csr.CRIAttribute(
            {"type": "extension_request", "values": set_of_extensions}
        )

        cri_attributes.append(cri_attribute)

    if alt_sid:
        if type(alt_sid) == str:
            alt_sid = alt_sid.encode()


        san_extension = asn1x509.Extension(
            {"extn_id": "security_ext", "extn_value": [asn1x509.GeneralName(
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
            )]}
        )

        set_of_extensions = asn1csr.SetOfExtensions([[san_extension]])

        cri_attribute = asn1csr.CRIAttribute(
            {"type": "extension_request", "values": set_of_extensions}
        )

        cri_attributes.append(cri_attribute)

    if renewal_cert:
        cri_attributes.append(
            asn1csr.CRIAttribute(
                {
                    "type": "1.3.6.1.4.1.311.13.1",
                    "values": asn1x509.SetOf(
                        [asn1x509.Certificate.load(cert_to_der(renewal_cert))],
                        spec=asn1x509.Certificate,
                    ),
                }
            )
        )

    certification_request_info["attributes"] = cri_attributes

    signature = rsa_pkcs1v15_sign(certification_request_info.dump(), key)

    csr = asn1csr.CertificationRequest(
        {
            "certification_request_info": certification_request_info,
            "signature_algorithm": asn1csr.SignedDigestAlgorithm(
                {"algorithm": "sha256_rsa"}
            ),
            "signature": signature,
        }
    )

    return (der_to_csr(csr.dump()), key)


def rsa_pkcs1v15_sign(
    data: bytes, key: rsa.RSAPrivateKey, hash: hashes.HashAlgorithm = hashes.SHA256
):
    return key.sign(data, padding.PKCS1v15(), hash())


def hash_digest(data: bytes, hash: hashes.Hash):
    digest = hashes.Hash(hash())
    digest.update(data)
    return digest.finalize()


def create_renewal(
    request: bytes,
    cert: x509.Certificate,
    key: rsa.RSAPrivateKey,
):
    x509_cert = asn1x509.Certificate.load(cert_to_der(cert))
    signature_hash_algorithm = cert.signature_hash_algorithm.__class__

    # SignerInfo

    issuer_and_serial = asn1cms.IssuerAndSerialNumber(
        {
            "issuer": x509_cert.issuer,
            "serial_number": x509_cert.serial_number,
        }
    )

    digest_algorithm = asn1cms.DigestAlgorithm(
        {"algorithm": signature_hash_algorithm.name}
    )

    signed_attribs = asn1cms.CMSAttributes(
        [
            asn1cms.CMSAttribute(
                {
                    "type": "1.3.6.1.4.1.311.13.1",
                    "values": asn1cms.SetOfAny(
                        [asn1x509.Certificate.load(cert_to_der(cert))],
                        spec=asn1x509.Certificate,
                    ),
                }
            ),
            asn1cms.CMSAttribute(
                {
                    "type": "message_digest",
                    "values": [hash_digest(request, signature_hash_algorithm)],
                }
            ),
        ]
    )

    attribs_signature = rsa_pkcs1v15_sign(
        signed_attribs.dump(), key, hash=signature_hash_algorithm
    )

    signer_info = asn1cms.SignerInfo(
        {
            "version": 1,
            "sid": issuer_and_serial,
            "digest_algorithm": digest_algorithm,
            "signature_algorithm": x509_cert["signature_algorithm"],
            "signature": attribs_signature,
            "signed_attrs": signed_attribs,
        }
    )

    # SignedData

    content_info = asn1cms.EncapsulatedContentInfo(
        {
            "content_type": "data",
            "content": request,
        }
    )

    signed_data = asn1cms.SignedData(
        {
            "version": 3,
            "digest_algorithms": [digest_algorithm],
            "encap_content_info": content_info,
            "certificates": [asn1cms.CertificateChoices({"certificate": x509_cert})],
            "signer_infos": [signer_info],
        }
    )

    # CMC

    cmc = asn1cms.ContentInfo(
        {
            "content_type": "signed_data",
            "content": signed_data,
        }
    )

    return cmc.dump()


def create_on_behalf_of(
    request: bytes,
    on_behalf_of: str,
    cert: x509.Certificate,
    key: rsa.RSAPrivateKey,
):
    x509_cert = asn1x509.Certificate.load(cert_to_der(cert))
    signature_hash_algorithm = cert.signature_hash_algorithm.__class__

    # SignerInfo

    issuer_and_serial = asn1cms.IssuerAndSerialNumber(
        {
            "issuer": x509_cert.issuer,
            "serial_number": x509_cert.serial_number,
        }
    )

    digest_algorithm = asn1cms.DigestAlgorithm(
        {"algorithm": signature_hash_algorithm.name}
    )

    requester_name = EnrollmentNameValuePair(
        {
            "name": checkNullString("requestername"),
            "value": checkNullString(on_behalf_of),
        }
    )

    signed_attribs = asn1cms.CMSAttributes(
        [
            asn1cms.CMSAttribute(
                {"type": "1.3.6.1.4.1.311.13.2.1", "values": [requester_name]}
            ),
            asn1cms.CMSAttribute(
                {
                    "type": "message_digest",
                    "values": [hash_digest(request, signature_hash_algorithm)],
                }
            ),
        ]
    )

    attribs_signature = rsa_pkcs1v15_sign(
        signed_attribs.dump(), key, hash=signature_hash_algorithm
    )

    signer_info = asn1cms.SignerInfo(
        {
            "version": 1,
            "sid": issuer_and_serial,
            "digest_algorithm": digest_algorithm,
            "signature_algorithm": x509_cert["signature_algorithm"],
            "signature": attribs_signature,
            "signed_attrs": signed_attribs,
        }
    )

    # SignedData

    content_info = asn1cms.EncapsulatedContentInfo(
        {
            "content_type": "data",
            "content": request,
        }
    )

    signed_data = asn1cms.SignedData(
        {
            "version": 3,
            "digest_algorithms": [digest_algorithm],
            "encap_content_info": content_info,
            "certificates": [asn1cms.CertificateChoices({"certificate": x509_cert})],
            "signer_infos": [signer_info],
        }
    )

    # CMC

    cmc = asn1cms.ContentInfo(
        {
            "content_type": "signed_data",
            "content": signed_data,
        }
    )

    return cmc.dump()


def create_key_archival(
    csr: x509.CertificateSigningRequest,
    private_key: rsa.RSAPrivateKey,
    cax_cert: x509.Certificate,
):
    x509_cax_cert = asn1x509.Certificate.load(cert_to_der(cax_cert))
    x509_csr = asn1csr.CertificationRequest.load(cert_to_der(csr))

    signature_hash_algorithm = csr.signature_hash_algorithm.__class__
    symmetric_key = os.urandom(32)
    iv = os.urandom(16)
    cax_key = cax_cert.public_key()
    encrypted_key = cax_key.encrypt(symmetric_key, padding.PKCS1v15())

    # EnvelopedData

    cax_issuer_and_serial = asn1cms.IssuerAndSerialNumber(
        {
            "issuer": x509_cax_cert.issuer,
            "serial_number": x509_cax_cert.serial_number,
        }
    )
    recipient_info = asn1cms.KeyTransRecipientInfo(
        {
            "version": 0,
            "rid": cax_issuer_and_serial,
            "key_encryption_algorithm": asn1cms.KeyEncryptionAlgorithm(
                {"algorithm": "rsaes_pkcs1v15"}
            ),
            "encrypted_key": encrypted_key,
        }
    )

    encryption_algorithm = asn1cms.EncryptionAlgorithm(
        {"algorithm": "aes256_cbc", "parameters": iv}
    )

    private_key_bytes = private_key_to_ms_blob(private_key)

    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))

    padder = PKCS7(encryption_algorithm.encryption_block_size * 8).padder()
    padded_private_key_bytes = padder.update(private_key_bytes) + padder.finalize()
    encryptor = cipher.encryptor()

    encrypted_private_key_bytes = (
        encryptor.update(padded_private_key_bytes) + encryptor.finalize()
    )

    encrypted_content_info = asn1cms.EncryptedContentInfo(
        {
            "content_type": "data",
            "content_encryption_algorithm": encryption_algorithm,
            "encrypted_content": encrypted_private_key_bytes,
        }
    )

    enveloped_data = asn1cms.EnvelopedData(
        {
            "version": 0,
            "recipient_infos": asn1cms.RecipientInfos([recipient_info]),
            "encrypted_content_info": encrypted_content_info,
        }
    )

    enveloped_data_info = asn1cms.ContentInfo(
        {
            "content_type": "1.2.840.113549.1.7.3",
            "content": enveloped_data,
        }
    )

    encrypted_key_hash = hash_digest(
        enveloped_data_info.dump(), signature_hash_algorithm
    )

    # PKIData

    attributes = asn1csr.SetOfAttributes(
        [
            asn1csr.Attribute(
                {
                    "type": szOID_ENCRYPTED_KEY_HASH,
                    "values": [asn1core.OctetString(encrypted_key_hash)],
                }
            )
        ]
    )

    attributes_info = CMCAddAttributesInfo(
        {"data_reference": 0, "cert_reference": [1], "attributes": attributes}
    )

    tagged_attribute = TaggedAttribute(
        {
            "bodyPartID": 2,
            "attrType": szOID_CMC_ADD_ATTRIBUTES,
            "attrValues": [attributes_info],
        }
    )

    tagged_request = TaggedRequest(
        {
            "tcr": TaggedCertificationRequest(
                {
                    "bodyPartID": 1,
                    "certificationRequest": asn1csr.CertificationRequest().load(
                        cert_to_der(csr)
                    ),
                }
            )
        }
    )

    pki_data = PKIData(
        {
            "controlSequence": [tagged_attribute],
            "reqSequence": [tagged_request],
            "cmsSequence": TaggedContentInfos([]),
            "otherMsgSequence": OtherMsgs([]),
        }
    )

    pki_data_bytes = pki_data.dump()

    cmc_request_hash = hash_digest(pki_data_bytes, signature_hash_algorithm)

    # SignerInfo

    digest_algorithm = asn1cms.DigestAlgorithm(
        {"algorithm": signature_hash_algorithm.name}
    )

    skid = SubjectKeyIdentifier.from_public_key(csr.public_key()).digest

    signed_attribs = asn1cms.CMSAttributes(
        [
            asn1cms.CMSAttribute(
                {"type": "content_type", "values": ["1.3.6.1.5.5.7.12.2"]}
            ),
            asn1cms.CMSAttribute(
                {
                    "type": "message_digest",
                    "values": [cmc_request_hash],
                }
            ),
        ]
    )

    attribs_signature = rsa_pkcs1v15_sign(
        signed_attribs.dump(), private_key, hash=signature_hash_algorithm
    )

    signer_info = asn1cms.SignerInfo(
        {
            "version": 3,
            "sid": asn1cms.SignerIdentifier({"subject_key_identifier": skid}),
            "digest_algorithm": digest_algorithm,
            "signature_algorithm": x509_csr["signature_algorithm"],
            "signature": attribs_signature,
            "signed_attrs": signed_attribs,
            "unsigned_attrs": asn1cms.CMSAttributes(
                [
                    asn1cms.CMSAttribute(
                        {
                            "type": "1.3.6.1.4.1.311.21.13",
                            "values": [enveloped_data_info],
                        }
                    )
                ]
            ),
        }
    )

    # SignedData

    content_info = asn1cms.EncapsulatedContentInfo(
        {
            "content_type": "1.3.6.1.5.5.7.12.2",
            "content": pki_data_bytes,
        }
    )

    signed_data = asn1cms.SignedData(
        {
            "version": 3,
            "digest_algorithms": [digest_algorithm],
            "encap_content_info": content_info,
            "signer_infos": [signer_info],
        }
    )

    # CMC

    cmc = asn1cms.ContentInfo(
        {
            "content_type": "signed_data",
            "content": signed_data,
        }
    )

    return cmc.dump()


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


def get_subject_from_str(subject) -> x509.Name:
    return x509.Name(x509.Name.from_rfc4514_string(subject).rdns[::-1])
