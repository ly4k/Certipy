import argparse
import logging
from typing import Callable, Tuple

from impacket.dcerpc.v5 import rpcrt
from impacket.dcerpc.v5.dtypes import DWORD, LPWSTR, NULL, PBYTE, ULONG
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.nrpc import checkNullString
from impacket.uuid import uuidtup_to_bin

from certipy import target
from certipy.auth import cert_id_to_parts
from certipy.certificate import (
    cert_to_pem,
    create_cms,
    create_csr,
    create_pfx,
    csr_to_der,
    der_to_cert,
    get_id_from_certificate,
    key_to_pem,
    load_pfx,
    pem_to_key,
)
from certipy.errors import translate_error_code
from certipy.rpc import get_dce_rpc
from certipy.target import Target

NAME = "req"
MSRPC_UUID_ICPR = uuidtup_to_bin(("91ae6020-9e3c-11cf-8d7c-00aa00c091be", "0.0"))


class DCERPCSessionError(rpcrt.DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        rpcrt.DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self) -> str:
        self.error_code &= 0xFFFFFFFF
        error_msg = translate_error_code(self.error_code)
        return "RequestSessionError: %s" % error_msg


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


class Request:
    def __init__(
        self,
        target: Target = None,
        ca: str = None,
        template: str = None,
        alt: str = None,
        retrieve: int = 0,
        on_behalf_of: str = None,
        pfx: str = None,
        out: str = None,
        dynamic_endpoint: bool = False,
        debug=False,
        **kwargs
    ):
        self.target = target
        self.ca = ca
        self.template = template
        self.alt_name = alt
        self.request_id = int(retrieve)
        self.on_behalf_of = on_behalf_of
        self.pfx = pfx
        self.out = out
        self.dynamic = dynamic_endpoint
        self.verbose = debug
        self.kwargs = kwargs

        self._dce = None

    @property
    def dce(self) -> rpcrt.DCERPC_v5:
        if self._dce is not None:
            return self._dce

        self._dce = get_dce_rpc(
            MSRPC_UUID_ICPR,
            r"\pipe\cert",
            self.target,
            timeout=self.target.timeout,
            dynamic=self.dynamic,
            verbose=self.verbose,
        )

        return self._dce

    def retrieve(self) -> bool:
        request_id = int(self.request_id)

        empty = CERTTRANSBLOB()
        empty["cb"] = 0
        empty["pb"] = NULL

        request = CertServerRequest()
        request["dwFlags"] = 0
        request["pwszAuthority"] = checkNullString(self.ca)
        request["pdwRequestId"] = request_id
        request["pctbAttribs"] = empty
        request["pctbRequest"] = empty

        logging.info("Rerieving certificate with ID %d" % request_id)

        response = self.dce.request(request, checkError=False)

        error_code = response["pdwDisposition"]

        if error_code == 3:
            logging.info("Successfully retrieved certificate")
        else:
            if error_code == 5:
                logging.warning("Certificate request is still pending approval")
            else:
                error_msg = translate_error_code(error_code)
                if "unknown error code" in error_msg:
                    logging.error(
                        "Got unknown error while trying to retrieve certificate: (%s): %s"
                        % (
                            error_msg,
                            b"".join(response["pctbDispositionMessage"]["pb"]).decode(
                                "utf-16le"
                            ),
                        )
                    )
                else:
                    logging.error(
                        "Got error while trying to retrieve certificate: %s" % error_msg
                    )

            return False

        cert = der_to_cert(b"".join(response["pctbEncodedCert"]["pb"]))
        id_type, identification = get_id_from_certificate(cert)
        if id_type is not None:
            logging.info("Got certificate with %s %s" % (id_type, repr(identification)))
        else:
            logging.info("Got certficate without identification")

        out = self.out
        if out is None:
            out, _ = cert_id_to_parts(id_type, identification)
            if out is None:
                out = self.target.username

            out = out.rstrip("$").lower()

        try:
            with open("%d.key" % request_id, "rb") as f:
                key = pem_to_key(f.read())
        except Exception as e:
            logging.warning(
                "Could not find matching private key. Saving certificate as PEM"
            )
            with open("%s.crt" % out, "wb") as f:
                f.write(cert_to_pem(cert))

            logging.info("Saved certificate to %s" % repr("%s.crt" % out))
        else:
            logging.info("Loaded private key from %s" % repr("%d.key" % request_id))
            pfx = create_pfx(key, cert)
            with open("%s.pfx" % out, "wb") as f:
                f.write(pfx)
            logging.info(
                "Saved certificate and private key to %s" % repr("%s.pfx" % out)
            )

        return True

    def request(self) -> bool:
        username = self.target.username

        if self.on_behalf_of:
            username = self.on_behalf_of
            if self.on_behalf_of.count("\\") == 0:
                logging.warning(
                    "Target does not look like a qualified principal: %s"
                    % self.on_behalf_of
                )
            else:
                username = "\\".join(username.split("\\")[1:])

        csr, key = create_csr(username, alt_name=self.alt_name)

        if self.on_behalf_of:
            if self.pfx is None:
                logging.error(
                    "A certificate and private key (-pfx) is required in order to request on behalf of another user"
                )
                return False

            with open(self.pfx, "rb") as f:
                agent_key, agent_cert = load_pfx(f.read())

            csr = create_cms(csr_to_der(csr), self.on_behalf_of, agent_cert, agent_key)
        else:
            csr = csr_to_der(csr)

        attributes = ["CertificateTemplate:%s" % self.template]

        if self.alt_name is not None:
            attributes.append("SAN:upn=%s" % self.alt_name)

        attributes = checkNullString("\n".join(attributes)).encode("utf-16le")
        pctb_attribs = CERTTRANSBLOB()
        pctb_attribs["cb"] = len(attributes)
        pctb_attribs["pb"] = attributes

        pctb_request = CERTTRANSBLOB()
        pctb_request["cb"] = len(csr)
        pctb_request["pb"] = csr

        request = CertServerRequest()
        request["dwFlags"] = 0
        request["pwszAuthority"] = checkNullString(self.ca)
        request["pdwRequestId"] = self.request_id
        request["pctbAttribs"] = pctb_attribs
        request["pctbRequest"] = pctb_request

        logging.info("Requesting certificate")

        response = self.dce.request(request)

        error_code = response["pdwDisposition"]
        request_id = response["pdwRequestId"]

        if error_code == 3:
            logging.info("Successfully requested certificate")
        else:
            if error_code == 5:
                logging.warning("Certificate request is pending approval")
            else:
                error_msg = translate_error_code(error_code)
                if "unknown error code" in error_msg:
                    logging.error(
                        "Got unknown error while trying to request certificate: (%s): %s"
                        % (
                            error_msg,
                            b"".join(response["pctbDispositionMessage"]["pb"]).decode(
                                "utf-16le"
                            ),
                        )
                    )
                else:
                    logging.error(
                        "Got error while trying to request certificate: %s" % error_msg
                    )

        logging.info("Request ID is %d" % request_id)

        if error_code != 3:
            should_save = input(
                "Would you like to save the private key? (y/N) "
            ).rstrip("\n")

            if should_save.lower() == "y":
                with open("%d.key" % request_id, "wb") as f:
                    f.write(key_to_pem(key))

                logging.info("Saved private key to %d.key" % request_id)

            return False

        cert = der_to_cert(b"".join(response["pctbEncodedCert"]["pb"]))
        id_type, identification = get_id_from_certificate(cert)
        if id_type is not None:
            logging.info("Got certificate with %s %s" % (id_type, repr(identification)))
        else:
            logging.info("Got certficate without identification")

        out = self.out
        if out is None:
            out, _ = cert_id_to_parts(id_type, identification)
            if out is None:
                out = self.target.username

            out = out.rstrip("$").lower()

        pfx = create_pfx(key, cert)

        with open("%s.pfx" % out, "wb") as f:
            f.write(pfx)

        logging.info("Saved certificate and private key to %s" % repr("%s.pfx" % out))


def entry(options: argparse.Namespace) -> None:
    target = Target.from_options(options)
    del options.target

    request = Request(target=target, **vars(options))

    if options.retrieve:
        request.retrieve()
    else:
        request.request()


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(NAME, help="Request certificates")

    subparser.add_argument(
        "-ca", action="store", metavar="certificate authority name", required=True
    )
    subparser.add_argument("-debug", action="store_true", help="Turn debug output on")

    group = subparser.add_argument_group("certificate request options")
    group.add_argument(
        "-template", action="store", metavar="template name", default="User"
    )
    group.add_argument("-alt", action="store", metavar="alternative UPN")
    group.add_argument(
        "-retrieve",
        action="store",
        metavar="request ID",
        help="Retrieve an issued certificate specified by a request ID instead of requesting a new certificate",
        default=0,
        type=int,
    )
    group.add_argument(
        "-on-behalf-of",
        action="store",
        metavar="domain\\account",
        help="Use a Certificate Request Agent certificate to request on behalf of another user",
    )
    group.add_argument(
        "-pfx",
        action="store",
        metavar="pfx/p12 file name",
        help="Path to Certificate Request Agent certificate",
    )

    group = subparser.add_argument_group("output options")
    group.add_argument("-out", action="store", metavar="output file name")

    group = subparser.add_argument_group("connection options")
    group.add_argument(
        "-dynamic-endpoint",
        action="store_true",
        help="Prefer dynamic TCP endpoint over named pipe",
    )

    target.add_argument_group(subparser, connection_options=group)

    return NAME, entry
