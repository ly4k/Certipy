import argparse
import re
from typing import List

import requests
from impacket.dcerpc.v5 import rpcrt
from impacket.dcerpc.v5.dtypes import DWORD, LPWSTR, NULL, PBYTE, ULONG
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.nrpc import checkNullString
from impacket.uuid import uuidtup_to_bin
from requests_ntlm import HttpNtlmAuth
from urllib3 import connection

from certipy.lib.certificate import (
    cert_id_to_parts,
    cert_to_pem,
    create_csr,
    create_key_archival,
    create_on_behalf_of,
    create_pfx,
    create_renewal,
    csr_to_der,
    der_to_cert,
    der_to_csr,
    pem_to_csr,
    der_to_pem,
    get_identifications_from_certificate,
    get_object_sid_from_certificate,
    key_to_pem,
    load_pfx,
    pem_to_cert,
    pem_to_key,
    rsa,
    x509,
)
from certipy.lib.errors import translate_error_code
from certipy.lib.formatting import print_certificate_identifications
from certipy.lib.logger import logging
from certipy.lib.rpc import get_dce_rpc
from certipy.lib.target import Target

from .ca import CA


def _http_request(self, method, url, body=None, headers=None):
    if headers is None:
        headers = {}
    else:
        # Avoid modifying the headers passed into .request()
        headers = headers.copy()
    super(connection.HTTPConnection, self).request(
        method, url, body=body, headers=headers
    )


connection.HTTPConnection.request = _http_request

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


class RequestInterface:
    def __init__(self, parent: "Request"):
        self.parent = parent

    def retrieve(self, request_id: int) -> x509.Certificate:
        raise NotImplementedError("Abstract method")

    def request(
        self,
        csr: bytes,
        attributes: List[str],
    ) -> x509.Certificate:
        raise NotImplementedError("Abstract method")


class RPCRequestInterface(RequestInterface):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._dce = None

    @property
    def dce(self) -> rpcrt.DCERPC_v5:
        if self._dce is not None:
            return self._dce

        self._dce = get_dce_rpc(
            MSRPC_UUID_ICPR,
            r"\pipe\cert",
            self.parent.target,
            timeout=self.parent.target.timeout,
            dynamic=self.parent.dynamic,
            verbose=self.parent.verbose,
        )

        return self._dce

    def retrieve(self, request_id: int) -> x509.Certificate:

        empty = CERTTRANSBLOB()
        empty["cb"] = 0
        empty["pb"] = NULL

        request = CertServerRequest()
        request["dwFlags"] = 0
        request["pwszAuthority"] = checkNullString(self.parent.ca)
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

        return cert

    def request(
        self,
        csr: bytes,
        attributes: List[str],
    ) -> x509.Certificate:
        attributes = checkNullString("\n".join(attributes)).encode("utf-16le")
        pctb_attribs = CERTTRANSBLOB()
        pctb_attribs["cb"] = len(attributes)
        pctb_attribs["pb"] = attributes

        pctb_request = CERTTRANSBLOB()
        pctb_request["cb"] = len(csr)
        pctb_request["pb"] = csr

        request = CertServerRequest()
        request["dwFlags"] = 0
        request["pwszAuthority"] = checkNullString(self.parent.ca)
        request["pdwRequestId"] = self.parent.request_id
        request["pctbAttribs"] = pctb_attribs
        request["pctbRequest"] = pctb_request

        logging.info("Requesting certificate via RPC")

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
                out = (
                    self.parent.out if self.parent.out is not None else str(request_id)
                )
                with open("%s.key" % out, "wb") as f:
                    f.write(key_to_pem(self.parent.key))

                logging.info("Saved private key to %s.key" % out)

            return False

        cert = der_to_cert(b"".join(response["pctbEncodedCert"]["pb"]))

        return cert


class WebRequestInterface(RequestInterface):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.target = self.parent.target

        self._session = None
        self.base_url = ""

    @property
    def session(self) -> requests.Session:
        if self._session is not None:
            return self._session

        if self.target.do_kerberos:
            raise Exception(
                "Kerberos authentication is currently not supported with Web Enrollment"
            )

        scheme = self.parent.scheme
        port = self.parent.port

        password = self.target.password
        if self.target.nthash:
            password = "%s:%s" % (self.target.nthash, self.target.nthash)

        principal = "%s\\%s" % (self.target.domain, self.target.username)

        session = requests.Session()
        session.timeout = self.target.timeout
        session.auth = HttpNtlmAuth(principal, password)
        session.verify = False

        base_url = "%s://%s:%i" % (scheme, self.target.target_ip, port)
        logging.info("Checking for Web Enrollment on %s" % repr(base_url))

        session.headers["User-Agent"] = None

        success = False
        try:
            res = session.get(
                "%s/certsrv/" % base_url,
                headers={"Host": self.target.remote_name},
                timeout=self.target.timeout,
                allow_redirects=False,
            )
        except Exception as e:
            logging.warning("Failed to connect to Web Enrollment interface: %s" % e)
        else:
            if res.status_code == 200:
                success = True
            elif res.status_code == 401:
                logging.error("Unauthorized for Web Enrollment at %s" % repr(base_url))
                return None
            else:
                logging.warning(
                    "Failed to authenticate to Web Enrollment at %s" % repr(base_url)
                )

        if not success:
            scheme = "https" if scheme == "http" else "http"
            port = 80 if scheme == "http" else 443
            base_url = "%s://%s:%i" % (scheme, self.target.target_ip, port)
            logging.info(
                "Trying to connect to Web Enrollment interface %s" % repr(base_url)
            )

            try:
                res = session.get(
                    "%s/certsrv/" % base_url,
                    headers={"Host": self.target.remote_name},
                    timeout=self.target.timeout,
                    allow_redirects=False,
                )
            except Exception as e:
                logging.warning("Failed to connect to Web Enrollment interface: %s" % e)
                return None
            else:
                if res.status_code == 200:
                    success = True
                elif res.status_code == 401:
                    logging.error(
                        "Unauthorized for Web Enrollment at %s" % repr(base_url)
                    )
                else:
                    logging.warning(
                        "Failed to authenticate to Web Enrollment at %s"
                        % repr(base_url)
                    )

        if not success:
            return None

        self.base_url = base_url
        self._session = session
        return self._session

    def retrieve(self, request_id: int) -> x509.Certificate:
        logging.info("Retrieving certificate for request ID: %d" % request_id)
        res = self.session.get(
            "%s/certsrv/certnew.cer" % self.base_url, params={"ReqID": request_id}
        )

        if res.status_code != 200:
            if self.parent.verbose:
                logging.error("Got error while trying to retrieve certificate:")
                print(res.text)
            else:
                logging.error(
                    "Got error while trying to retrieve certificate. Use -debug to print the response"
                )
            return False

        if b"BEGIN CERTIFICATE" in res.content:
            cert = pem_to_cert(res.content)
        else:
            content = res.text
            if "Taken Under Submission" in content:
                logging.warning("Certificate request is pending approval")
            elif "The requested property value is empty" in content:
                logging.warning("Unknown request ID %d" % request_id)
            else:
                error_code = re.findall(r" (0x[0-9a-fA-F]+) \(", content)
                try:
                    error_code = int(error_code[0], 16)
                    msg = translate_error_code(error_code)
                    logging.warning("Got error from AD CS: %s" % msg)
                except:
                    if self.parent.verbose:
                        logging.warning("Got unknown error from AD CS:")
                        print(content)
                    else:
                        logging.warning(
                            "Got unknown error from AD CS. Use -debug to print the response"
                        )

            return False

        return cert

    def request(
        self,
        csr: bytes,
        attributes: List[str],
    ) -> x509.Certificate:
        session = self.session
        if not session:
            return False

        csr = der_to_pem(csr, "CERTIFICATE REQUEST")

        attributes = "\n".join(attributes)

        params = {
            "Mode": "newreq",
            "CertAttrib": attributes,
            "CertRequest": csr,
            "TargetStoreFlags": "0",
            "SaveCert": "yes",
            "ThumbPrint": "",
        }

        logging.info("Requesting certificate via Web Enrollment")

        res = session.post("%s/certsrv/certfnsh.asp" % self.base_url, data=params)
        content = res.text

        if res.status_code != 200:
            logging.error("Got error while trying to request certificate: ")
            if self.parent.verbose:
                print(content)
            else:
                logging.warning("Use -debug to print the response")
            return False

        request_id = re.findall(r"certnew.cer\?ReqID=([0-9]+)&", content)
        if not request_id:
            if "template that is not supported" in content:
                logging.error(
                    "Template %s is not supported by AD CS" % repr(self.parent.template)
                )
                return False
            else:
                request_id = re.findall(r"Your Request Id is ([0-9]+)", content)
                if len(request_id) != 1:
                    logging.error("Failed to get request id from response")
                    request_id = None
                else:
                    request_id = int(request_id[0])

                    logging.info("Request ID is %d" % request_id)

                if "Certificate Pending" in content:
                    logging.warning("Certificate request is pending approval")
                elif '"Denied by Policy Module"' in content:
                    res = self.session.get(
                        "%s/certsrv/certnew.cer" % self.base_url,
                        params={"ReqID": request_id},
                    )
                    try:
                        error_codes = re.findall(
                            "(0x[a-zA-Z0-9]+) \([-]?[0-9]+ ",
                            res.text,
                            flags=re.MULTILINE,
                        )

                        error_msg = translate_error_code(int(error_codes[0], 16))
                        logging.error(
                            "Got error while trying to request certificate: %s"
                            % error_msg
                        )
                    except:
                        logging.warning("Got unknown error from AD CS:")
                        if self.parent.verbose:
                            print(res.text)
                        else:
                            logging.warning("Use -debug to print the response")
                else:
                    error_code = re.findall(
                        r"Denied by Policy Module  (0x[0-9a-fA-F]+),", content
                    )
                    try:
                        error_code = int(error_code[0], 16)
                        msg = translate_error_code(error_code)
                        logging.warning("Got error from AD CS: %s" % msg)
                    except:
                        logging.warning("Got unknown error from AD CS:")
                        if self.parent.verbose:
                            print(content)
                        else:
                            logging.warning("Use -debug to print the response")

            if request_id is None:
                return False

            should_save = input(
                "Would you like to save the private key? (y/N) "
            ).rstrip("\n")

            if should_save.lower() == "y":
                out = (
                    self.parent.out if self.parent.out is not None else str(request_id)
                )
                with open("%s.key" % out, "wb") as f:
                    f.write(key_to_pem(self.parent.key))

                logging.info("Saved private key to %s.key" % out)

            return False

        if len(request_id) == 0:
            logging.error("Failed to get request id from response")
            return False

        request_id = int(request_id[0])

        logging.info("Request ID is %d" % request_id)

        return self.retrieve(request_id)


class Request:
    def __init__(
        self,
        target: Target = None,
        ca: str = None,
        template: str = None,
        upn: str = None,
        dns: str = None,
        sid: str = None,
        subject: str = None,
        csrfile: str = None,
        retrieve: int = 0,
        on_behalf_of: str = None,
        pfx: str = None,
        key_size: int = None,
        archive_key: bool = False,
        renew: bool = False,
        out: str = None,
        key: rsa.RSAPrivateKey = None,
        web: bool = False,
        port: int = None,
        scheme: str = None,
        dynamic_endpoint: bool = False,
        debug=False,
        **kwargs
    ):
        self.target = target
        self.ca = ca
        self.template = template
        self.alt_upn = upn
        self.alt_dns = dns
        self.alt_sid = sid
        self.subject = subject
        self.csrfile = csrfile
        self.request_id = int(retrieve)
        self.on_behalf_of = on_behalf_of
        self.pfx = pfx
        self.key_size = key_size
        self.archive_key = archive_key
        self.renew = renew
        self.out = out
        self.key = key

        self.web = web
        self.port = port
        self.scheme = scheme

        self.dynamic = dynamic_endpoint
        self.verbose = debug
        self.kwargs = kwargs

        if not self.port and self.scheme:
            if self.scheme == "http":
                self.port = 80
            elif self.scheme == "https":
                self.port = 443

        self._dce = None

        self._interface = None

    @property
    def interface(self) -> RequestInterface:
        if self._interface is not None:
            return self._interface

        if self.web:
            self._interface = WebRequestInterface(self)
        else:
            self._interface = RPCRequestInterface(self)

        return self._interface

    def retrieve(self) -> bool:
        request_id = int(self.request_id)

        cert = self.interface.retrieve(request_id)
        if cert is False:
            logging.error("Failed to retrieve certificate")
            return False

        identifications = get_identifications_from_certificate(cert)

        print_certificate_identifications(identifications)

        object_sid = get_object_sid_from_certificate(cert)
        if object_sid is not None:
            logging.info("Certificate object SID is %s" % repr(object_sid))
        else:
            logging.info("Certificate has no object SID")

        out = self.out
        if out is None:
            out, _ = cert_id_to_parts(identifications)
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

        if sum(map(bool, [self.archive_key, self.on_behalf_of, self.renew])) > 1:
            logging.error(
                "Combinations of -renew, -on-behalf-of, and -archive-key are currently not supported"
            )
            return None

        if self.on_behalf_of:
            username = self.on_behalf_of
            if self.on_behalf_of.count("\\") > 0:
                parts = username.split("\\")
                username = "\\".join(parts[1:])
                domain = parts[0]
                if "." in domain:
                    logging.warning(
                        "Domain part of '-on-behalf-of' should not be a FQDN"
                    )

        renewal_cert = None
        renewal_key = None
        if self.renew:
            if self.pfx is None:
                logging.error(
                    "A certificate and private key (-pfx) is required in order for renewal"
                )
                return False

            with open(self.pfx, "rb") as f:
                renewal_key, renewal_cert = load_pfx(f.read())

        if self.csrfile:
            # Read file
            with open(self.csrfile, "rb") as c:
                csr = pem_to_csr(c.read())
                
        else:
            csr, key = create_csr(
                username,
                alt_dns=self.alt_dns,
                alt_upn=self.alt_upn,
                alt_sid=self.alt_sid,
                key=self.key,
                key_size=self.key_size,
                subject=self.subject,
                renewal_cert=renewal_cert,
            )
            self.key = key

        csr = csr_to_der(csr)

        if self.archive_key:
            ca = CA(self.target, self.ca)
            logging.info("Trying to retrieve CAX certificate")
            cax_cert = ca.get_exchange_certificate()
            logging.info("Retrieved CAX certificate")

            csr = create_key_archival(der_to_csr(csr), self.key, cax_cert)

        if self.renew:
            csr = create_renewal(csr, renewal_cert, renewal_key)

        if self.on_behalf_of:
            if self.pfx is None:
                logging.error(
                    "A certificate and private key (-pfx) is required in order to request on behalf of another user"
                )
                return False

            with open(self.pfx, "rb") as f:
                agent_key, agent_cert = load_pfx(f.read())

            csr = create_on_behalf_of(csr, self.on_behalf_of, agent_cert, agent_key)

        attributes = ["CertificateTemplate:%s" % self.template]

        if self.alt_upn is not None or self.alt_dns is not None:
            san = []
            if self.alt_dns:
                san.append("dns=%s" % self.alt_dns)
            if self.alt_upn:
                san.append("upn=%s" % self.alt_upn)

            attributes.append("SAN:%s" % "&".join(san))

        cert = self.interface.request(csr, attributes)

        if cert is False:
            logging.error("Failed to request certificate")
            return False

        if self.subject:
            subject = ",".join(map(lambda x: x.rfc4514_string(), cert.subject.rdns))
            logging.info("Got certificate with subject: %s" % subject)

        identifications = get_identifications_from_certificate(cert)

        print_certificate_identifications(identifications)

        object_sid = get_object_sid_from_certificate(cert)
        if object_sid is not None:
            logging.info("Certificate object SID is %s" % repr(object_sid))
        else:
            logging.info("Certificate has no object SID")

        out = self.out
        if out is None:
            out, _ = cert_id_to_parts(identifications)
            if out is None:
                out = self.target.username

            out = out.rstrip("$").lower()

        if self.csrfile:
            pfx = create_pfx(None, cert)

        else:
            pfx = create_pfx(key, cert)

        outfile = "%s.pfx" % out

        with open(outfile, "wb") as f:
            f.write(pfx)

        if self.csrfile:
            logging.info("Saved certificate without private key to %s" % repr(outfile))
        else:
            logging.info("Saved certificate and private key to %s" % repr(outfile))

        return pfx, outfile


def entry(options: argparse.Namespace) -> None:
    target = Target.from_options(options)
    del options.target

    request = Request(target=target, **vars(options))

    if options.retrieve:
        request.retrieve()
    else:
        request.request()
