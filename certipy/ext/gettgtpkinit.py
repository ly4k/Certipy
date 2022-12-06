#!/usr/bin/env python3
#
# Based on examples from minikerberos by skelsec
# Parts of this code was inspired by the following project by @rubin_mor
# https://github.com/morRubin/AzureADJoinedMachinePTC
#
# Author:
#  Tamas Jos (@skelsec)
#  Dirk-jan Mollema (@_dirkjan)
#
# Modified by Adrian Vollmer:
#  * also return t_key in decrypt_asrep()
import argparse
import logging
import binascii
import secrets
import datetime
import hashlib
import base64

from oscrypto.keys import parse_pkcs12, parse_certificate, parse_private
from oscrypto.asymmetric import rsa_pkcs1v15_sign, load_private_key
from asn1crypto import cms
from asn1crypto import algos
from asn1crypto import core
from asn1crypto import keys

from minikerberos import logger
from minikerberos.pkinit import PKINIT, DirtyDH
from minikerberos.common.ccache import CCACHE
from minikerberos.common.target import KerberosTarget
from minikerberos.network.clientsocket import KerberosClientSocket
from minikerberos.protocol.constants import NAME_TYPE, PaDataType
from minikerberos.protocol.encryption import Enctype, _checksum_table, _enctype_table, Key
from minikerberos.protocol.structures import AuthenticatorChecksum
from minikerberos.protocol.asn1_structs import KDC_REQ_BODY, PrincipalName, HostAddress, \
    KDCOptions, EncASRepPart, AP_REQ, AuthorizationData, Checksum, krb5_pvno, Realm, \
    EncryptionKey, Authenticator, Ticket, APOptions, EncryptedData, AS_REQ, AP_REP, PADATA_TYPE, \
    PA_PAC_REQUEST
from minikerberos.protocol.rfc4556 import PKAuthenticator, AuthPack, Dunno2, MetaData, Info, CertIssuer, CertIssuers, PA_PK_AS_REP, KDCDHKeyInfo, PA_PK_AS_REQ
class myPKINIT(PKINIT):
    """
    Copy of minikerberos PKINIT
    With some changes where it differs from PKINIT used in NegoEx
    """

    @staticmethod
    def from_pfx(pfxfile, pfxpass, dh_params = None):
        with open(pfxfile, 'rb') as f:
            pfxdata = f.read()
        return myPKINIT.from_pfx_data(pfxdata, pfxpass, dh_params)

    @staticmethod
    def from_pfx_data(pfxdata, pfxpass, dh_params = None):
        pkinit = myPKINIT()
        # oscrypto does not seem to support pfx without password, so convert it to PEM using cryptography instead
        if not pfxpass:
            from cryptography.hazmat.primitives.serialization import pkcs12
            from cryptography.hazmat.primitives import serialization
            privkey, cert, extra_certs = pkcs12.load_key_and_certificates(pfxdata, None)
            pem_key = privkey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            pkinit.privkey = load_private_key(parse_private(pem_key))
            pem_cert = cert.public_bytes(
                encoding=serialization.Encoding.PEM
            )
            pkinit.certificate = parse_certificate(pem_cert)
        else:
            #print('Loading pfx12')
            if isinstance(pfxpass, str):
                pfxpass = pfxpass.encode()
            pkinit.privkeyinfo, pkinit.certificate, pkinit.extra_certs = parse_pkcs12(pfxdata, password=pfxpass)
            pkinit.privkey = load_private_key(pkinit.privkeyinfo)
        #print('pfx12 loaded!')
        pkinit.setup(dh_params = dh_params)
        return pkinit

    @staticmethod
    def from_pem(certfile, privkeyfile, dh_params = None):
        pkinit = myPKINIT()
        with open(certfile, 'rb') as f:
            pkinit.certificate = parse_certificate(f.read())
        with open(privkeyfile, 'rb') as f:
            pkinit.privkey = load_private_key(parse_private(f.read()))
        pkinit.setup(dh_params = dh_params)
        return pkinit

    def sign_authpack(self, data, wrap_signed = False):
        return self.sign_authpack_native(data, wrap_signed)

    def setup(self, dh_params = None):
        self.issuer = self.certificate.issuer.native['common_name']
        if dh_params is None:
            print('Generating DH params...')
            # self.diffie = DirtyDH.from_dict()
            print('DH params generated.')
        else:
            #print('Loading default DH params...')
            if isinstance(dh_params, dict):
                self.diffie = DirtyDH.from_dict(dh_params)
            elif isinstance(dh_params, bytes):
                self.diffie = DirtyDH.from_asn1(dh_params)
            elif isinstance(dh_params, DirtyDH):
                self.diffie = dh_params
            else:
                raise Exception('DH params must be either a bytearray or a dict')

    def build_asreq(self, domain = None, cname = None, kdcopts = ['forwardable','renewable','renewable-ok']):
        if isinstance(kdcopts, list):
            kdcopts = set(kdcopts)
        if cname is not None:
            if isinstance(cname, str):
                cname = [cname]
        else:
            cname = [self.cname]

        # if target is not None:
        #     if isinstance(target, str):
        #         target = [target]
        # else:
        #     target = ['127.0.0.1']

        now = datetime.datetime.now(datetime.timezone.utc)

        kdc_req_body_data = {}
        kdc_req_body_data['kdc-options'] = KDCOptions(kdcopts)
        kdc_req_body_data['cname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': cname})
        kdc_req_body_data['realm'] = domain.upper()
        kdc_req_body_data['sname'] = PrincipalName({'name-type': NAME_TYPE.SRV_INST.value, 'name-string': ['krbtgt', domain.upper()]})
        kdc_req_body_data['till']  = (now + datetime.timedelta(days=1)).replace(microsecond=0)
        kdc_req_body_data['rtime'] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
        kdc_req_body_data['nonce'] = secrets.randbits(31)
        kdc_req_body_data['etype'] = [18,17] # 23 breaks...
        # kdc_req_body_data['addresses'] = [HostAddress({'addr-type': 20, 'address': b'127.0.0.1'})] # not sure if this is needed
        kdc_req_body = KDC_REQ_BODY(kdc_req_body_data)


        checksum = hashlib.sha1(kdc_req_body.dump()).digest()

        authenticator = {}
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = now.replace(microsecond=0)
        authenticator['nonce'] = secrets.randbits(31)
        authenticator['paChecksum'] = checksum


        dp = {}
        dp['p'] = self.diffie.p
        dp['g'] = self.diffie.g
        dp['q'] = 0 # mandatory parameter, but it is not needed

        pka = {}
        pka['algorithm'] = '1.2.840.10046.2.1'
        pka['parameters'] = keys.DomainParameters(dp)

        spki = {}
        spki['algorithm'] = keys.PublicKeyAlgorithm(pka)
        spki['public_key'] = self.diffie.get_public_key()


        authpack = {}
        authpack['pkAuthenticator'] = PKAuthenticator(authenticator)
        authpack['clientPublicValue'] = keys.PublicKeyInfo(spki)
        authpack['clientDHNonce'] = self.diffie.dh_nonce

        authpack = AuthPack(authpack)
        signed_authpack = self.sign_authpack(authpack.dump(), wrap_signed = True)

        payload = PA_PK_AS_REQ()
        payload['signedAuthPack'] = signed_authpack

        pa_data_1 = {}
        pa_data_1['padata-type'] = PaDataType.PK_AS_REQ.value
        pa_data_1['padata-value'] = payload.dump()

        pa_data_0 = {}
        pa_data_0['padata-type'] = int(PADATA_TYPE('PA-PAC-REQUEST'))
        pa_data_0['padata-value'] = PA_PAC_REQUEST({'include-pac': True}).dump()

        asreq = {}
        asreq['pvno'] = 5
        asreq['msg-type'] = 10
        asreq['padata'] = [pa_data_0, pa_data_1]
        asreq['req-body'] = kdc_req_body

        return AS_REQ(asreq).dump()

    def sign_authpack_native(self, data, wrap_signed = False):
        """
        Creating PKCS7 blob which contains the following things:

        1. 'data' blob which is an ASN1 encoded "AuthPack" structure
        2. the certificate used to sign the data blob
        3. the singed 'signed_attrs' structure (ASN1) which points to the "data" structure (in point 1)
        """

        da = {}
        da['algorithm'] = algos.DigestAlgorithmId('1.3.14.3.2.26') # for sha1

        si = {}
        si['version'] = 'v1'
        si['sid'] = cms.IssuerAndSerialNumber({
            'issuer':  self.certificate.issuer,
            'serial_number':  self.certificate.serial_number,
        })


        si['digest_algorithm'] = algos.DigestAlgorithm(da)
        si['signed_attrs'] = [
            cms.CMSAttribute({'type': 'content_type', 'values': ['1.3.6.1.5.2.3.1']}), # indicates that the encap_content_info's authdata struct (marked with OID '1.3.6.1.5.2.3.1' is signed )
            cms.CMSAttribute({'type': 'message_digest', 'values': [hashlib.sha1(data).digest()]}), ### hash of the data, the data itself will not be signed, but this block of data will be.
        ]
        si['signature_algorithm'] = algos.SignedDigestAlgorithm({'algorithm' : '1.2.840.113549.1.1.1'})
        si['signature'] = rsa_pkcs1v15_sign(self.privkey,  cms.CMSAttributes(si['signed_attrs']).dump(), "sha1")

        ec = {}
        ec['content_type'] = '1.3.6.1.5.2.3.1'
        ec['content'] = data

        sd = {}
        sd['version'] = 'v3'
        sd['digest_algorithms'] = [algos.DigestAlgorithm(da)] # must have only one
        sd['encap_content_info'] = cms.EncapsulatedContentInfo(ec)
        sd['certificates'] = [self.certificate]
        sd['signer_infos'] = cms.SignerInfos([cms.SignerInfo(si)])

        if wrap_signed is True:
            ci = {}
            ci['content_type'] = '1.2.840.113549.1.7.2' # signed data OID
            ci['content'] = cms.SignedData(sd)
            return cms.ContentInfo(ci).dump()

        return cms.SignedData(sd).dump()

    def decrypt_asrep(self, as_rep):
        def truncate_key(value, keysize):
            output = b''
            currentNum = 0
            while len(output) < keysize:
                currentDigest = hashlib.sha1(bytes([currentNum]) + value).digest()
                if len(output) + len(currentDigest) > keysize:
                    output += currentDigest[:keysize - len(output)]
                    break
                output += currentDigest
                currentNum += 1

            return output

        for pa in as_rep['padata']:
            if pa['padata-type'] == 17:
                pkasrep = PA_PK_AS_REP.load(pa['padata-value']).native
                break
        else:
            raise Exception('PA_PK_AS_REP not found!')
        ci = cms.ContentInfo.load(pkasrep['dhSignedData']).native
        sd = ci['content']
        keyinfo = sd['encap_content_info']
        if keyinfo['content_type'] != '1.3.6.1.5.2.3.2':
            raise Exception('Keyinfo content type unexpected value')
        authdata = KDCDHKeyInfo.load(keyinfo['content']).native
        pubkey = int(''.join(['1'] + [str(x) for x in authdata['subjectPublicKey']]), 2)

        pubkey = int.from_bytes(core.BitString(authdata['subjectPublicKey']).dump()[7:], 'big', signed = False)
        shared_key = self.diffie.exchange(pubkey)

        server_nonce = pkasrep['serverDHNonce']
        fullKey = shared_key + self.diffie.dh_nonce + server_nonce

        etype = as_rep['enc-part']['etype']
        cipher = _enctype_table[etype]
        if etype == Enctype.AES256:
            t_key = truncate_key(fullKey, 32)
        elif etype == Enctype.AES128:
            t_key = truncate_key(fullKey, 16)
        elif etype == Enctype.RC4:
            raise NotImplementedError('RC4 key truncation documentation missing. it is different from AES')
            #t_key = truncate_key(fullKey, 16)


        key = Key(cipher.enctype, t_key)
        enc_data = as_rep['enc-part']['cipher']
        logger.info('AS-REP encryption key (you might need this later):')
        logger.info(binascii.hexlify(t_key).decode('utf-8'))
        dec_data = cipher.decrypt(key, 3, enc_data)
        encasrep = EncASRepPart.load(dec_data).native
        cipher = _enctype_table[ int(encasrep['key']['keytype'])]
        session_key = Key(cipher.enctype, encasrep['key']['keyvalue'])
        return encasrep, session_key, cipher, t_key

def amain(args):
    # Static DH params because the ones generated by cryptography are considered unsafe by AD for some weird reason
    dhparams = {
        'p':int('00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff', 16),
        'g':2
    }
    logger.info('Loading certificate and key from file')
    if args.pfx_base64:
        pfxdata = base64.b64decode(args.pfx_base64)
        ini = myPKINIT.from_pfx_data(pfxdata, args.pfx_pass, dhparams)
    elif args.cert_pfx:
        ini = myPKINIT.from_pfx(args.cert_pfx, args.pfx_pass, dhparams)
    elif args.cert_pem and args.key_pem:
        ini = myPKINIT.from_pem(args.cert_pem, args.key_pem, dhparams)
    else:
        logging.error('You must either specify a PFX file + optional password or a combination of Cert PEM file and Private key PEM file')
        return
    domain, username = args.identity.split('/')
    req = ini.build_asreq(domain,username)
    logger.info('Requesting TGT')
    if not args.dc_ip:
        args.dc_ip = domain

    sock = KerberosClientSocket(KerberosTarget(args.dc_ip))
    res = sock.sendrecv(req)

    encasrep, session_key, cipher = ini.decrypt_asrep(res.native)
    ccache = CCACHE()
    ccache.add_tgt(res.native, encasrep)
    ccache.to_file(args.ccache)
    logger.info('Saved TGT to file')

def main():
    import argparse

    parser = argparse.ArgumentParser(description='Requests a TGT using Kerberos PKINIT and either a PEM or PFX based certificate+key')
    parser.add_argument('identity', action='store', metavar='domain/username', help='Domain and username in the cert')
    parser.add_argument('ccache', help='ccache file to store the TGT in')
    parser.add_argument('-cert-pfx', action='store', metavar='file', help='PFX file')
    parser.add_argument('-pfx-pass', action='store', metavar='password', help='PFX file password')
    parser.add_argument('-pfx-base64', action='store', metavar='BASE64', help='PFX file as base64 string')
    parser.add_argument('-cert-pem', action='store', metavar='file', help='Certificate in PEM format')
    parser.add_argument('-key-pem', action='store', metavar='file', help='Private key file in PEM format')
    parser.add_argument('-dc-ip', help='DC IP or hostname to use as KDC')
    parser.add_argument('-v', '--verbose', action='count', default=0)

    args = parser.parse_args()
    if args.verbose == 0:
        logger.setLevel(logging.INFO)
    elif args.verbose == 1:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(1)

    amain(args)


if __name__ == '__main__':
    main()
