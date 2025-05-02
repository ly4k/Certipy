# Copyright (C) 2013 by the Massachusetts Institute of Technology.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in
#   the documentation and/or other materials provided with the
#   distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.

# XXX current status:
# * Done and tested
#   - AES encryption, checksum, string2key, prf
#   - cf2 (needed for FAST)
# * Still to do:
#   - DES enctypes and cksumtypes
#   - RC4 exported enctype (if we need it for anything)
#   - Unkeyed checksums
#   - Special RC4, raw DES/DES3 operations for GSSAPI
# * Difficult or low priority:
#   - Camellia not supported by PyCrypto
#   - Cipher state only needed for kcmd suite
#   - Nonstandard enctypes and cksumtypes like des-hmac-sha1
# Original code was taken from impacket, ported to python3 by Tamas Jos (@skelsec)

import functools
import os
import string
from binascii import unhexlify
from math import gcd
from struct import pack, unpack
from typing import Dict

from unicrypto import hmac as HMAC
from unicrypto.hashlib import md4
from unicrypto.hashlib import md5 as MD5
from unicrypto.hashlib import sha1 as SHA
from unicrypto.pbkdf2 import pbkdf2 as PBKDF2
from unicrypto.symmetric import AES, DES, MODE_CBC, MODE_ECB
from unicrypto.symmetric import RC4 as ARC4
from unicrypto.symmetric import TDES as DES3  # , MODE_CBC, MODE_ECB


def get_random_bytes(lenBytes):
    # We don't really need super strong randomness here to use PyCrypto.Random
    return os.urandom(lenBytes)


class Enctype(object):
    DES_CRC = 1
    DES_MD4 = 2
    DES_MD5 = 3
    DES3 = 16
    AES128 = 17
    AES256 = 18
    RC4 = 23


class Cksumtype(object):
    CRC32 = 1
    MD4 = 2
    MD4_DES = 3
    MD5 = 7
    MD5_DES = 8
    SHA1 = 9
    SHA1_DES3 = 12
    SHA1_AES128 = 15
    SHA1_AES256 = 16
    HMAC_MD5 = -138


class InvalidChecksum(ValueError):
    pass


def _zeropad(s, padsize):
    # Return s padded with 0 bytes to a multiple of padsize.
    padlen = (padsize - (len(s) % padsize)) % padsize
    return s + b"\x00" * padlen


def _xorbytes(b1, b2):
    # xor two strings together and return the resulting string.
    assert len(b1) == len(b2)
    t1 = int.from_bytes(b1, byteorder="big", signed=False)
    t2 = int.from_bytes(b2, byteorder="big", signed=False)
    return (t1 ^ t2).to_bytes(len(b1), byteorder="big", signed=False)


def _mac_equal(mac1, mac2):
    # Constant-time comparison function.  (We can't use HMAC.verify
    # since we use truncated macs.)
    assert len(mac1) == len(mac2)
    res = 0
    for x, y in zip(mac1, mac2):
        res |= x ^ y
    return res == 0


def _nfold(str, nbytes):
    # Convert str to a string of length nbytes using the RFC 3961 nfold
    # operation.

    # Rotate the bytes in str to the right by nbits bits.
    def rotate_right(str, nbits):
        num = int.from_bytes(str, byteorder="big", signed=False)
        size = len(str) * 8
        nbits %= size
        body = num >> nbits
        remains = (num << (size - nbits)) - (body << size)
        return (body + remains).to_bytes(len(str), byteorder="big", signed=False)

    # Add equal-length strings together with end-around carry.
    def add_ones_complement(str1, str2):
        n = len(str1)
        v = []
        for i in range(0, len(str1), 1):
            t = str1[i] + str2[i]
            v.append(t)

        # v = [ord(a) + ord(b) for a, b in zip(str1, str2)]
        # Propagate carry bits to the left until there aren't any left.
        while any(x & ~0xFF for x in v):
            v = [(v[i - n + 1] >> 8) + (v[i] & 0xFF) for i in range(n)]
        return b"".join(x.to_bytes(1, byteorder="big", signed=False) for x in v)

    # Concatenate copies of str to produce the least common multiple
    # of len(str) and nbytes, rotating each copy of str to the right
    # by 13 bits times its list position.  Decompose the concatenation
    # into slices of length nbytes, and add them together as
    # big-endian ones' complement integers.
    slen = len(str)
    lcm = int(nbytes * slen / gcd(nbytes, slen))
    bigstr = b"".join((rotate_right(str, 13 * i) for i in range(int(lcm / slen))))
    slices = (bigstr[p : p + nbytes] for p in range(0, lcm, nbytes))

    return functools.reduce(add_ones_complement, slices)


def _is_weak_des_key(keybytes):
    return keybytes in (
        b"\x01\x01\x01\x01\x01\x01\x01\x01",
        b"\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe",
        b"\x1f\x1f\x1f\x1f\x0e\x0e\x0e\x0e",
        b"\xe0\xe0\xe0\xe0\xf1\xf1\xf1\xf1",
        b"\x01\xfe\x01\xfe\x01\xfe\x01\xfe",
        b"\xfe\x01\xfe\x01\xfe\x01\xfe\x01",
        b"\x1f\xe0\x1f\xe0\x0e\xf1\x0e\xf1",
        b"\xe0\x1f\xe0\x1f\xf1\x0e\xf1\x0e",
        b"\x01\xe0\x01\xe0\x01\xf1\x01\xf1",
        b"\xe0\x01\xe0\x01\xf1\x01\xf1\x01",
        b"\x1f\xfe\x1f\xfe\x0e\xfe\x0e\xfe",
        b"\xfe\x1f\xfe\x1f\xfe\x0e\xfe\x0e",
        b"\x01\x1f\x01\x1f\x01\x0e\x01\x0e",
        b"\x1f\x01\x1f\x01\x0e\x01\x0e\x01",
        b"\xe0\xfe\xe0\xfe\xf1\xfe\xf1\xfe",
        b"\xfe\xe0\xfe\xe0\xfe\xf1\xfe\xf1",
    )


class _EnctypeProfile(object):
    # Base class for enctype profiles.  Usable enctype classes must define:
    #   * enctype: enctype number
    #   * keysize: protocol size of key in bytes
    #   * seedsize: random_to_key input size in bytes
    #   * random_to_key (if the keyspace is not dense)
    #   * string_to_key
    #   * encrypt
    #   * decrypt
    #   * prf

    @classmethod
    def random_to_key(cls, seed):
        if len(seed) != cls.seedsize:
            raise ValueError("Wrong seed length")
        return Key(cls.enctype, seed)


class _SimplifiedEnctype(_EnctypeProfile):
    # Base class for enctypes using the RFC 3961 simplified profile.
    # Defines the encrypt, decrypt, and prf methods.  Subclasses must
    # define:
    #   * blocksize: Underlying cipher block size in bytes
    #   * padsize: Underlying cipher padding multiple (1 or blocksize)
    #   * macsize: Size of integrity MAC in bytes
    #   * hashmod: PyCrypto hash module for underlying hash function
    #   * basic_encrypt, basic_decrypt: Underlying CBC/CTS cipher

    @classmethod
    def derive(cls, key, constant):
        # RFC 3961 only says to n-fold the constant only if it is
        # shorter than the cipher block size.  But all Unix
        # implementations n-fold constants if their length is larger
        # than the block size as well, and n-folding when the length
        # is equal to the block size is a no-op.
        plaintext = _nfold(constant, cls.blocksize)
        rndseed = b""
        while len(rndseed) < cls.seedsize:
            ciphertext = cls.basic_encrypt(key, plaintext)
            rndseed += ciphertext
            plaintext = ciphertext
        return cls.random_to_key(rndseed[0 : cls.seedsize])

    @classmethod
    def encrypt(cls, key, keyusage, plaintext, confounder):
        ki = cls.derive(key, pack(">IB", keyusage, 0x55))
        ke = cls.derive(key, pack(">IB", keyusage, 0xAA))
        if confounder is None:
            confounder = get_random_bytes(cls.blocksize)
        basic_plaintext = confounder + _zeropad(plaintext, cls.padsize)
        hmac = HMAC.new(ki.contents, basic_plaintext, cls.hashmod).digest()
        return cls.basic_encrypt(ke, basic_plaintext) + hmac[: cls.macsize]

    @classmethod
    def decrypt(cls, key, keyusage, ciphertext):
        ki = cls.derive(key, pack(">IB", keyusage, 0x55))
        ke = cls.derive(key, pack(">IB", keyusage, 0xAA))
        if len(ciphertext) < cls.blocksize + cls.macsize:
            raise ValueError("ciphertext too short")
        basic_ctext, mac = ciphertext[: -cls.macsize], ciphertext[-cls.macsize :]
        if len(basic_ctext) % cls.padsize != 0:
            raise ValueError("ciphertext does not meet padding requirement")
        basic_plaintext = cls.basic_decrypt(ke, basic_ctext)
        hmac = HMAC.new(ki.contents, basic_plaintext, cls.hashmod).digest()
        expmac = hmac[: cls.macsize]
        if not _mac_equal(mac, expmac):
            raise InvalidChecksum("ciphertext integrity failure")
        # Discard the confounder.
        return basic_plaintext[cls.blocksize :]

    @classmethod
    def prf(cls, key, string):
        # Hash the input.  RFC 3961 says to truncate to the padding
        # size, but implementations truncate to the block size.
        hashval = cls.hashmod(string).digest()
        truncated = hashval[: -(len(hashval) % cls.blocksize)]
        # Encrypt the hash with a derived key.
        kp = cls.derive(key, b"prf")
        return cls.basic_encrypt(kp, truncated)


class _DESCBC(_SimplifiedEnctype):
    enctype = Enctype.DES_MD5
    keysize = 8
    seedsize = 8
    blocksize = 8
    padsize = 8
    macsize = 16
    hashmod = MD5

    @classmethod
    def encrypt(cls, key, keyusage, plaintext, confounder):
        if confounder is None:
            confounder = get_random_bytes(cls.blocksize)
        basic_plaintext = (
            confounder + "\x00" * cls.macsize + _zeropad(plaintext, cls.padsize)
        )
        checksum = cls.hashmod.new(basic_plaintext).digest()
        basic_plaintext = (
            basic_plaintext[: len(confounder)]
            + checksum
            + basic_plaintext[len(confounder) + len(checksum) :]
        )
        return cls.basic_encrypt(key, basic_plaintext)

    @classmethod
    def decrypt(cls, key, keyusage, ciphertext):
        if len(ciphertext) < cls.blocksize + cls.macsize:
            raise ValueError("ciphertext too short")

        complex_plaintext = cls.basic_decrypt(key, ciphertext)
        cofounder = complex_plaintext[: cls.padsize]
        mac = complex_plaintext[cls.padsize : cls.padsize + cls.macsize]
        message = complex_plaintext[cls.padsize + cls.macsize :]

        expmac = cls.hashmod.new(cofounder + "\x00" * cls.macsize + message).digest()
        if not _mac_equal(mac, expmac):
            raise InvalidChecksum("ciphertext integrity failure")
        return message

    @classmethod
    def mit_des_string_to_key(cls, string, salt):
        def fixparity(deskey):
            temp = b""
            for byte in deskey:
                t = (bin(byte)[2:]).rjust(8, "0")
                if t[:7].count("1") % 2 == 0:
                    temp += int(t[:7] + "1", 2).to_bytes(
                        1, byteorder="big", signed=False
                    )
                else:
                    temp += int(t[:7] + "0", 2).to_bytes(
                        1, byteorder="big", signed=False
                    )
            return temp

        def addparity(l1):
            temp = list()
            for byte in l1:
                if (bin(byte).count("1") % 2) == 0:
                    byte = (byte << 1) | 0b00000001
                else:
                    byte = (byte << 1) & 0b11111110
                temp.append(byte)
            return temp

        def XOR(l1, l2):
            temp = list()
            for b1, b2 in zip(l1, l2):
                temp.append((b1 ^ b2) & 0b01111111)

            return temp

        odd = True
        s = string + salt
        tempstring = [0, 0, 0, 0, 0, 0, 0, 0]
        s = s + b"\x00" * (
            8 - (len(s) % 8)
        )  # pad(s); /* with nulls to 8 byte boundary */

        for block in [s[i : i + 8] for i in range(0, len(s), 8)]:
            temp56 = list()
            # removeMSBits
            for byte in block:
                temp56.append(byte & 0b01111111)

            # reverse
            if odd == False:
                bintemp = ""
                for byte in temp56:
                    bintemp += (bin(byte)[2:]).rjust(7, "0")
                bintemp = bintemp[::-1]

                temp56 = list()
                for bits7 in [bintemp[i : i + 7] for i in range(0, len(bintemp), 7)]:
                    temp56.append(int(bits7, 2))

            odd = not odd

            tempstring = XOR(tempstring, temp56)

        tempkey = b"".join(
            byte.to_bytes(1, byteorder="big", signed=False)
            for byte in addparity(tempstring)
        )
        if _is_weak_des_key(tempkey):
            tempkey[7] = (tempkey[7] ^ 0xF0).to_bytes(1, byteorder="big", signed=False)

        cipher = DES(tempkey, MODE_CBC, tempkey)
        chekcsumkey = cipher.encrypt(s)[-8:]
        chekcsumkey = fixparity(chekcsumkey)
        if _is_weak_des_key(chekcsumkey):
            chekcsumkey[7] = chr(ord(chekcsumkey[7]) ^ 0xF0)

        return Key(cls.enctype, chekcsumkey)

    @classmethod
    def basic_encrypt(cls, key, plaintext):
        assert len(plaintext) % 8 == 0
        des = DES(key.contents, MODE_CBC, b"\x00" * 8)
        return des.encrypt(plaintext)

    @classmethod
    def basic_decrypt(cls, key, ciphertext):
        assert len(ciphertext) % 8 == 0
        des = DES(key.contents, MODE_CBC, b"\x00" * 8)
        return des.decrypt(ciphertext)

    @classmethod
    def string_to_key(cls, string, salt, params):
        if params is not None and params != "":
            raise ValueError("Invalid DES string-to-key parameters")
        key = cls.mit_des_string_to_key(string, salt)
        return key


class _DES3CBC(_SimplifiedEnctype):
    enctype = Enctype.DES3
    keysize = 24
    seedsize = 21
    blocksize = 8
    padsize = 8
    macsize = 20
    hashmod = SHA

    @classmethod
    def random_to_key(cls, seed):
        # XXX Maybe reframe as _DESEnctype.random_to_key and use that
        # way from DES3 random-to-key when DES is implemented, since
        # MIT does this instead of the RFC 3961 random-to-key.
        def expand(seed):
            def parity(b):
                # Return b with the low-order bit set to yield odd parity.
                b &= ~1
                return b if bin(b & ~1).count("1") % 2 else b | 1

            assert len(seed) == 7
            firstbytes = [parity(b & ~1) for b in seed]
            lastbyte = parity(sum((seed[i] & 1) << i + 1 for i in range(7)))
            keybytes = b"".join(
                b.to_bytes(1, byteorder="big", signed=False)
                for b in firstbytes + [lastbyte]
            )
            if _is_weak_des_key(keybytes):
                keybytes[7] = (keybytes[7] ^ 0xF0).to_bytes(
                    1, byteorder="big", signed=False
                )
            return keybytes

        if len(seed) != 21:
            raise ValueError("Wrong seed length")
        k1, k2, k3 = expand(seed[:7]), expand(seed[7:14]), expand(seed[14:])
        return Key(cls.enctype, k1 + k2 + k3)

    @classmethod
    def string_to_key(cls, string, salt, params):
        if params is not None and params != "":
            raise ValueError("Invalid DES3 string-to-key parameters")
        k = cls.random_to_key(_nfold(string + salt, 21))
        return cls.derive(k, "kerberos".encode())

    @classmethod
    def basic_encrypt(cls, key, plaintext):
        assert len(plaintext) % 8 == 0
        des3 = DES3(key.contents, MODE_CBC, IV=b"\x00" * 8)
        return des3.encrypt(plaintext)

    @classmethod
    def basic_decrypt(cls, key, ciphertext):
        assert len(ciphertext) % 8 == 0
        des3 = DES3(key.contents, MODE_CBC, IV=b"\x00" * 8)
        return des3.decrypt(ciphertext)


class _AESEnctype(_SimplifiedEnctype):
    # Base class for aes128-cts and aes256-cts.
    blocksize = 16
    padsize = 1
    macsize = 12
    hashmod = SHA

    @classmethod
    def string_to_key(cls, string, salt, params):
        (iterations,) = unpack(">L", params or b"\x00\x00\x10\x00")
        # prf = lambda p, s: HMAC.new(p, s, SHA).digest()
        # seed = PBKDF2(string, salt, cls.seedsize, iterations, prf)
        seed = PBKDF2(string, salt, iterations, cls.seedsize)
        tkey = cls.random_to_key(seed)
        return cls.derive(tkey, "kerberos".encode())

    @classmethod
    def basic_encrypt(cls, key, plaintext):
        assert len(plaintext) >= 16
        aes = AES(key.contents, MODE_CBC, b"\x00" * 16)
        ctext = aes.encrypt(_zeropad(plaintext, 16))
        if len(plaintext) > 16:
            # Swap the last two ciphertext blocks and truncate the
            # final block to match the plaintext length.
            lastlen = len(plaintext) % 16 or 16
            ctext = ctext[:-32] + ctext[-16:] + ctext[-32:-16][:lastlen]
        return ctext

    @classmethod
    def basic_decrypt(cls, key, ciphertext):
        assert len(ciphertext) >= 16
        aes = AES(key.contents, MODE_ECB)
        if len(ciphertext) == 16:
            return aes.decrypt(ciphertext)
        # Split the ciphertext into blocks.  The last block may be partial.
        cblocks = [ciphertext[p : p + 16] for p in range(0, len(ciphertext), 16)]
        lastlen = len(cblocks[-1])
        # CBC-decrypt all but the last two blocks.
        prev_cblock = b"\x00" * 16
        plaintext = b""
        for b in cblocks[:-2]:
            plaintext += _xorbytes(aes.decrypt(b), prev_cblock)
            prev_cblock = b
        # Decrypt the second-to-last cipher block.  The left side of
        # the decrypted block will be the final block of plaintext
        # xor'd with the final partial cipher block; the right side
        # will be the omitted bytes of ciphertext from the final
        # block.
        b = aes.decrypt(cblocks[-2])
        lastplaintext = _xorbytes(b[:lastlen], cblocks[-1])
        omitted = b[lastlen:]
        # Decrypt the final cipher block plus the omitted bytes to get
        # the second-to-last plaintext block.
        plaintext += _xorbytes(aes.decrypt(cblocks[-1] + omitted), prev_cblock)
        return plaintext + lastplaintext


class _AES128CTS(_AESEnctype):
    enctype = Enctype.AES128
    keysize = 16
    seedsize = 16


class _AES256CTS(_AESEnctype):
    enctype = Enctype.AES256
    keysize = 32
    seedsize = 32


class _RC4(_EnctypeProfile):
    enctype = Enctype.RC4
    keysize = 16
    seedsize = 16

    @staticmethod
    def usage_str(keyusage):
        # Return a four-byte string for an RFC 3961 keyusage, using
        # the RFC 4757 rules.  Per the errata, do not map 9 to 8.
        table = {3: 8, 23: 13}
        msusage = table[keyusage] if keyusage in table else keyusage
        return pack("<I", msusage)

    @classmethod
    def string_to_key(cls, string, salt, params):
        utf16string = string.decode("UTF-8").encode("UTF-16LE")
        # return Key(cls.enctype, hashlib.new('md4', utf16string).digest())
        data = md4(utf16string).digest()  # hashlib.new('md4', utf16string).digest()
        return Key(cls.enctype, data)

    @classmethod
    def encrypt(cls, key, keyusage, plaintext, confounder):
        if confounder is None:
            confounder = get_random_bytes(8)
        ki = HMAC.new(key.contents, cls.usage_str(keyusage), MD5).digest()
        cksum = HMAC.new(ki, confounder + plaintext, MD5).digest()
        ke = HMAC.new(ki, cksum, MD5).digest()
        return cksum + ARC4(ke).encrypt(confounder + plaintext)

    @classmethod
    def decrypt(cls, key, keyusage, ciphertext):
        if len(ciphertext) < 24:
            raise ValueError("ciphertext too short")
        cksum, basic_ctext = ciphertext[:16], ciphertext[16:]
        ki = HMAC.new(key.contents, cls.usage_str(keyusage), MD5).digest()
        ke = HMAC.new(ki, cksum, MD5).digest()
        basic_plaintext = ARC4(ke).decrypt(basic_ctext)
        exp_cksum = HMAC.new(ki, basic_plaintext, MD5).digest()
        ok = _mac_equal(cksum, exp_cksum)
        if not ok and keyusage == 9:
            # Try again with usage 8, due to RFC 4757 errata.
            ki = HMAC.new(key.contents, pack("<I", 8), MD5).digest()
            exp_cksum = HMAC.new(ki, basic_plaintext, MD5).digest()
            ok = _mac_equal(cksum, exp_cksum)
        if not ok:
            raise InvalidChecksum("ciphertext integrity failure")
        # Discard the confounder.
        return basic_plaintext[8:]

    @classmethod
    def prf(cls, key, string):
        return HMAC.new(key.contents, string, SHA).digest()


class _ChecksumProfile(object):
    # Base class for checksum profiles.  Usable checksum classes must
    # define:
    #   * checksum
    #   * verify (if verification is not just checksum-and-compare)
    @classmethod
    def verify(cls, key, keyusage, text, cksum):
        expected = cls.checksum(key, keyusage, text)
        if not _mac_equal(cksum, expected):
            raise InvalidChecksum("checksum verification failure")


class _SimplifiedChecksum(_ChecksumProfile):
    # Base class for checksums using the RFC 3961 simplified profile.
    # Defines the checksum and verify methods.  Subclasses must
    # define:
    #   * macsize: Size of checksum in bytes
    #   * enc: Profile of associated enctype

    @classmethod
    def checksum(cls, key, keyusage, text):
        kc = cls.enc.derive(key, pack(">IB", keyusage, 0x99))
        hmac = HMAC.new(kc.contents, text, cls.enc.hashmod).digest()
        return hmac[: cls.macsize]

    @classmethod
    def verify(cls, key, keyusage, text, cksum):
        if key.enctype != cls.enc.enctype:
            raise ValueError("Wrong key type for checksum")
        super(_SimplifiedChecksum, cls).verify(key, keyusage, text, cksum)


class _SHA1AES128(_SimplifiedChecksum):
    macsize = 12
    enc = _AES128CTS


class _SHA1AES256(_SimplifiedChecksum):
    macsize = 12
    enc = _AES256CTS


class _SHA1DES3(_SimplifiedChecksum):
    macsize = 20
    enc = _DES3CBC


class _HMACMD5(_ChecksumProfile):
    @classmethod
    def checksum(cls, key, keyusage, text):
        ksign = HMAC.new(key.contents, b"signaturekey\x00", MD5).digest()
        md5hash = MD5(_RC4.usage_str(keyusage) + text).digest()
        return HMAC.new(ksign, md5hash, MD5).digest()

    @classmethod
    def verify(cls, key, keyusage, text, cksum):
        if key.enctype != Enctype.RC4:
            raise ValueError("Wrong key type for checksum")
        super(_HMACMD5, cls).verify(key, keyusage, text, cksum)


_enctype_table: Dict[str, _SimplifiedEnctype] = {
    Enctype.DES_MD5: _DESCBC,
    Enctype.DES3: _DES3CBC,
    Enctype.AES128: _AES128CTS,
    Enctype.AES256: _AES256CTS,
    Enctype.RC4: _RC4,
}


_checksum_table = {
    Cksumtype.SHA1_DES3: _SHA1DES3,
    Cksumtype.SHA1_AES128: _SHA1AES128,
    Cksumtype.SHA1_AES256: _SHA1AES256,
    Cksumtype.HMAC_MD5: _HMACMD5,
    0xFFFFFF76: _HMACMD5,
}


def _get_enctype_profile(enctype):
    if enctype not in _enctype_table:
        raise ValueError("Invalid enctype %d" % enctype)
    return _enctype_table[enctype]


def _get_checksum_profile(cksumtype):
    if cksumtype not in _checksum_table:
        raise ValueError("Invalid cksumtype %d" % cksumtype)
    return _checksum_table[cksumtype]


class Key(object):
    def __init__(self, enctype: Enctype, contents: bytes):
        e = _get_enctype_profile(enctype)
        if len(contents) != e.keysize:
            raise ValueError("Wrong key length")
        self.enctype = enctype
        self.contents = contents


def random_to_key(enctype, seed):
    e = _get_enctype_profile(enctype)
    if len(seed) != e.seedsize:
        raise ValueError("Wrong crypto seed length")
    return e.random_to_key(seed)


def string_to_key(enctype, string, salt, params=None):
    e = _get_enctype_profile(enctype)
    return e.string_to_key(string, salt, params)


def encrypt(key, keyusage, plaintext, confounder=None):
    e = _get_enctype_profile(key.enctype)
    return e.encrypt(key, keyusage, plaintext, confounder)


def decrypt(key, keyusage, ciphertext):
    # Throw InvalidChecksum on checksum failure.  Throw ValueError on
    # invalid key enctype or malformed ciphertext.
    e = _get_enctype_profile(key.enctype)
    return e.decrypt(key, keyusage, ciphertext)


def prf(key, string):
    e = _get_enctype_profile(key.enctype)
    return e.prf(key, string)


def make_checksum(cksumtype, key, keyusage, text):
    c = _get_checksum_profile(cksumtype)
    return c.checksum(key, keyusage, text)


def verify_checksum(cksumtype, key, keyusage, text, cksum):
    # Throw InvalidChecksum exception on checksum failure.  Throw
    # ValueError on invalid cksumtype, invalid key enctype, or
    # malformed checksum.
    c = _get_checksum_profile(cksumtype)
    c.verify(key, keyusage, text, cksum)


def cf2(enctype, key1, key2, pepper1, pepper2):
    # Combine two keys and two pepper strings to produce a result key
    # of type enctype, using the RFC 6113 KRB-FX-CF2 function.
    def prfplus(key, pepper, l):
        # Produce l bytes of output using the RFC 6113 PRF+ function.
        out = b""
        count = 1
        while len(out) < l:
            out += prf(key, count.to_bytes(1, byteorder="big", signed=False) + pepper)
            count += 1
        return out[:l]

    e = _get_enctype_profile(enctype)
    return e.random_to_key(
        _xorbytes(
            prfplus(key1, pepper1, e.seedsize), prfplus(key2, pepper2, e.seedsize)
        )
    )


if __name__ == "__main__":

    def h(hexstr):
        return unhexlify(hexstr)

    # AES128 encrypt and decrypt
    kb = h("9062430C8CDA3388922E6D6A509F5B7A")
    conf = h("94B491F481485B9A0678CD3C4EA386AD")
    keyusage = 2
    plain = "9 bytesss".encode()
    ctxt = h(
        "68FB9679601F45C78857B2BF820FD6E53ECA8D42FD4B1D7024A09205ABB7CD2E" "C26C355D2F"
    )
    k = Key(Enctype.AES128, kb)
    assert encrypt(k, keyusage, plain, conf) == ctxt
    assert decrypt(k, keyusage, ctxt) == plain

    # AES256 encrypt and decrypt
    kb = h("F1C795E9248A09338D82C3F8D5B567040B0110736845041347235B1404231398")
    conf = h("E45CA518B42E266AD98E165E706FFB60")
    keyusage = 4
    plain = "30 bytes bytes bytes bytes byt".encode()
    ctxt = h(
        "D1137A4D634CFECE924DBC3BF6790648BD5CFF7DE0E7B99460211D0DAEF3D79A"
        "295C688858F3B34B9CBD6EEBAE81DAF6B734D4D498B6714F1C1D"
    )
    k = Key(Enctype.AES256, kb)
    assert encrypt(k, keyusage, plain, conf) == ctxt
    assert decrypt(k, keyusage, ctxt) == plain

    # AES128 checksum
    kb = h("9062430C8CDA3388922E6D6A509F5B7A")
    keyusage = 3
    plain = "eight nine ten eleven twelve thirteen".encode()
    cksum = h("01A4B088D45628F6946614E3")
    k = Key(Enctype.AES128, kb)
    verify_checksum(Cksumtype.SHA1_AES128, k, keyusage, plain, cksum)

    # AES256 checksum
    kb = h("B1AE4CD8462AFF1677053CC9279AAC30B796FB81CE21474DD3DDBCFEA4EC76D7")
    keyusage = 4
    plain = "fourteen".encode()
    cksum = h("E08739E3279E2903EC8E3836")
    k = Key(Enctype.AES256, kb)
    verify_checksum(Cksumtype.SHA1_AES256, k, keyusage, plain, cksum)

    # AES128 string-to-key
    string = "password".encode()
    salt = "ATHENA.MIT.EDUraeburn".encode()
    params = h("00000002")
    kb = h("C651BF29E2300AC27FA469D693BDDA13")
    k = string_to_key(Enctype.AES128, string, salt, params)
    assert k.contents == kb

    # AES256 string-to-key
    string = b"X" * 64
    salt = "pass phrase equals block size".encode()
    params = h("000004B0")
    kb = h("89ADEE3608DB8BC71F1BFBFE459486B05618B70CBAE22092534E56C553BA4B34")
    k = string_to_key(Enctype.AES256, string, salt, params)
    assert k.contents == kb

    # AES128 prf
    kb = h("77B39A37A868920F2A51F9DD150C5717")
    k = string_to_key(Enctype.AES128, "key1".encode(), "key1".encode())
    assert prf(k, b"\x01\x61") == kb

    # AES256 prf
    kb = h("0D674DD0F9A6806525A4D92E828BD15A")
    k = string_to_key(Enctype.AES256, "key2".encode(), "key2".encode())
    assert prf(k, b"\x02\x62") == kb

    # AES128 cf2
    kb = h("97DF97E4B798B29EB31ED7280287A92A")
    k1 = string_to_key(Enctype.AES128, "key1".encode(), "key1".encode())
    k2 = string_to_key(Enctype.AES128, "key2".encode(), "key2".encode())
    k = cf2(Enctype.AES128, k1, k2, b"a", b"b")
    assert k.contents == kb

    # AES256 cf2
    kb = h("4D6CA4E629785C1F01BAF55E2E548566B9617AE3A96868C337CB93B5E72B1C7B")
    k1 = string_to_key(Enctype.AES256, "key1".encode(), "key1".encode())
    k2 = string_to_key(Enctype.AES256, "key2".encode(), "key2".encode())
    k = cf2(Enctype.AES256, k1, k2, b"a", b"b")
    assert k.contents == kb

    # DES3 encrypt and decrypt
    kb = h("0DD52094E0F41CECCB5BE510A764B35176E3981332F1E598")
    conf = h("94690A17B2DA3C9B")
    keyusage = 3
    plain = b"13 bytes byte"
    ctxt = h(
        "839A17081ECBAFBCDC91B88C6955DD3C4514023CF177B77BF0D0177A16F705E8"
        "49CB7781D76A316B193F8D30"
    )
    k = Key(Enctype.DES3, kb)
    assert encrypt(k, keyusage, plain, conf) == ctxt
    assert decrypt(k, keyusage, ctxt) == _zeropad(plain, 8)

    # DES3 string-to-key
    string = "password".encode()
    salt = "ATHENA.MIT.EDUraeburn".encode()
    kb = h("850BB51358548CD05E86768C313E3BFEF7511937DCF72C3E")
    k = string_to_key(Enctype.DES3, string, salt)
    assert k.contents == kb

    # DES3 checksum
    kb = h("7A25DF8992296DCEDA0E135BC4046E2375B3C14C98FBC162")
    keyusage = 2
    plain = "six seven".encode()
    cksum = h("0EEFC9C3E049AABC1BA5C401677D9AB699082BB4")
    k = Key(Enctype.DES3, kb)
    verify_checksum(Cksumtype.SHA1_DES3, k, keyusage, plain, cksum)

    # DES3 cf2
    kb = h("E58F9EB643862C13AD38E529313462A7F73E62834FE54A01")
    k1 = string_to_key(Enctype.DES3, "key1".encode(), "key1".encode())
    k2 = string_to_key(Enctype.DES3, "key2".encode(), "key2".encode())
    k = cf2(Enctype.DES3, k1, k2, b"a", b"b")
    assert k.contents == kb

    # RC4 encrypt and decrypt
    kb = h("68F263DB3FCE15D031C9EAB02D67107A")
    conf = h("37245E73A45FBF72")
    keyusage = 4
    plain = b"30 bytes bytes bytes bytes byt"
    ctxt = h(
        "95F9047C3AD75891C2E9B04B16566DC8B6EB9CE4231AFB2542EF87A7B5A0F260"
        "A99F0460508DE0CECC632D07C354124E46C5D2234EB8"
    )
    k = Key(Enctype.RC4, kb)
    assert encrypt(k, keyusage, plain, conf) == ctxt
    assert decrypt(k, keyusage, ctxt) == plain

    # RC4 string-to-key
    string = "foo".encode()
    kb = h("AC8E657F83DF82BEEA5D43BDAF7800CC")
    k = string_to_key(Enctype.RC4, string, None)
    assert k.contents == kb

    # RC4 checksum
    kb = h("F7D3A155AF5E238A0B7A871A96BA2AB2")
    keyusage = 6
    plain = "seventeen eighteen nineteen twenty".encode()
    cksum = h("EB38CC97E2230F59DA4117DC5859D7EC")
    k = Key(Enctype.RC4, kb)
    verify_checksum(Cksumtype.HMAC_MD5, k, keyusage, plain, cksum)

    # RC4 cf2
    kb = h("24D7F6B6BAE4E5C00D2082C5EBAB3672")
    k1 = string_to_key(Enctype.RC4, "key1".encode(), "key1".encode())
    k2 = string_to_key(Enctype.RC4, "key2".encode(), "key2".encode())
    k = cf2(Enctype.RC4, k1, k2, b"a", b"b")
    assert k.contents == kb

    # DES string-to-key
    string = "password".encode()
    salt = "ATHENA.MIT.EDUraeburn".encode()
    kb = h("cbc22fae235298e3")
    k = string_to_key(Enctype.DES_MD5, string, salt)
    assert k.contents == kb

    # DES string-to-key
    string = "potatoe".encode()
    salt = "WHITEHOUSE.GOVdanny".encode()
    kb = h("df3d32a74fd92a01")
    k = string_to_key(Enctype.DES_MD5, string, salt)
    assert k.contents == kb
    print("all tests passed!")
