import logging
import struct

from typing import Self

log = logging.getLogger(__name__)


class MultiByteInt31(object):
    def __init__(self, value: int):
        self.value = value

    def to_bytes(self) -> bytes:
        MAXMBI = 0x7F

        if self.value < 0:
            raise ValueError("Signed numbers are not supported")

        if self.value <= MAXMBI:
            return bytes([self.value])

        result = []
        for _ in range(5):
            byte = self.value & MAXMBI
            self.value >>= 7
            if self.value != 0:
                byte |= MAXMBI + 1
            result.append(byte)

            if self.value == 0:
                break

        return bytes(result)

    def __str__(self):
        return str(self.value)

    @classmethod
    def parse(cls, fp) -> Self:
        # TODO: better error message needed when bytes value too large
        MAXMBI = 0x7F

        value = 0
        for i in range(5):
            v = struct.unpack("<B", fp.read(1))[0]
            value |= (v & MAXMBI) << 7 * i
            if not v & (MAXMBI + 1):
                break
        return cls(value)


class Utf8String(object):
    def __init__(self, value: str):
        self.value = value

    def to_bytes(self) -> bytes:
        data = self.value.encode("utf-8")
        strlen = len(data)
        return MultiByteInt31(strlen).to_bytes() + data

    def __str__(self):
        return self.value

    def __unicode__(self):
        return self.value

    @classmethod
    def parse(cls, fp) -> Self:
        lngth = struct.unpack("<B", fp.read(1))[0]
        return cls(fp.read(lngth).decode("utf8", errors="ignore"))


class Decimal(object):
    def __init__(self, sign, high, low, scale):
        if not 0 <= scale <= 28:
            raise ValueError("scale %d isn't between 0 and 28" % scale)
        self.sign = sign
        self.high = high
        self.low = low
        self.scale = scale

    def to_bytes(self) -> bytes:
        bytes = struct.pack("<H", 0)
        bytes += struct.pack("<B", self.scale)
        bytes += struct.pack("<B", 0x80 if self.sign else 0x00)
        bytes += struct.pack("<I", self.high)
        bytes += struct.pack("<Q", self.low)

        return bytes

    def __str__(self):
        value = str(self.high * 2**64 + self.low)
        if self.scale > 0:
            value = value[: -self.scale] + "." + value[-self.scale :]

        if self.sign:
            value = "-%s" % value
        return value

    @classmethod
    def parse(cls, fp) -> Self:
        fp.read(2)
        scale = struct.unpack("<B", fp.read(1))[0]
        sign = struct.unpack("<B", fp.read(1))[0] & 0x80
        high = struct.unpack("<I", fp.read(4))[0]
        low = struct.unpack("<Q", fp.read(8))[0]

        return cls(sign, high, low, scale)
