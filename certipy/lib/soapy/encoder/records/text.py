import base64
import datetime
import struct
from html.entities import codepoint2name
from typing import Self

from .constants import DICTIONARY
from .datatypes import Decimal, MultiByteInt31
from .record import record


class Text(record): ...


class ZeroTextRecord(Text):
    type = 0x80

    def __str__(self):
        return "0"

    @classmethod
    def parse(cls, fp) -> Self:
        return cls()


class OneTextRecord(Text):
    type = 0x82

    def __str__(self):
        return "1"

    @classmethod
    def parse(cls, fp) -> Self:
        return cls()


class FalseTextRecord(Text):
    type = 0x84

    def __str__(self):
        return "false"

    @classmethod
    def parse(cls, fp) -> Self:
        return cls()


class TrueTextRecord(Text):
    type = 0x86

    def __str__(self):
        return "true"

    @classmethod
    def parse(cls, fp) -> Self:
        return cls()


class Int8TextRecord(Text):
    type = 0x88

    def __init__(self, value):
        self.value = value

    def to_bytes(self) -> bytes:
        return super(Int8TextRecord, self).to_bytes() + struct.pack("<b", self.value)

    def __str__(self):
        return str(self.value)

    @classmethod
    def parse(cls, fp) -> Self:
        return cls(struct.unpack("<b", fp.read(1))[0])


class Int16TextRecord(Int8TextRecord):
    type = 0x8A

    def to_bytes(self) -> bytes:
        # print self.value
        return struct.pack("<B", self.type) + struct.pack("<h", self.value)

    @classmethod
    def parse(cls, fp) -> Self:
        return cls(struct.unpack("<h", fp.read(2))[0])


class Int32TextRecord(Int8TextRecord):
    type = 0x8C

    def to_bytes(self) -> bytes:
        return struct.pack("<B", self.type) + struct.pack("<i", self.value)

    @classmethod
    def parse(cls, fp) -> Self:
        return cls(struct.unpack("<i", fp.read(4))[0])


class Int64TextRecord(Int8TextRecord):
    type = 0x8E

    def to_bytes(self) -> bytes:
        return struct.pack("<B", self.type) + struct.pack("<q", self.value)

    @classmethod
    def parse(cls, fp) -> Self:
        return cls(struct.unpack("<q", fp.read(8))[0])


class UInt64TextRecord(Int64TextRecord):
    type = 0xB2

    def to_bytes(self) -> bytes:
        return struct.pack("<B", self.type) + struct.pack("<Q", self.value)

    @classmethod
    def parse(cls, fp) -> Self:
        return cls(struct.unpack("<Q", fp.read(8))[0])


class BoolTextRecord(Text):
    type = 0xB4

    def __init__(self, value):
        self.value = value

    def to_bytes(self) -> bytes:
        return struct.pack("<B", self.type) + struct.pack("<B", 1 if self.value else 0)

    def __str__(self):
        return str(self.value)

    @classmethod
    def parse(cls, fp) -> Self:
        value = True if struct.unpack("<B", fp.read(1))[0] == 1 else False
        return cls(value)


class UnicodeChars8TextRecord(Text):
    type = 0xB6

    def __init__(self, string):
        self.value = string

    def to_bytes(self) -> bytes:
        data = self.value.encode("utf-16")[2:]  # skip bom
        bytes = struct.pack("<B", self.type)
        bytes += struct.pack("<B", len(data))
        bytes += data
        return bytes

    def __str__(self):
        return self.value

    @classmethod
    def parse(cls, fp) -> Self:
        ln: int = struct.unpack("<B", fp.read(1))[0]
        data: bytes = fp.read(ln)
        return cls(data.decode("utf-16"))


class UnicodeChars16TextRecord(UnicodeChars8TextRecord):
    type = 0xB8

    def to_bytes(self) -> bytes:
        data = self.value.encode("utf-16")[2:]  # skip bom
        bytes = struct.pack("<B", self.type)
        bytes += struct.pack("<H", len(data))
        bytes += data
        return bytes

    def __str__(self):
        return self.value

    @classmethod
    def parse(cls, fp) -> Self:
        ln: int = struct.unpack("<H", fp.read(2))[0]
        data: bytes = fp.read(ln)
        return cls(data.decode("utf-16"))


class UnicodeChars32TextRecord(UnicodeChars8TextRecord):
    type = 0xBA

    def to_bytes(self) -> bytes:
        data = self.value.encode("utf-16")[2:]  # skip bom
        bytes = struct.pack("<B", self.type)
        bytes += struct.pack("<I", len(data))
        bytes += data
        return bytes

    def __str__(self):
        return self.value

    @classmethod
    def parse(cls, fp) -> Self:
        ln: int = struct.unpack("<I", fp.read(4))[0]
        data: bytes = fp.read(ln)
        return cls(data.decode("utf-16"))


class QNameDictionaryTextRecord(Text):
    type = 0xBC

    def __init__(self, prefix, index):
        self.prefix = prefix
        self.index = index

    def to_bytes(self):
        bytes = struct.pack("<B", self.type)
        bytes += struct.pack("<B", ord(self.prefix) - ord("a"))
        bytes += MultiByteInt31(self.index).to_bytes()
        return bytes

    def __str__(self):
        return "%s:%s" % (self.prefix, DICTIONARY[self.index])

    @classmethod
    def parse(cls, fp) -> Self:
        prefix = chr(struct.unpack("<B", fp.read(1))[0] + ord("a"))
        index = MultiByteInt31.parse(fp).value
        return cls(prefix, index)


class FloatTextRecord(Text):
    type = 0x90

    def __init__(self, value):
        self.value: float = value

    def to_bytes(self) -> bytes:
        bytes = super(FloatTextRecord, self).to_bytes()
        bytes += struct.pack("<f", self.value)
        return bytes

    def __str__(self):
        try:
            if self.value == int(self.value):
                return "%.0f" % self.value
            else:
                return str(self.value)
        except:
            return str(self.value).upper()

    @classmethod
    def parse(cls, fp) -> Self:
        value = struct.unpack("<f", fp.read(4))[0]
        return cls(value)


class DoubleTextRecord(FloatTextRecord):
    type = 0x92

    def __init__(self, value: float):
        self.value = value

    def to_bytes(self) -> bytes:
        bytes = super(FloatTextRecord, self).to_bytes()
        bytes += struct.pack("<d", self.value)
        return bytes

    def __str__(self):
        return super(DoubleTextRecord, self).__str__()

    @classmethod
    def parse(cls, fp) -> Self:
        value = struct.unpack("<d", fp.read(8))[0]
        return cls(value)


class DecimalTextRecord(Text):
    type = 0x94

    def __init__(self, value: Decimal):
        self.value = value

    def __str__(self):
        return str(self.value)

    def to_bytes(self) -> bytes:
        return super(DecimalTextRecord, self).to_bytes() + self.value.to_bytes()

    @classmethod
    def parse(cls, fp) -> Self:
        value = Decimal.parse(fp)
        return cls(value)


class DatetimeTextRecord(Text):
    type = 0x96

    def __init__(self, value: int, tz: int):
        self.value = value
        self.tz = tz

    def __str__(self):
        ticks = self.value
        dt = datetime.datetime(1, 1, 1) + datetime.timedelta(microseconds=ticks / 10)
        return dt.isoformat()

    def to_bytes(self) -> bytes:
        bytes = super(DatetimeTextRecord, self).to_bytes()
        bytes += struct.pack(
            "<Q", (self.tz & 3) | (self.value & 0x1FFFFFFFFFFFFFFF) << 2
        )

        return bytes

    @classmethod
    def parse(cls, fp) -> Self:
        data = struct.unpack("<Q", fp.read(8))[0]
        tz = data & 3
        value = data
        return cls(value, tz)


def escapecp(cp):
    return "&%s;" % codepoint2name[cp] if (cp in codepoint2name) else chr(cp)


def escape(text):
    newtext = ""
    for c in text:
        newtext += escapecp(ord(c))
    return newtext


class Chars8TextRecord(Text):
    type = 0x98

    def __init__(self, value: str):
        self.value = value

    def __str__(self):
        # TODO:  check if having unexcaped value is a problem?
        # removed the return excape(self.value) because str() was used
        # in the print_records function, so it printed stuff like
        # amp(value) and stuff.
        return self.value

    def to_bytes(self) -> bytes:
        data = self.value.encode("utf-8")
        bytes = struct.pack("<B", self.type)
        bytes += struct.pack("<B", len(data))
        bytes += data

        return bytes

    @classmethod
    def parse(cls, fp) -> Self:
        ln = struct.unpack("<B", fp.read(1))[0]
        value: str = fp.read(ln).decode("utf-8")
        return cls(value)


class Chars16TextRecord(Text):
    type = 0x9A

    def __init__(self, value: str):
        self.value = value

    def __str__(self):
        return self.value

    def to_bytes(self) -> bytes:
        data = self.value.encode("utf-8")
        bytes = struct.pack("<B", self.type)
        bytes += struct.pack("<H", len(data))
        bytes += data

        return bytes

    @classmethod
    def parse(cls, fp) -> Self:
        ln = struct.unpack("<H", fp.read(2))[0]
        value: str = fp.read(ln).decode("utf-8")
        return cls(value)


class Chars32TextRecord(Text):
    type = 0x9C

    def __init__(self, value: str):
        self.value = value

    def __str__(self):
        return self.value

    def to_bytes(self) -> bytes:
        data = self.value.encode("utf-8")
        bytes = struct.pack("<B", self.type)
        bytes += struct.pack("<I", len(data))
        bytes += data

        return bytes

    @classmethod
    def parse(cls, fp) -> Self:
        ln = struct.unpack("<I", fp.read(4))[0]
        value: str = fp.read(ln).decode("utf-8")
        return cls(value)


class UniqueIdTextRecord(Text):
    type = 0xAC

    def __init__(self, uuid):
        if isinstance(uuid, list) or isinstance(uuid, tuple):
            self.uuid = uuid
        else:
            if uuid.startswith("urn:uuid"):
                uuid = uuid[9:]
            uuid = uuid.split("-")
            tmp = uuid[0:3]
            tmp.append(uuid[3][0:2])
            tmp.append(uuid[3][2:])
            tmp.append(uuid[4][0:2])
            tmp.append(uuid[4][2:4])
            tmp.append(uuid[4][4:6])
            tmp.append(uuid[4][6:8])
            tmp.append(uuid[4][8:10])
            tmp.append(uuid[4][10:])

            self.uuid = [int(s, 16) for s in tmp]

    def to_bytes(self) -> bytes:
        bytes = super(UniqueIdTextRecord, self).to_bytes()
        bytes += struct.pack("<IHHBBBBBBBB", *self.uuid)

        return bytes

    def __str__(self):
        return "urn:uuid:%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" % (
            tuple(self.uuid)
        )

    @classmethod
    def parse(cls, fp) -> Self:
        uuid = struct.unpack("<IHHBBBBBBBB", fp.read(16))
        return cls(uuid)


class UuidTextRecord(UniqueIdTextRecord):
    type = 0xB0

    def __str__(self):
        return "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" % (tuple(self.uuid))


class Bytes8TextRecord(Text):
    type = 0x9E

    def __init__(self, data: bytes):
        self.value = data

    def to_bytes(self) -> bytes:
        bytes = struct.pack("<B", self.type)
        bytes += struct.pack("<B", len(self.value))
        bytes += self.value

        return bytes

    def __str__(self):
        return base64.b64encode(self.value).decode()

    @classmethod
    def parse(cls, fp) -> Self:
        ln = struct.unpack("<B", fp.read(1))[0]
        data: bytes = struct.unpack("%ds" % ln, fp.read(ln))[0]
        return cls(data)


class Bytes16TextRecord(Text):
    type = 0xA0

    def __init__(self, data: bytes):
        self.value = data

    def __str__(self):
        return base64.b64encode(self.value).decode()

    def to_bytes(self) -> bytes:
        bytes = struct.pack("<B", self.type)
        bytes += struct.pack("<H", len(self.value))
        bytes += self.value

        return bytes

    @classmethod
    def parse(cls, fp) -> Self:
        ln = struct.unpack("<H", fp.read(2))[0]
        data: bytes = struct.unpack("%ds" % ln, fp.read(ln))[0]
        return cls(data)


class Bytes32TextRecord(Text):
    type = 0xA2

    def __init__(self, data: bytes):
        self.value = data

    def __str__(self):
        return base64.b64encode(self.value).decode()

    def to_bytes(self) -> bytes:
        bytes = struct.pack("<B", self.type)
        bytes += struct.pack("<I", len(self.value))
        bytes += self.value

        return bytes

    @classmethod
    def parse(cls, fp) -> Self:
        ln = struct.unpack("<I", fp.read(4))[0]
        data: bytes = struct.unpack("%ds" % ln, fp.read(ln))[0]
        return cls(data)


class StartListTextRecord(Text):
    type = 0xA4


class EndListTextRecord(Text):
    type = 0xA6


class EmptyTextRecord(Text):
    type = 0xA8


class TimeSpanTextRecord(Text):
    type = 0xAE

    def __init__(self, value):
        self.value = value

    def to_bytes(self) -> bytes:
        return super(TimeSpanTextRecord, self).to_bytes() + struct.pack(
            "<q", self.value
        )

    def __str__(self):
        return str(datetime.timedelta(microseconds=self.value / 10))

    @classmethod
    def parse(cls, fp) -> Self:
        value = struct.unpack("<q", fp.read(8))[0]
        return cls(value)


class DictionaryTextRecord(Text):
    type = 0xAA

    def __init__(self, index):
        self.index = index

    def to_bytes(self) -> bytes:
        return (
            super(DictionaryTextRecord, self).to_bytes()
            + MultiByteInt31(self.index).to_bytes()
        )

    def __str__(self):
        return DICTIONARY[self.index]

    @classmethod
    def parse(cls, fp) -> Self:
        index = MultiByteInt31.parse(fp).value
        return cls(index)


record.add_records(
    (
        ZeroTextRecord,
        OneTextRecord,
        FalseTextRecord,
        TrueTextRecord,
        Int8TextRecord,
        Int16TextRecord,
        Int32TextRecord,
        Int64TextRecord,
        UInt64TextRecord,
        BoolTextRecord,
        UnicodeChars8TextRecord,
        UnicodeChars16TextRecord,
        UnicodeChars32TextRecord,
        QNameDictionaryTextRecord,
        FloatTextRecord,
        DoubleTextRecord,
        DecimalTextRecord,
        DatetimeTextRecord,
        Chars8TextRecord,
        Chars16TextRecord,
        Chars32TextRecord,
        UniqueIdTextRecord,
        UuidTextRecord,
        Bytes8TextRecord,
        Bytes16TextRecord,
        Bytes32TextRecord,
        StartListTextRecord,
        EndListTextRecord,
        EmptyTextRecord,
        TimeSpanTextRecord,
        DictionaryTextRecord,
    )
)
