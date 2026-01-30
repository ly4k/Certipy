import struct
from typing import Self

from .datatypes import MultiByteInt31, Utf8String
from .constants import DICTIONARY
from .record import record, Attribute


class ShortAttributeRecord(Attribute):
    type = 0x04

    def __init__(self, name: str, value: record):
        self.name = name
        self.value = value

    def to_bytes(self) -> bytes:
        """
        >>> ShortAttributeRecord('test', TrueTextRecord()).to_bytes()
        '\\x04\\x04test\\x86'
        """
        bytes = super(ShortAttributeRecord, self).to_bytes()
        bytes += Utf8String(self.name).to_bytes()
        bytes += self.value.to_bytes()

        return bytes

    def __str__(self):
        return '%s="%s"' % (self.name, str(self.value))

    @classmethod
    def parse(cls, fp) -> Self:
        name: str = Utf8String.parse(fp).value
        type: int = struct.unpack("<B", fp.read(1))[0]
        value: record = record.records[type].parse(fp)

        return cls(name, value)


class AttributeRecord(Attribute):
    type = 0x05

    def __init__(self, prefix: str, name: str, value: record):
        self.prefix = prefix
        self.name = name
        self.value = value

    def to_bytes(self) -> bytes:
        """
        >>> AttributeRecord('x', 'test', TrueTextRecord()).to_bytes()
        '\\x05\\x01x\\x04test\\x86'
        """
        bytes = super(AttributeRecord, self).to_bytes()
        bytes += Utf8String(self.prefix).to_bytes()
        bytes += Utf8String(self.name).to_bytes()
        bytes += self.value.to_bytes()

        return bytes

    def __str__(self):
        return '%s:%s="%s"' % (self.prefix, self.name, str(self.value))

    @classmethod
    def parse(cls, fp) -> Self:
        prefix: str = Utf8String.parse(fp).value
        name: str = Utf8String.parse(fp).value
        type: int = struct.unpack("<B", fp.read(1))[0]
        value: record = record.records[type].parse(fp)

        return cls(prefix, name, value)


class ShortDictionaryAttributeRecord(Attribute):
    type = 0x06

    def __init__(self, index: int, value: record):
        self.index = index
        self.value = value

    def to_bytes(self) -> bytes:
        """
        ''>>> ShortDictionaryAttributeRecord(3, TrueTextRecord()).to_bytes()
        '\\x06\\x03\\x86'
        """
        bytes = super(ShortDictionaryAttributeRecord, self).to_bytes()
        bytes += MultiByteInt31(self.index).to_bytes()
        bytes += self.value.to_bytes()

        return bytes

    def __str__(self):
        return '%s="%s"' % (DICTIONARY[self.index], str(self.value))

    @classmethod
    def parse(cls, fp) -> Self:
        index: int = MultiByteInt31.parse(fp).value
        type: int = struct.unpack("<B", fp.read(1))[0]
        value: record = record.records[type].parse(fp)

        return cls(index, value)


class DictionaryAttributeRecord(Attribute):
    type = 0x07

    def __init__(self, prefix: str, index: int, value: record):
        self.prefix = prefix
        self.index = index
        self.value = value

    def to_bytes(self) -> bytes:
        """
        >>> DictionaryAttributeRecord('x', 2, TrueTextRecord()).to_bytes()
        '\\x07\\x01x\\x02\\x86'
        """
        bytes = super(DictionaryAttributeRecord, self).to_bytes()
        bytes += Utf8String(self.prefix).to_bytes()
        bytes += MultiByteInt31(self.index).to_bytes()
        bytes += self.value.to_bytes()

        return bytes

    def __str__(self):
        return '%s:%s="%s"' % (self.prefix, DICTIONARY[self.index], str(self.value))

    @classmethod
    def parse(cls, fp) -> Self:
        prefix: str = Utf8String.parse(fp).value
        index: int = MultiByteInt31.parse(fp).value
        type: int = struct.unpack("<B", fp.read(1))[0]
        value: record = record.records[type].parse(fp)

        return cls(prefix, index, value)


class ShortDictionaryXmlnsAttributeRecord(Attribute):
    type = 0x0A

    def __init__(self, index: int):
        self.index = index

    def __str__(self):
        return 'xmlns="%s"' % (DICTIONARY[self.index],)

    def to_bytes(self) -> bytes:
        """
        >>> ShortDictionaryXmlnsAttributeRecord( 6).to_bytes()
        '\\n\\x06'
        """
        bytes = struct.pack("<B", self.type)
        bytes += MultiByteInt31(self.index).to_bytes()

        return bytes

    @classmethod
    def parse(cls, fp) -> Self:
        index: int = MultiByteInt31.parse(fp).value
        return cls(index)


class DictionaryXmlnsAttributeRecord(Attribute):
    type = 0x0B

    def __init__(self, prefix: str, index: int):
        self.prefix = prefix
        self.index = index

    def __str__(self):
        return 'xmlns:%s="%s"' % (self.prefix, DICTIONARY[self.index])

    def to_bytes(self) -> bytes:
        """
        >>> DictionaryXmlnsAttributeRecord('a', 6).to_bytes()
        '\\x0b\\x01\x61\\x06'
        """
        bytes = struct.pack("<B", self.type)
        bytes += Utf8String(self.prefix).to_bytes()
        bytes += MultiByteInt31(self.index).to_bytes()

        return bytes

    @classmethod
    def parse(cls, fp) -> Self:
        prefix: str = Utf8String.parse(fp).value
        index: int = MultiByteInt31.parse(fp).value
        return cls(prefix, index)


class ShortXmlnsAttributeRecord(Attribute):
    type = 0x08

    def __init__(self, value: str, *args, **kwargs):
        super(ShortXmlnsAttributeRecord, self).__init__(*args, **kwargs)
        self.value = value

    def to_bytes(self) -> bytes:
        bytes = struct.pack("<B", self.type)
        bytes += Utf8String(self.value).to_bytes()
        return bytes

    def __str__(self):
        return 'xmlns="%s"' % (self.value,)

    @classmethod
    def parse(cls, fp) -> Self:
        value: str = Utf8String.parse(fp).value
        return cls(value)


class XmlnsAttributeRecord(Attribute):
    type = 0x09

    def __init__(self, name: str, value: str, *args, **kwargs):
        super(XmlnsAttributeRecord, self).__init__(*args, **kwargs)
        self.name = name
        self.value = value

    def to_bytes(self) -> bytes:
        bytes = struct.pack("<B", self.type)
        bytes += Utf8String(self.name).to_bytes()
        bytes += Utf8String(self.value).to_bytes()
        return bytes

    def __str__(self):
        return 'xmlns:%s="%s"' % (self.name, self.value)

    @classmethod
    def parse(cls, fp) -> Self:
        name: str = Utf8String.parse(fp).value
        value: str = Utf8String.parse(fp).value
        return cls(name, value)


class PrefixAttributeRecord(AttributeRecord):
    def __init__(self, name: str, value: record):
        super(PrefixAttributeRecord, self).__init__(self.char, name, value)

    def to_bytes(self) -> bytes:
        string = Utf8String(self.name)
        return struct.pack("<B", self.type) + string.to_bytes() + self.value.to_bytes()

    @classmethod
    def parse(cls, fp) -> Self:
        name: str = Utf8String.parse(fp).value
        type: int = struct.unpack("<B", fp.read(1))[0]
        value: record = record.records[type].parse(fp)
        return cls(name, value)


class PrefixDictionaryAttributeRecord(DictionaryAttributeRecord):
    def __init__(self, index: int, value):
        super(PrefixDictionaryAttributeRecord, self).__init__(self.char, index, value)

        # TODO: what is self.char?

    def to_bytes(self) -> bytes:
        idx = MultiByteInt31(self.index)
        return struct.pack("<B", self.type) + idx.to_bytes() + self.value.to_bytes()

    @classmethod
    def parse(cls, fp) -> Self:
        index: int = MultiByteInt31.parse(fp).value
        type: int = struct.unpack("<B", fp.read(1))[0]
        value: record = record.records[type].parse(fp)
        return cls(index, value)


record.add_records(
    (
        ShortAttributeRecord,
        AttributeRecord,
        ShortDictionaryAttributeRecord,
        DictionaryAttributeRecord,
        ShortDictionaryXmlnsAttributeRecord,
        DictionaryXmlnsAttributeRecord,
        ShortXmlnsAttributeRecord,
        XmlnsAttributeRecord,
    )
)

__records__ = []

for c in range(0x0C, 0x25 + 1):
    char = chr(c - 0x0C + ord("a"))
    cls = type(
        "PrefixDictionaryAttribute" + char.upper() + "Record",
        (PrefixDictionaryAttributeRecord,),
        dict(
            type=c,
            char=char,
        ),
    )
    __records__.append(cls)

for c in range(0x26, 0x3F + 1):
    char = chr(c - 0x26 + ord("a"))
    cls = type(
        "PrefixAttribute" + char.upper() + "Record",
        (PrefixAttributeRecord,),
        dict(
            type=c,
            char=char,
        ),
    )
    __records__.append(cls)

record.add_records(__records__)
del __records__
