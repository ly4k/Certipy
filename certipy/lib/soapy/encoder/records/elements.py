import struct
from typing import Self

from .constants import DICTIONARY
from .datatypes import MultiByteInt31, Utf8String
from .record import Element, record


class ShortElementRecord(Element):
    type = 0x40

    def __init__(self, name: str, *args, **kwargs):
        self.childs = []
        self.name = name
        self.attributes = []

    def to_bytes(self) -> bytes:
        string = Utf8String(self.name)

        bytes = super(ShortElementRecord, self).to_bytes() + string.to_bytes()

        for attr in self.attributes:
            bytes += attr.to_bytes()
        return bytes

    def __str__(self):
        attributes_str = " ".join([str(a) for a in self.attributes])
        return f"<{self.name}{f' {attributes_str}' if attributes_str else ''}>"

    @classmethod
    def parse(cls, fp):
        name = Utf8String.parse(fp).value
        return cls(name)


class ElementRecord(ShortElementRecord):
    type = 0x41

    def __init__(self, prefix: str, name: str, *args, **kwargs):
        super(ElementRecord, self).__init__(name)
        self.prefix = prefix

    def to_bytes(self) -> bytes:
        pref = Utf8String(self.prefix)
        data = super(ElementRecord, self).to_bytes()
        type = data[0]
        return type.to_bytes() + pref.to_bytes() + data[1:]

    def __str__(self):
        attributes_str = " ".join([str(a) for a in self.attributes])
        return f"<{self.prefix}:{self.name}{f' {attributes_str}' if attributes_str else ''}>"

    @classmethod
    def parse(cls, fp):
        prefix = Utf8String.parse(fp).value
        name = Utf8String.parse(fp).value
        return cls(prefix, name)


class ShortDictionaryElementRecord(Element):
    type = 0x42

    def __init__(self, index: int, *args, **kwargs):
        self.childs = []
        self.index = index
        self.attributes = []
        self.name = DICTIONARY[self.index]

    def __str__(self):
        attributes_str = " ".join([str(a) for a in self.attributes])
        return f"<{self.name} {f' {attributes_str}' if attributes_str else ''}>"

    def to_bytes(self) -> bytes:
        string = MultiByteInt31(self.index)

        bytes = super(ShortDictionaryElementRecord, self).to_bytes() + string.to_bytes()

        for attr in self.attributes:
            bytes += attr.to_bytes()
        return bytes

    @classmethod
    def parse(cls, fp):
        index = MultiByteInt31.parse(fp).value
        return cls(index)


class DictionaryElementRecord(Element):
    type = 0x43

    def __init__(self, prefix: str, index: int, *args, **kwargs):
        self.childs = []
        self.prefix = prefix
        self.index = index
        self.attributes = []
        self.name = DICTIONARY[self.index]

    def __str__(self):
        attributes_str = " ".join(str(a) for a in self.attributes)
        return f"<{self.prefix}:{self.name}{' ' + attributes_str if attributes_str else ''}>"

    def to_bytes(self) -> bytes:
        pref = Utf8String(self.prefix)
        string = MultiByteInt31(self.index)

        bytes = (
            super(DictionaryElementRecord, self).to_bytes()
            + pref.to_bytes()
            + string.to_bytes()
        )

        for attr in self.attributes:
            bytes += attr.to_bytes()
        return bytes

    @classmethod
    def parse(cls, fp):
        prefix = Utf8String.parse(fp).value
        index = MultiByteInt31.parse(fp).value
        return cls(prefix, index)


class PrefixElementRecord(ElementRecord):
    def __init__(self, name: str):
        super(PrefixElementRecord, self).__init__(self.char, name)

    def to_bytes(self) -> bytes:
        string = Utf8String(self.name)

        bytes = struct.pack("<B", self.type) + string.to_bytes()

        for attr in self.attributes:
            bytes += attr.to_bytes()
        return bytes

    @classmethod
    def parse(cls, fp):
        name = Utf8String.parse(fp).value
        return cls(name)


class PrefixDictionaryElementRecord(DictionaryElementRecord):
    def __init__(self, index: int):
        super(PrefixDictionaryElementRecord, self).__init__(self.char, index)
        # TODO: what is self.char????

    def to_bytes(self) -> bytes:
        string = MultiByteInt31(self.index)

        bytes = struct.pack("<B", self.type) + string.to_bytes()

        for attr in self.attributes:
            bytes += attr.to_bytes()
        return bytes

    @classmethod
    def parse(cls, fp) -> Self:
        index: int = MultiByteInt31.parse(fp).value
        return cls(index)


record.add_records(
    (
        ShortElementRecord,
        ElementRecord,
        ShortDictionaryElementRecord,
        DictionaryElementRecord,
    )
)

__records__ = []

for c in range(0x44, 0x5D + 1):
    char = chr(c - 0x44 + ord("a"))
    cls = type(
        "PrefixDictionaryElement" + char.upper() + "Record",
        (PrefixDictionaryElementRecord,),
        dict(
            type=c,
            char=char,
        ),
    )
    __records__.append(cls)

for c in range(0x5E, 0x77 + 1):
    char = chr(c - 0x5E + ord("a"))
    cls = type(
        "PrefixElement" + char.upper() + "Record",
        (PrefixElementRecord,),
        dict(
            type=c,
            char=char,
        ),
    )
    __records__.append(cls)

record.add_records(__records__)
del __records__
