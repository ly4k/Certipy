import struct

from typing import Self, Type

import logging as log

from .datatypes import MultiByteInt31, Utf8String


class record:
    records: dict[int, Type[Self]] = dict()

    @classmethod
    def add_records(cls, records):
        """adds records to the lookup table

        Args:
            records (list[record]): list of record subclasses
        """
        for r in records:
            record.records[r.type] = r

    def __init__(self, type=None):
        if type:
            self.type = type

        self.childs = []
        self.parent = None

    def to_bytes(self):
        """
        Generates the representing bytes of the record

        """
        return struct.pack("<B", self.type)

    def __repr__(self):
        args = ["type=0x%X" % self.type]
        return "<%s(%s)>" % (type(self).__name__, ",".join(args))

    @classmethod
    def parse(cls, fp) -> list[Self] | Self:
        """
        Parses the binary data from fp into record objects

        Args:
            fp: file like object to read from
        Returns:
            (record): a root record object with its child records
        """
        if cls != record:
            return cls()  # TODO: this might need to be removed from list
        root = []
        records = root
        parents = []
        last_el = None

        while True:
            # Gate the parsing.  When there is no more
            # to read, return the current parsed data
            type_byte: bytes = fp.read(1)
            if not type_byte:
                return root

            type: int = struct.unpack("<B", type_byte)[0]

            if type in record.records:
                log.debug("%s found" % record.records[type].__name__)

                obj = record.records[type].parse(fp)

                if isinstance(obj, EndElementRecord):
                    if parents:
                        records = parents.pop()

                elif isinstance(obj, Element):
                    last_el = obj
                    records.append(obj)
                    parents.append(records)
                    obj.childs = []
                    records = obj.childs

                elif isinstance(obj, Attribute) and last_el:
                    last_el.attributes.append(obj)

                else:
                    records.append(obj)

                log.debug("Value: %s" % str(obj))

            # if the type isnt already in the declared types,
            # then it is a '*WithEnd' type record
            elif type - 1 in record.records:
                log.debug(
                    "%s with end element found (0x%x)"
                    % (record.records[type - 1].__name__, type)
                )
                records.append(record.records[type - 1].parse(fp))
                last_el = None

                if parents:
                    records = parents.pop()
            else:
                log.warn("type 0x%x not found" % type)

        return root


class Element(record): ...


class EndElementRecord(Element):
    type = 0x01


class Attribute(record): ...


class CommentRecord(record):
    type = 0x02

    def __init__(self, comment: str, *args, **kwargs):
        super(CommentRecord, self).__init__()
        self.comment = comment

    def to_bytes(self) -> bytes:
        string = Utf8String(self.comment)

        return super(CommentRecord, self).to_bytes() + string.to_bytes()

    def __str__(self):
        return "<!-- %s -->" % self.comment

    @classmethod
    def parse(cls, fp) -> Self:
        data: str = Utf8String.parse(fp).value
        return cls(data)


class ArrayRecord(record):
    type = 0x03

    # note, these are NOT the same thing as like a ZeroTextWithEndElement
    # see [MC-NBFX]: 2.2.3.31
    datatypes: dict[int, tuple[str, int, str]] = {
        0xB5: ("BoolTextWithEndElement", 1, "?"),
        0x8B: ("Int16TextWithEndElement", 2, "h"),
        0x8D: ("Int32TextWithEndElement", 4, "i"),
        0x8F: ("Int64TextWithEndElement", 8, "q"),
        0x91: ("FloatTextWithEndElement", 4, "f"),
        0x93: ("DoubleTextWithEndElement", 8, "d"),
        0x95: ("DecimalTextWithEndElement", 16, ""),
        0x97: ("DateTimeTextWithEndElement", 8, ""),
        0xAF: ("TimeSpanTextWithEndElement", 8, ""),
        0xB1: ("UuidTextWithEndElement", 16, ""),
    }

    def __init__(self, element, recordtype, data):
        super(ArrayRecord, self).__init__()
        self.element = element
        self.recordtype = recordtype
        self.count = len(data)
        self.data = data

    def to_bytes(self) -> bytes:
        bytes = super(ArrayRecord, self).to_bytes()
        bytes += self.element.to_bytes()
        bytes += EndElementRecord().to_bytes()
        bytes += struct.pack("<B", self.recordtype)[0]
        bytes += MultiByteInt31(self.count).to_bytes()
        for data in self.data:
            if type(data) == str:
                bytes += data
            else:
                bytes += data.to_bytes()
        return bytes

    @classmethod
    def parse(cls, fp) -> Self:
        element_type = struct.unpack("<B", fp.read(1))[0]
        element = cls.records[element_type].parse(fp)
        element_end = fp.read(1)
        while element_end != b"\x01":
            element_end = fp.read(1)
        recordtype = struct.unpack("<B", fp.read(1))[0]
        count = MultiByteInt31.parse(fp).value
        data = []
        for i in range(count):
            data.append(cls.records[recordtype - 1].parse(fp))
        return cls(element, recordtype, data)

    def __str__(self):
        string = ""
        for data in self.data:
            string += str(self.element)
            string += str(data)
            string += "</%s>" % self.element.name

        return string


record.add_records(
    (
        EndElementRecord,
        CommentRecord,
        ArrayRecord,
    )
)
