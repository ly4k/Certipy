import logging as log

from .record import Element, EndElementRecord, record
from .text import Text


def print_records(records, first_call=True) -> str:
    """
    returns the given record tree as a string
    """

    if not records:
        return ""

    output = ""
    for r in records:
        if isinstance(r, EndElementRecord):
            continue

        output += str(r)
        new_line = ""
        if hasattr(r, "childs"):
            new_line = print_records(r.childs, False)
        if isinstance(r, Element):
            output += new_line
            if hasattr(r, "prefix"):
                output += "</%s:%s>" % (r.prefix, r.name)
            else:
                output += "</%s>" % r.name
    return output


def pretty_print_records(records, skip=0, first_call=True) -> str:
    """prints the given record tree into a file like object"""

    if not records:
        return ""

    output = ""
    for r in records:
        if isinstance(r, EndElementRecord):
            continue
        if isinstance(r, Element):
            output += str(r)
        else:
            output += str(r)

        new_line = ""
        if hasattr(r, "childs"):
            new_line = pretty_print_records(r.childs, skip + 1, False)
        if isinstance(r, Element):
            output += new_line
            if new_line:
                output += "\r\n" + " " * skip
            if hasattr(r, "prefix"):
                output += "</%s:%s>" % (r.prefix, r.name)
            else:
                output += "</%s>" % r.name
    return output


def dump_records(records: list[record]) -> bytes:
    """
    returns the byte representation of a given record tree

    """
    out = b""

    for r in records:
        msg = f"Write {type(r).__name__}"

        if r == records[-1] and isinstance(r, Text):
            r.type = r.type + 1
            msg += " with EndElement (0x%X)" % r.type
        log.debug(msg)
        log.debug(f"Value {r}")

        if (
            isinstance(r, Element)
            and not isinstance(r, EndElementRecord)
            and len(r.attributes)
        ):
            log.debug(" Attributes:")
            for a in r.attributes:
                log.debug(f" {type(a).__name__}: {a}")

        out += r.to_bytes()

        if hasattr(r, "childs"):
            out += dump_records(r.childs)

            # only print the end element if the current record is NOT a "*WithEnd" record type
            if (not r.childs or not isinstance(r.childs[-1], Text)) and not isinstance(
                r, Text
            ):
                log.debug(f"Write EndElement for {type(r).__name__}")
                out += EndElementRecord().to_bytes()

        elif isinstance(r, Element) and not isinstance(r, EndElementRecord):
            log.debug(f"Write EndElement for {type(r).__name__}")
            out += EndElementRecord().to_bytes()

    return out


class Net7BitInteger(object):
    @staticmethod
    def decode7bit(data: bytes) -> tuple[int, int]:
        MAXMBI = 0x7F

        length = 0
        value = 0
        for i in range(5):
            length += 1
            v = data[i]
            value |= (v & MAXMBI) << 7 * i
            if not v & (MAXMBI + 1):
                break
        return value, length

    @staticmethod
    def encode7bit(value):
        MAXMBI = 0x7F
        if value < 0:
            raise ValueError("Signed numbers are not supported")

        if value <= MAXMBI:
            return bytes([value])

        result = []
        for _ in range(5):
            byte = value & MAXMBI
            value >>= 7
            if value != 0:
                byte |= MAXMBI + 1
            result.append(byte)

            if value == 0:
                break

        return bytes(result)
