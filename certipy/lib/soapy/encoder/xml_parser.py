import base64
import logging as log
import re
from html import unescape
from html.parser import HTMLParser
from typing import TextIO

from .records import INVERTED_DICT
from .records.attributes import *
from .records.elements import *
from .records.record import *
from .records.text import *

classes = dict([(i.__name__, i) for i in record.records.values()])

int_reg = re.compile(r"^-?\d+$")
uint_reg = re.compile(r"^\d+$")
uuid_reg = re.compile(r"^(([a-fA-F0-9]{8})-(([a-fA-F0-9]{4})-){3}([a-fA-F0-9]{12}))$")
uniqueid_reg = re.compile(
    r"^urn:uuid:(([a-fA-F0-9]{8})-(([a-fA-F0-9]{4})-){3}([a-fA-F0-9]{12}))$"
)
base64_reg = re.compile(r"^[a-zA-Z0-9/+]*={0,2}$")
float_reg = re.compile(r"^-?(INF)|(NaN)|(\d+(\.\d+)?)$")

datetime_reg = re.compile(
    r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d{1,7})?)?(Z|(\+|-\d{2}:\d{2}))"
)

# https://github.com/python/cpython/blob/3.12/Lib/html/parser.py
tagfind_tolerant = re.compile(r"([a-zA-Z][^\t\n\r\f />\x00]*)(?:\s|/(?!>))*")
attrfind_tolerant = re.compile(
    r'((?<=[\'"\s/])[^\s/>][^\s/=>]*)(\s*=+\s*'
    r'(\'[^\']*\'|"[^"]*"|(?![\'"])[^>\s]*))?(?:\s|/(?!>))*'
)

endendtag = re.compile(">")
# the HTML 5 spec, section 8.1.2.2, doesn't allow spaces between
# </ and the tag name, so maybe this should be fixed
endtagfind = re.compile(r"</\s*([a-zA-Z][-.a-zA-Z0-9:_]*)\s*>")


# https://github.com/python/cpython/blob/main/Lib/_markupbase.py
_markedsectionclose = re.compile(r"]\s*]\s*>")
_msmarkedsectionclose = re.compile(r"]\s*>")


class XMLParser(HTMLParser):
    def reset(self):
        HTMLParser.reset(self)
        self.records = []
        self.last_record = record()
        self.last_record.childs = self.records
        self.last_record.parent = None
        self.data = None

    # ============ overrides to prevent lowercasing names ===============
    # this breaks standard and makes dictionary lookups hard

    # Internal -- handle starttag, return end or -1 if not terminated
    def parse_starttag(self, i):
        self.__starttag_text = None
        endpos = self.check_for_whole_start_tag(i)
        if endpos < 0:
            return endpos
        rawdata = self.rawdata
        self.__starttag_text = rawdata[i:endpos]

        # Now parse the data between i+1 and j into a tag and attrs
        attrs = []
        match = tagfind_tolerant.match(rawdata, i + 1)
        assert match, "unexpected call to parse_starttag()"
        k = match.end()
        self.lasttag = tag = match.group(1)
        while k < endpos:
            m = attrfind_tolerant.match(rawdata, k)
            if not m:
                break
            attrname, rest, attrvalue = m.group(1, 2, 3)
            if not rest:
                attrvalue = None
            elif (
                attrvalue[:1] == "'" == attrvalue[-1:]
                or attrvalue[:1] == '"' == attrvalue[-1:]
            ):
                attrvalue = attrvalue[1:-1]
            if attrvalue:
                attrvalue = unescape(attrvalue)
            attrs.append((attrname, attrvalue))
            k = m.end()

        end = rawdata[k:endpos].strip()
        if end not in (">", "/>"):
            self.handle_data(rawdata[i:endpos])
            return endpos
        if end.endswith("/>"):
            # XHTML-style empty tag: <span attr="value" />
            self.handle_startendtag(tag, attrs)
        else:
            self.handle_starttag(tag, attrs)
            if tag in self.CDATA_CONTENT_ELEMENTS:
                self.set_cdata_mode(tag)
        return endpos

    # Internal -- parse endtag, return end or -1 if incomplete
    def parse_endtag(self, i):
        rawdata = self.rawdata
        assert rawdata[i : i + 2] == "</", "unexpected call to parse_endtag"
        match = endendtag.search(rawdata, i + 1)  # >
        if not match:
            return -1
        gtpos = match.end()
        match = endtagfind.match(rawdata, i)  # </ + tag + >
        if not match:
            if self.cdata_elem is not None:
                self.handle_data(rawdata[i:gtpos])
                return gtpos
            # find the name: w3.org/TR/html5/tokenization.html#tag-name-state
            namematch = tagfind_tolerant.match(rawdata, i + 2)
            if not namematch:
                # w3.org/TR/html5/tokenization.html#end-tag-open-state
                if rawdata[i : i + 3] == "</>":
                    return i + 3
                else:
                    return self.parse_bogus_comment(i)
            tagname = namematch.group(1)
            # consume and ignore other stuff between the name and the >
            # Note: this is not 100% correct, since we might have things like
            # </tag attr=">">, but looking for > after the name should cover
            # most of the cases and is much simpler
            gtpos = rawdata.find(">", namematch.end())
            self.handle_endtag(tagname)
            return gtpos + 1

        elem = match.group(1)  # script or style
        if self.cdata_elem is not None:
            if elem != self.cdata_elem:
                self.handle_data(rawdata[i:gtpos])
                return gtpos

        self.handle_endtag(elem)
        self.clear_cdata_mode()
        return gtpos

    def set_cdata_mode(self, elem):
        self.cdata_elem = elem.lower()
        self.interesting = re.compile(r"</\s*%s\s*>" % self.cdata_elem, re.I)

    # ============= end overrides =================

    def _parse_tag(self, tag: str) -> record:
        if ":" in tag:
            prefix, name = tag.split(":", 1)

            if len(prefix) == 1:
                cls_name = "Element" + prefix.upper() + "Record"
                if name in INVERTED_DICT:
                    cls_name = "PrefixDictionary" + cls_name
                    log.debug("New %s: %s" % (cls_name, name))
                    return classes[cls_name](INVERTED_DICT[name])
                else:
                    cls_name = "Prefix" + cls_name
                    log.debug("New %s: %s" % (cls_name, name))
                    return classes[cls_name](name)
            else:
                if name in INVERTED_DICT:
                    log.debug("New DictionaryElementRecord: %s:%s" % (prefix, name))
                    return DictionaryElementRecord(prefix, INVERTED_DICT[name])
                else:
                    log.debug("New ElementRecord: %s:%s" % (prefix, name))
                    return ElementRecord(prefix, name)
        else:
            if tag in INVERTED_DICT:
                log.debug("New ShortDictionaryElementRecord: %s" % (tag,))
                return ShortDictionaryElementRecord(INVERTED_DICT[tag])
            else:
                log.debug("New ShortElementRecord: %s" % (tag,))
                return ShortElementRecord(tag)

    def _store_data(self, data, end=False):
        textrecord = self._parse_data(data)
        if isinstance(textrecord, EmptyTextRecord):
            return
        log.debug("New %s: %s" % (type(textrecord).__name__, data))

        self.last_record.childs.append(textrecord)

    def _parse_data(self, data):
        data = data.strip() if data else data
        b64 = False
        try:
            if base64_reg.match(data):
                base64.b64decode(data)
                b64 = True
        except:
            b64 = False
        if data == "0":
            return ZeroTextRecord()
        elif data == "1":
            return OneTextRecord()
        elif data.lower() == "false":
            return FalseTextRecord()
        elif data.lower() == "true":
            return TrueTextRecord()
        elif len(data) > 3 and data[1] == ":" and data[2:] in INVERTED_DICT:
            return QNameDictionaryTextRecord(data[0], INVERTED_DICT[data[2:]])
        elif uniqueid_reg.match(data):
            m = uniqueid_reg.match(data)
            return UniqueIdTextRecord(m.group(1))
        elif uuid_reg.match(data):
            m = uuid_reg.match(data)
            return UuidTextRecord(m.group(1))
        elif int_reg.match(data):
            val = int(data)
            if val >= -(2**7) and val <= 2**7 - 1:
                return Int8TextRecord(val)
            elif val >= -(2**15) and val <= 2**15 - 1:
                return Int16TextRecord(val)
            elif val >= -(2**31) and val <= 2**31 - 1:
                return Int32TextRecord(val)
            elif val >= -(2**63) and val <= 2**63 - 1:
                return Int64TextRecord(val)
            else:
                val = len(data)
                if val < 2**8:
                    return Chars8TextRecord(data)
                elif val < 2**16:
                    return Chars16TextRecord(data)
                elif val < 2**32:
                    return Chars32TextRecord(data)
        elif data == "":
            return EmptyTextRecord()
        elif b64:
            data = base64.b64decode(data)
            val = len(data)
            if val < 2**8:
                return Bytes8TextRecord(data)
            elif val < 2**16:
                return Bytes16TextRecord(data)
            elif val < 2**32:
                return Bytes32TextRecord(data)
        elif float_reg.match(data):
            return DoubleTextRecord(float(data))
        elif data in INVERTED_DICT:
            return DictionaryTextRecord(INVERTED_DICT[data])
        elif datetime_reg.match(data) and False:  # TODO
            raise NotImplementedError("datetime isnt implmented rn")
        else:
            val = len(data)
            if val < 2**8:
                return Chars8TextRecord(data)
            elif val < 2**16:
                return Chars16TextRecord(data)
            elif val < 2**32:
                return Chars32TextRecord(data)

    def _parse_attr(self, name, value):
        if ":" in name:
            prefix = name[: name.find(":")]
            name = name[name.find(":") + 1 :]

            if prefix == "xmlns":
                if value in INVERTED_DICT:
                    return DictionaryXmlnsAttributeRecord(name, INVERTED_DICT[value])
                else:
                    return XmlnsAttributeRecord(name, value)
            elif len(prefix) == 1:
                value = self._parse_data(value)
                cls_name = "Attribute" + prefix.upper() + "Record"
                if name in INVERTED_DICT:
                    return classes["PrefixDictionary" + cls_name](
                        INVERTED_DICT[name], value
                    )
                else:
                    return classes["Prefix" + cls_name](name, value)
            else:
                value = self._parse_data(value)
                if name in INVERTED_DICT:
                    return DictionaryAttributeRecord(prefix, INVERTED_DICT[name], value)
                else:
                    return AttributeRecord(prefix, name, value)
        elif name == "xmlns":
            if value in INVERTED_DICT:
                return ShortDictionaryXmlnsAttributeRecord(INVERTED_DICT[value])
            else:
                return ShortXmlnsAttributeRecord(value)
        else:
            value = self._parse_data(value)
            if name in INVERTED_DICT:
                return ShortDictionaryAttributeRecord(INVERTED_DICT[name], value)
            else:
                return ShortAttributeRecord(name, value)

    def handle_starttag(self, tag: str, attrs):
        if self.data:
            self._store_data(self.data, False)
            self.data = None

        el = self._parse_tag(tag)
        for n, v in attrs:
            el.attributes.append(self._parse_attr(n, v))
        self.last_record.childs.append(el)
        el.parent = self.last_record
        self.last_record = el

    def handle_startendtag(self, tag: str, attrs: list):
        if self.data:
            self._store_data(self.data, False)
            self.data = None

        el = self._parse_tag(tag)
        for n, v in attrs:
            el.attributes.append(self._parse_attr(n, v))
        self.last_record.childs.append(el)

    def handle_endtag(self, tag: str):
        if self.data:
            self._store_data(self.data, True)
            self.data = None
        self.last_record = self.last_record.parent

    def handle_data(self, data):
        if not self.data:
            self.data = data
        else:
            self.data += data

    def handle_charref(self, name):
        if name[0] == "x":
            self.handle_data(chr(int(name[1:], 16)))
        else:
            self.handle_data(chr(int(name, 10)))

    def handle_entityref(self, name):
        self.handle_data(unescape("&%s;" % name))

    def handle_comment(self, data):
        if self.data:
            self._store_data(self.data, False)
            self.data = None

        self.last_record.childs.append(CommentRecord(data))

    def parse_marked_section(self, i, report=1):
        rawdata = self.rawdata
        assert rawdata[i : i + 3] == "<![", "unexpected call to parse_marked_section()"
        sectName, j = self._scan_name(i + 3, i)
        if j < 0:
            return j

        match = None
        if sectName in ("temp", "cdata", "ignore", "include", "rcdata"):
            # look for standard ]]> ending
            match = _markedsectionclose.search(rawdata, i + 3)
        elif sectName in ("if", "else", "endif"):
            # look for MS Office ]> ending
            match = _msmarkedsectionclose.search(rawdata, i + 3)
        else:
            log.error(
                "unknown status keyword %r in marked section" % rawdata[i + 3 : j]
            )

        if not match:
            return -1
        if report:
            if sectName == "cdata":
                assert rawdata[j] == "["
                self.handle_data(rawdata[j + 1 : match.start(0)])
            else:
                j = match.start(0)
                self.unknown_decl(rawdata[i + 3 : j])
        return match.end(0)

    @classmethod
    def parse(cls, data: str | TextIO):
        """
        Parses a XML String/Fileobject into a Record tree

        Args:
            data(str | TextIO): a Record tree
        """
        p = cls()
        xml = None
        if isinstance(data, str):
            xml = data
        elif hasattr(data, "read"):
            xml = data.read()
        else:
            raise ValueError("%s has an incompatible type %s" % (data, type(data)))

        p.feed(xml)

        return p.records
