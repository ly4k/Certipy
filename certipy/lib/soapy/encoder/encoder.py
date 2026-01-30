from io import BytesIO

from .records import Net7BitInteger, record, dump_records, print_records
from .xml_parser import XMLParser


class Encoder:
    """Preforms encoding and decoding on xml data.

    Compliant with [MC-NBFX] and known extentions.

    Supports known encoding types:

        [MC-NBFS]
        [MC-NBFSE]
    """

    def __init__(self, encoding: int = 0x8):
        self._encoding = encoding

    """
    # TODO:
        Notes:
            Need to deal with persistant nbfse talk.

            Since we are the sender, we dont need
            to track a dict from the server I think.

            The exception to this is mex responses.  The server
            sends dictionaries with mex responses

            We should prefer to not use a dict if possible.
    
    """

    def _extract_dict_from_xml(self) -> dict[int, str]:
        """TODO: needs to be populated"""

        return {}

    def _inband_dict_to_bin(self, inbandDict: dict[int, str]) -> bytes:
        """Convert dict into string table and seralize"""

        string_table = bytes()

        for _, v in inbandDict.items():
            size = Net7BitInteger.encode7bit(len(v.encode("utf-8")))
            string_table += size + v.encode("utf-8")

        size = Net7BitInteger.encode7bit(len(string_table))

        return size + string_table

    def _extract_stringtable_inband(self, data) -> dict[int, str]:
        """Extract strings from inband dict and place them into
        the string table.
        """

        string_table = {}
        idx = 1
        while data:
            size, len_len = Net7BitInteger.decode7bit(data)
            word = data[len_len : len_len + size]
            data = data[len_len + size :]
            string_table[idx] = word
            idx += 2

        return string_table

    # ========== Interface =============

    def encode(self, xml: str) -> bytes:
        """Serialize xml data with appropreate
        encoding type into bytes.

        Args:
            xml (str): xml data in string form

        Returns:
            (bytes): encoded xml data
        """
        r = XMLParser.parse(xml)

        base_data = dump_records(r)

        if self._encoding == 0x07:  # NBFS
            return base_data
        if self._encoding == 0x08:  # NBFSE
            inbandDict = self._inband_dict_to_bin(self._extract_dict_from_xml())
            return inbandDict + base_data

    def decode(self, data: bytes) -> str:
        """Deseralize and decode xml bytes into
        string form

        Args:
            data (bytes): seralize and encoded data

        Returns:
            (str): xml in string form
        """

        if self._encoding == 0x07:
            data = data

        if self._encoding == 0x08:
            size3, len_len3 = Net7BitInteger.decode7bit(data)

            # if there is something in the inband dict
            if size3 != 0:
                # cut off just the dict part and try to extract it
                string_table = self._extract_stringtable_inband(
                    data[len_len3 : len_len3 + size3]
                )
                print(string_table)

            # then index data to be the start of the actual xml blob
            data = data[len_len3 + size3 :]

        r = record.parse(BytesIO(data))  # begin parsing from first record
        xml = print_records(r)

        return xml
