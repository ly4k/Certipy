import argparse
import re

from typing import List
from certipy.lib.registry import RegConnection, RegEntry
from certipy.commands import find

class Parse(find.Find):
    def __init__(
        self,
        domain: str = "UNKNOWN",
        ca: str = "UNKNOWN",
        sids: List[str] = [],
        published: List[str] = [],
        **kwargs
    ):
        super().__init__(self, **kwargs)
        self.dc_only = True
        self.target.username = 'unknown'
        self.target.target_ip = 'unknown'
        self.domain = domain
        self.ca = ca
        self.sids = sids
        self.published = published
        self.mappings = {
            # "KeyUsage" : "TODO"
            "DisplayName": "displayName",
            "ValidityPeriod": "pKIExpirationPeriod",
            "RenewalOverlap": "pKIOverlapPeriod",
            "ExtKeyUsageSyntax": "pKIExtendedKeyUsage",
            "Security": "nTSecurityDescriptor",
        }

    @property
    def connection(self) -> RegConnection:
        if self._connection is not None:
            return self._connection

        self._connection = RegConnection(self.domain, self.sids)
        return self._connection

    def get_issuance_policies(self) -> List[RegEntry]:
        return []

    def get_certificate_authorities(self) -> List[RegEntry]:
        if len(self.published) == 0:
            return []

        ca = RegEntry(
            **{
                "attributes": {
                    "cn" : "Unknown",
                    "name" : self.ca,
                    "dNSHostName" : "localhost",
                    "cACertificateDN" : "Unknown",
                    "cACertificate" : [ b"" ],
                    "certificateTemplates" : self.published,
                    "objectGUID": "Unknown",
                }
            }
        )

        return [ca]

    def parse(self, file: str):
        self.file = file
        return self.find()

class ParseBof(Parse):

    def get_certificate_templates(self) -> List[RegEntry]:

        templates = []

        with open(self.file, "r", encoding="utf-8") as f:
            contents = f.read()
            data = re.sub(r'\n\n\d{2}\/\d{2} (\d{2}:){2}\d{2} UTC \[output\]\nreceived output:\n', '', contents)
            lines = iter(data.splitlines())
            line = next(lines)

            template = None

            while True:
                try:
                    datatype = None

                    if 'HKEY_USERS\.DEFAULT\\Software\\Microsoft\\Cryptography\\CertificateTemplateCache\\' in line:
                        if template is not None:
                            templates.append(template)
                            # print(template)
                        template = RegEntry()
                        parts = line.split('\\')
                        template.set("cn", parts[-1])
                        template.set("name", parts[-1])
                        template.set("objectGUID", parts[-1])
                        line = next(lines)
                        continue

                    if line.startswith('\t'):
                        line = line.strip()
                        parts = re.split('\s+', line)
                        if len(parts) < 2:
                            line = next(lines)
                            continue
                        name = parts[0]
                        datatype = parts[1]
                        data = parts[2] if len(parts) > 2 else None
                        if datatype == 'REG_DWORD':
                            data = int(line.split('REG_DWORD')[1].strip())
                        elif datatype == 'REG_SZ':
                            data = line.split('REG_SZ')[1].strip()
                        elif datatype == 'REG_MULTI_SZ':
                            data = line.split('REG_MULTI_SZ')[1].strip()
                            if data == '':
                                data = []
                            else:
                                data = data.split("\\0")
                        elif datatype == 'REG_BINARY':
                            data = []
                            while True:
                                line = next(lines)
                                if not line.startswith(" "):
                                    break
                                else:
                                    data = data + re.split("\s+", line.strip())
                            # print(data)
                            data = bytes.fromhex("".join(data))

                        if name in self.mappings:
                            name = self.mappings[name]
                        if not template is None:
                            template.set(name, data)

                    if datatype != 'REG_BINARY':
                        line = next(lines)
                except StopIteration:
                    break

            if template is not None:
                templates.append(template)

        return templates

class ParseReg(Parse):

    def get_certificate_templates(self) -> List[RegEntry]:

        templates = []

        with open(self.file, "r", encoding="utf-16-le", newline="\r\n") as f:
            firstline = f.readline()

            if "Windows Registry Editor Version" not in firstline:
                raise Exception("Unexpected file format, Windows registry file expected")

            data = f.read()
            lines = iter(data.splitlines())
            line = next(lines)

            template = None

            while True:
                try:
                    if line.startswith('[HKEY_USERS\.DEFAULT\\Software\\Microsoft\\Cryptography\\CertificateTemplateCache\\'):
                        line = line[1:-1]
                        if template is not None:
                            templates.append(template)
                            # print(template)
                        template = RegEntry()
                        parts = line.split('\\')
                        template.set("cn", parts[-1])
                        template.set("name", parts[-1])
                        template.set("objectGUID", parts[-1])
                    elif line.startswith('"'):
                        line = line.strip()
                        parts = line.split('=')
                        if len(parts) < 2:
                            line = next(lines)
                            continue
                        name = parts[0]
                        name = name[1:-1]
                        data = parts[1]
                        if data.startswith('"'):
                            data = data[1:-1]
                        elif data.startswith('dword:'):
                            data = int('0x' + data[6:],16)
                            data = data if data<2**31 else data-2**32
                        elif data.startswith('hex:'):
                            data = data[4:]
                            values = []
                            while True:
                                values = values + data.replace(',\\', '').split(',')
                                if not line.endswith('\\'):
                                    break
                                line = next(lines)
                                data = line.strip()
                            data = bytes.fromhex("".join(values))
                        elif data.startswith('hex(7):'):
                            data = data[7:]
                            values = []
                            while True:
                                values = values + data.replace(',\\', '').split(',')
                                if not line.endswith('\\'):
                                    break
                                line = next(lines)
                                data = line.strip()

                            data = bytes.fromhex("".join(values))
                            data = data.decode('utf-16le')
                            data = data.rstrip('\x00')

                            if data == '':
                                data = []
                            else:
                                data = data.split('\x00')

                        if name in self.mappings:
                            name = self.mappings[name]
                        if not template is None:
                            template.set(name, data)

                    line = next(lines)
                except StopIteration:
                    break

            if template is not None:
                templates.append(template)

        return templates

def entry(options: argparse.Namespace) -> None:

    domain = options.domain
    del options.domain

    ca = options.ca
    del options.ca

    sids = options.sids
    del options.sids

    published = options.published
    del options.published

    file = options.file
    del options.file

    format = options.format
    del options.format

    if format == 'bof':
        parse = ParseBof(domain, ca, sids, published, **vars(options))
    if format == 'reg':
        parse = ParseReg(domain, ca, sids, published, **vars(options))

    parse.parse(file)
