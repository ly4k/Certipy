import argparse
import re

from typing import List
from certipy.lib.registry import RegConnection, RegEntry
from certipy.commands import find

class Parse(find.Find):
    def __init__(
        self,
        domain: str = "UNKNOWN",
        sids: List[str] = [],
        published: List[str] = [],
        **kwargs
    ):
        super().__init__(self, **kwargs)
        self.dc_only = True
        self.target.username = 'unknown'
        self.target.target_ip = 'unknown'
        self.domain = domain
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
                    "name" : "Unknown",
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

def entry(options: argparse.Namespace) -> None:

    domain = options.domain
    del options.domain

    sids = options.sids
    del options.sids

    published = options.published
    del options.published

    file = options.file
    del options.file

    parse = ParseBof(domain, sids, published, **vars(options))
    parse.parse(file)
