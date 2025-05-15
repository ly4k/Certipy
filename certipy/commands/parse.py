"""
Certificate Template Parser Module for Certipy.

This module provides functionality to parse certificate templates from various sources:
- Registry files exported from Windows systems (.reg format)
- Beacon Object Files (BOF) output containing certificate template data

The parsed templates can then be analyzed using the same functionality as the `find`
command, allowing offline analysis of certificate templates and their security settings.
"""

import argparse
import re
from enum import Enum
from pathlib import Path
from typing import Iterator, List, Optional

from certipy.commands import find
from certipy.lib.errors import handle_error
from certipy.lib.logger import logging
from certipy.lib.registry import RegConnection, RegEntry


class ParserType(Enum):
    """Supported parser types for certificate template data."""

    BOF = "bof"  # Beacon Object File output
    REG = "reg"  # Windows Registry export file


class Parse(find.Find):
    """
    Base parser class for certificate templates.

    This class extends the Find functionality to work with offline template data,
    allowing analysis of certificate templates without direct access to AD.
    """

    def __init__(
        self,
        domain: str = "UNKNOWN",
        ca: str = "UNKNOWN",
        sids: List[str] = [],
        published: List[str] = [],
        **kwargs,  # type: ignore
    ):
        """
        Initialize the certificate template parser.

        Args:
            domain: Domain name for the templates (default: UNKNOWN)
            ca: Certificate Authority name (default: UNKNOWN)
            sids: List of SIDs to resolve in ACLs
            published: List of templates published by the CA
            kwargs: Additional arguments to pass to Find base class
        """
        super().__init__(**kwargs)

        # Set up for offline analysis
        self.dc_only = True
        self.target.username = "unknown"
        self.target.target_ip = "unknown"

        # Store instance variables
        self.domain = domain
        self.ca = ca
        self.sids = sids
        self.published = published
        self.file = None

        # Mappings between registry keys and LDAP attribute names
        self.mappings = {
            "DisplayName": "displayName",
            "ValidityPeriod": "pKIExpirationPeriod",
            "RenewalOverlap": "pKIOverlapPeriod",
            "ExtKeyUsageSyntax": "pKIExtendedKeyUsage",
            "Security": "nTSecurityDescriptor",
            # Maps common registry names to their corresponding LDAP attributes
        }

    @property
    def connection(self) -> RegConnection:  # type: ignore
        """
        Get or create a registry connection for SID resolution.

        Returns:
            RegConnection object for SID resolution
        """
        if self._connection is not None:
            return self._connection

        self._connection: Optional[RegConnection] = RegConnection(
            self.domain, self.sids
        )
        return self._connection

    def get_issuance_policies(self) -> List[RegEntry]:  # type: ignore
        """
        Get certificate issuance policies.

        Returns:
            Empty list (not implemented for offline analysis)
        """
        return []

    def get_certificate_authorities(self) -> List[RegEntry]:  # type: ignore
        """
        Get certificate authorities.

        Creates a mock CA entry with the provided templates for analysis.

        Returns:
            List containing a single mock CA RegEntry if templates are published,
            otherwise an empty list
        """
        if not self.published:
            return []

        # Create a mock CA entry with the published templates
        ca = RegEntry(
            **{
                "attributes": {
                    "cn": "Unknown",
                    "name": self.ca,
                    "dNSHostName": "localhost",
                    "cACertificateDN": "Unknown",
                    "cACertificate": [b""],
                    "certificateTemplates": self.published,
                    "objectGUID": "Unknown",
                }
            }
        )

        return [ca]

    def parse(self, file: str) -> None:
        """
        Parse certificate templates from a file.

        Args:
            file: Path to the file containing template data
        """
        self.file = file

        # Ensure the file exists
        file_path = Path(file)
        if not file_path.exists():
            logging.error(f"File not found: {file}")
            return

        logging.info(f"Parsing templates from {file}")

        # Use the find functionality to analyze the parsed templates
        self.find()


class ParseBof(Parse):
    """
    Parser for certificate templates from BOF output.

    This parser handles output from Beacon Object Files that dump registry
    certificate template information.
    """

    def get_certificate_templates(self) -> List[RegEntry]:  # type: ignore
        """
        Parse certificate templates from BOF output.

        Returns:
            List of RegEntry objects representing certificate templates
        """
        templates = []

        if self.file is None:
            raise ValueError("File not set for parsing")

        try:
            with open(self.file, "r", encoding="utf-8") as f:
                contents = f.read()
                # Remove timestamp headers from BOF output
                data = re.sub(
                    r"\n\n\d{2}\/\d{2} (\d{2}:){2}\d{2} UTC \[output\]\nreceived output:\n",
                    "",
                    contents,
                )
                lines = iter(data.splitlines())

                template = None
                registry_key_prefix = "HKEY_USERS\\.DEFAULT\\Software\\Microsoft\\Cryptography\\CertificateTemplateCache\\"

                # Process each line
                for line in lines:
                    try:
                        # Start of a new template
                        if registry_key_prefix in line:
                            if template is not None:
                                templates.append(template)

                            # Initialize new template with name from registry key
                            template = RegEntry()
                            parts = line.split("\\")
                            template_name = parts[-1]
                            template.set("cn", template_name)
                            template.set("name", template_name)
                            template.set("objectGUID", template_name)
                            continue

                        # Process registry values
                        if line.startswith("\t"):
                            line = line.strip()
                            parts = re.split(r"\s+", line, maxsplit=2)
                            if len(parts) < 2:
                                continue

                            name = parts[0]
                            datatype = parts[1]

                            # Process different registry value types
                            if datatype == "REG_DWORD":
                                data = int(line.split("REG_DWORD")[1].strip())
                            elif datatype == "REG_SZ":
                                data = line.split("REG_SZ")[1].strip()
                            elif datatype == "REG_MULTI_SZ":
                                data = line.split("REG_MULTI_SZ")[1].strip()
                                if data == "":
                                    data = []
                                else:
                                    data = data.split("\\0")
                            elif datatype == "REG_BINARY":
                                data = []
                                # Binary data may span multiple lines
                                while True:
                                    try:
                                        next_line = next(lines)
                                        if not next_line.startswith(" "):
                                            line = next_line  # Save for next iteration
                                            break
                                        else:
                                            data.extend(
                                                re.split(r"\s+", next_line.strip())
                                            )
                                    except StopIteration:
                                        break

                                # Convert hex strings to bytes
                                data = bytes.fromhex("".join(data))
                                continue  # We've already read the next line

                            # Map registry names to LDAP attributes if applicable
                            if name in self.mappings:
                                name = self.mappings[name]

                            # Set the attribute in the template
                            if template is not None:
                                template.set(name, data)
                    except Exception as e:
                        logging.debug(f"Error parsing line: {e}")
                        continue

                # Add the last template
                if template is not None:
                    templates.append(template)

        except Exception as e:
            logging.error(f"Error parsing BOF file: {e}")
            handle_error()
            return []

        logging.info(f"Parsed {len(templates)} templates from BOF output")
        return templates


class ParseReg(Parse):
    """
    Parser for certificate templates from Windows Registry export files.

    This parser handles .reg files exported from Windows containing
    certificate template information.
    """

    def get_certificate_templates(self) -> List[RegEntry]:  # type: ignore
        """
        Parse certificate templates from a .reg file.

        Returns:
            List of RegEntry objects representing certificate templates
        """
        templates = []

        if self.file is None:
            raise ValueError("File not set for parsing")

        try:
            with open(self.file, "r", encoding="utf-16-le", newline="\r\n") as f:
                # Verify it's a registry file
                firstline = f.readline()
                if "Windows Registry Editor Version" not in firstline:
                    raise ValueError(
                        "Unexpected file format, Windows registry file expected"
                    )

                data = f.read()
                lines = iter(data.splitlines())
                template = None
                registry_key_prefix = "[HKEY_USERS\\.DEFAULT\\Software\\Microsoft\\Cryptography\\CertificateTemplateCache\\"

                # Process each line
                for line in lines:
                    try:
                        # Start of a new template
                        if line.startswith(registry_key_prefix):
                            if template is not None:
                                templates.append(template)

                            # Initialize new template with name from registry key
                            template = RegEntry()
                            parts = line[1:-1].split("\\")
                            template_name = parts[-1]
                            template.set("cn", template_name)
                            template.set("name", template_name)
                            template.set("objectGUID", template_name)
                            continue

                        # Process registry values
                        if line.startswith('"'):
                            line = line.strip()
                            key_value = line.split("=", 1)
                            if len(key_value) < 2:
                                continue

                            name = key_value[0][1:-1]  # Remove quotes
                            raw_data = key_value[1]

                            # Process different registry value types
                            if raw_data.startswith('"'):
                                # REG_SZ
                                data = raw_data[1:-1]
                            elif raw_data.startswith("dword:"):
                                # REG_DWORD
                                data = int("0x" + raw_data[6:], 16)
                                # Handle signed values
                                data = data if data < 2**31 else data - 2**32
                            elif raw_data.startswith("hex:"):
                                # REG_BINARY
                                data = self._parse_hex_data(raw_data[4:], lines)
                            elif raw_data.startswith("hex(7):"):
                                # REG_MULTI_SZ
                                hex_data = self._parse_hex_data(raw_data[7:], lines)
                                data = hex_data.decode("utf-16le").rstrip("\x00")

                                if data == "":
                                    data = []
                                else:
                                    data = data.split("\x00")
                            else:
                                logging.debug(f"Unknown value type: {raw_data}")
                                continue

                            # Map registry names to LDAP attributes if applicable
                            if name in self.mappings:
                                name = self.mappings[name]

                            # Set the attribute in the template
                            if template is not None:
                                template.set(name, data)
                    except Exception as e:
                        logging.debug(f"Error parsing line: {e}")
                        continue

                # Add the last template
                if template is not None:
                    templates.append(template)

        except Exception as e:
            logging.error(f"Error parsing registry file: {e}")
            handle_error()
            return []

        logging.info(f"Parsed {len(templates)} templates from registry file")
        return templates

    def _parse_hex_data(self, initial_data: str, lines_iter: Iterator[str]) -> bytes:
        """
        Parse hex data that might span multiple lines.

        Args:
            initial_data: The initial hex data string
            lines_iter: Iterator for the file lines

        Returns:
            Bytes object containing the parsed hex data
        """
        values = []
        data = initial_data

        # Process hex data that can span multiple lines (indicated by trailing backslash)
        while True:
            values.extend(data.replace(",\\", "").split(","))
            if not data.endswith("\\"):
                break

            try:
                data = next(lines_iter).strip()
            except StopIteration:
                break

        return bytes.fromhex("".join(values))


def get_parser(
    parser_type: ParserType,
    domain: str,
    ca: str,
    sids: List[str],
    published: List[str],
    **kwargs,  # type: ignore
) -> Parse:
    """
    Factory function to get the appropriate parser.

    Args:
        parser_type: Type of parser to create
        domain: Domain name
        ca: CA name
        sids: List of SIDs
        published: List of published templates
        kwargs: Additional arguments

    Returns:
        Appropriate parser instance

    Raises:
        ValueError: If an unsupported parser type is provided
    """
    if parser_type == ParserType.BOF:
        return ParseBof(domain, ca, sids, published, **kwargs)
    elif parser_type == ParserType.REG:
        return ParseReg(domain, ca, sids, published, **kwargs)
    else:
        raise ValueError(f"Unsupported parser type: {parser_type}")


def entry(options: argparse.Namespace) -> None:
    """
    Command-line entry point for the parse functionality.

    Args:
        options: Command line arguments
    """
    # Extract and remove parse-specific options
    domain = options.domain
    ca = options.ca
    sids = options.sids or []
    published = options.published or []
    file_path = options.file
    parser_format = options.format.lower()

    # Remove processed options
    for opt in ["domain", "ca", "sids", "published", "file", "format"]:
        options.__delattr__(opt)

    # Validate input file
    if not file_path or not Path(file_path).exists():
        logging.error(f"Input file not found: {file_path}")
        return

    try:
        # Create and use the appropriate parser
        parser_type = ParserType(parser_format)
        parser = get_parser(
            parser_type=parser_type,
            domain=domain,
            ca=ca,
            sids=sids,
            published=published,
            **vars(options),
        )
        parser.parse(file_path)

    except ValueError as e:
        logging.error(f"Error: {e}")
        logging.error(
            f"Supported parser formats: {', '.join([p.value for p in ParserType])}"
        )
    except Exception as e:
        logging.error(f"Parse failed: {e}")
        handle_error()
