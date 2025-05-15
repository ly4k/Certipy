"""
Parser for certificate manipulation command.

This module defines the command-line interface for the 'cert' command,
which allows managing certificates and private keys, including importing,
exporting, and converting between different formats.
"""

import argparse
from typing import Callable, Tuple

# Command name identifier
NAME = "cert"


def entry(options: argparse.Namespace) -> None:
    """
    Entry point for the cert command.

    This function imports and calls the actual implementation of the cert
    command from the certipy.commands module.

    Args:
        options: Parsed command-line arguments
    """
    from certipy.commands import cert

    cert.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:  # type: ignore
    """
    Add the certificate management command subparser to the main parser.

    This function creates and configures a subparser for managing certificates
    and private keys, including options for importing from various formats,
    exporting to PFX, and manipulating certificate components.

    Args:
        subparsers: Parent parser to attach the subparser to

    Returns:
        Tuple of (command_name, entry_function) for command registration
    """
    # Create the cert subparser with description
    subparser = subparsers.add_parser(
        NAME,
        help="Manage certificates and private keys",
        description=(
            "Import, export, and manipulate certificates and private keys locally. "
            "This command supports various operations like converting between formats, "
            "extracting components, and creating PFX files."
        ),
    )

    # Input options group
    input_group = subparser.add_argument_group("input options")
    input_group.add_argument(
        "-pfx",
        action="store",
        metavar="infile",
        help="Load certificate and private key from PFX/P12 file",
    )
    input_group.add_argument(
        "-password",
        action="store",
        metavar="password",
        help="Password for the input PFX/P12 file",
    )
    input_group.add_argument(
        "-key",
        action="store",
        metavar="infile",
        help="Load private key from PEM or DER file",
    )
    input_group.add_argument(
        "-cert",
        action="store",
        metavar="infile",
        help="Load certificate from PEM or DER file",
    )

    # Output options group
    output_group = subparser.add_argument_group("output options")
    output_group.add_argument(
        "-export", action="store_true", help="Export to PFX/P12 file (default format)"
    )
    output_group.add_argument(
        "-out",
        action="store",
        metavar="outfile",
        help="Output filename for the exported certificate/key",
    )
    output_group.add_argument(
        "-nocert",
        action="store_true",
        help="Don't include certificate in output (key only)",
    )
    output_group.add_argument(
        "-nokey",
        action="store_true",
        help="Don't include private key in output (certificate only)",
    )
    output_group.add_argument(
        "-export-password",
        action="store",
        metavar="password",
        help="Password to protect the output PFX/P12 file",
    )

    return NAME, entry
