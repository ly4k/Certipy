"""
Parser for certificate template offline analyzer command.

This module defines the command-line interface for the 'parse' command,
which enables offline analysis of AD CS certificate templates from registry data
exported from domain controllers.
"""

import argparse
from typing import Callable, Tuple

# Command name identifier
NAME = "parse"


def entry(options: argparse.Namespace) -> None:
    """
    Entry point for the parse command.

    This function imports and calls the actual implementation of the parse
    command from the certipy.commands module.

    Args:
        options: Parsed command-line arguments
    """
    from certipy.commands import parse

    parse.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:  # type: ignore
    """
    Add the parse command subparser to the main parser.

    This function creates and configures a subparser for analyzing AD CS certificate
    templates from registry data, allowing offline enumeration of potentially
    vulnerable templates.

    Args:
        subparsers: Parent parser to attach the subparser to

    Returns:
        Tuple of (command_name, entry_function) for command registration
    """
    # Create the parse subparser with description
    subparser = subparsers.add_parser(
        NAME,
        help="Offline enumerate AD CS based on registry data",
        description=(
            "Parse and analyze certificate templates from exported registry data. "
            "This allows assessment of AD CS security without direct domain access."
        ),
    )

    # Input file (positional argument, required)
    subparser.add_argument(
        "file", help="File to parse (BOF output or .reg file from registry export)"
    )

    # Output format options
    output_group = subparser.add_argument_group("output options")
    output_group.add_argument(
        "-text",
        action="store_true",
        help="Output result as formatted text file",
    )
    output_group.add_argument(
        "-stdout",
        action="store_true",
        help="Output result as text directly to console",
    )
    output_group.add_argument(
        "-json",
        action="store_true",
        help="Output result as JSON",
    )
    output_group.add_argument(
        "-csv",
        action="store_true",
        help="Output result as CSV",
    )
    output_group.add_argument(
        "-output",
        action="store",
        metavar="prefix",
        help="Filename prefix for writing results to",
    )

    # Parse options for input interpretation and filtering
    parse_group = subparser.add_argument_group("parse options")
    parse_group.add_argument(
        "-format",
        metavar="format",
        help="Input format: BOF output or Windows .reg file (default: bof)",
        choices=["bof", "reg"],
        default="bof",
    )
    parse_group.add_argument(
        "-domain",
        metavar="domain name",
        help="Domain name. Only used for output context (default: UNKNOWN)",
        type=lambda arg: arg.upper(),
        default="UNKNOWN",
    )
    parse_group.add_argument(
        "-ca",
        metavar="ca name",
        help="CA name. Only used for output context (default: UNKNOWN)",
        default="UNKNOWN",
    )

    # Security analysis options
    parse_group.add_argument(
        "-sids",
        metavar="sids",
        help="Consider the comma separated list of SIDs as owned for vulnerability assessment",
        type=lambda arg: list(map(str.strip, arg.split(","))),
        default=[],
    )
    parse_group.add_argument(
        "-published",
        metavar="templates",
        help="Consider the comma separated list of template names as published in AD",
        type=lambda arg: list(map(str.strip, arg.split(","))),
        default=[],
    )

    # Filter options
    filter_group = subparser.add_argument_group("filter options")
    filter_group.add_argument(
        "-enabled",
        action="store_true",
        help="Show only enabled certificate templates",
    )
    filter_group.add_argument(
        "-vulnerable",
        action="store_true",
        help="Show only vulnerable certificate templates based on nested group memberships",
    )
    filter_group.add_argument(
        "-hide-admins",
        action="store_true",
        help="Don't show administrator permissions for -text, -stdout, -json, and -csv output",
    )

    return NAME, entry
