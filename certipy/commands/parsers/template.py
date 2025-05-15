"""
Parser for certificate template management commands.

This module defines the command-line interface for the 'template' command,
which allows manipulating certificate templates in Active Directory.
"""

import argparse
from typing import Callable, Tuple

from . import target

# Command name identifier
NAME = "template"


def entry(options: argparse.Namespace) -> None:
    """
    Entry point for the template command.

    This function imports and calls the actual implementation of the template
    command from the certipy.commands module.

    Args:
        options: Parsed command-line arguments
    """
    from certipy.commands import template

    template.entry(options)


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:  # type: ignore
    """
    Add the certificate template command subparser to the main parser.

    This function creates and configures a subparser for managing certificate templates
    in Active Directory, including options for viewing, modifying, and saving
    template configurations.

    Args:
        subparsers: Parent parser to attach the subparser to

    Returns:
        Tuple of (command_name, entry_function) for command registration
    """
    # Create the template subparser with description
    subparser = subparsers.add_parser(
        NAME,
        help="Manage certificate templates",
        description=(
            "Manipulate certificate templates in Active Directory. "
            "This command allows viewing and modifying template configurations for privilege escalation testing or remediation."
        ),
    )

    # Required template name argument
    subparser.add_argument(
        "-template",
        action="store",
        metavar="template name",
        required=True,
        help="Name of the certificate template to operate on (case-sensitive)",
    )

    # Group configuration-related options
    config_group = subparser.add_argument_group("configuration options")
    config_group.add_argument(
        "-write-configuration",
        action="store",
        metavar="configuration file",
        help=(
            "Apply configuration from a JSON file to the certificate template. "
            "Use this option to restore a previous configuration or apply custom settings. "
            "The file should contain the template configuration in valid JSON format."
        ),
    )
    config_group.add_argument(
        "-write-default-configuration",
        action="store_true",
        help=(
            "Apply the default Certipy ESC1 configuration to the certificate template. "
            "This configures the template to be vulnerable to ESC1 attack."
        ),
    )

    config_group.add_argument(
        "-save-configuration",
        action="store",
        metavar="configuration file",
        help=(
            "Save the current template configuration to a JSON file. "
            "This creates a backup before making changes or documents the current settings. "
            "If not specified when using -write-configuration or -write-default-configuration, a backup will still be created."
        ),
    )
    config_group.add_argument(
        "-no-save",
        action="store_true",
        help=(
            "Skip saving the current template configuration before applying changes. "
            "Use this option to apply modifications without creating a backup file."
        ),
    )
    config_group.add_argument(
        "-force",
        action="store_true",
        help=(
            "Don't prompt for confirmation before applying changes. "
            "Use this option to apply modifications without user interaction."
        ),
    )

    # Add standard target arguments (domain, username, etc.) from shared module
    target.add_argument_group(subparser)

    return NAME, entry
