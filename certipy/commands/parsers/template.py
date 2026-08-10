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


def validate_options(options: argparse.Namespace) -> None:
    """Validate option combinations specific to the template command."""
    create = getattr(options, "create", False)
    source_template = getattr(options, "source_template", None)
    template_oid = getattr(options, "template_oid", None)

    if create and not source_template:
        raise ValueError("-create requires -source-template")
    if source_template and not create:
        raise ValueError("-source-template can only be used with -create")
    if template_oid and not create:
        raise ValueError("-template-oid can only be used with -create")
    if create and getattr(options, "no_save", False):
        raise ValueError("-no-save cannot be used with -create")
    if create and getattr(options, "save_configuration", None):
        raise ValueError("-save-configuration cannot be used with -create")


def entry(options: argparse.Namespace) -> None:
    """
    Entry point for the template command.

    This function imports and calls the actual implementation of the template
    command from the certipy.commands module.

    Args:
        options: Parsed command-line arguments
    """
    try:
        validate_options(options)
    except ValueError as error:
        raise SystemExit(str(error)) from error

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
            "View, modify, or explicitly create certificate templates in Active "
            "Directory. Creation clones an existing template, assigns a unique OID, "
            "and does not publish the new template to a CA."
        ),
        epilog=(
            "Creation examples:\n"
            "  certipy template -template NewTemplate -create "
            "-source-template User [connection options]\n"
            "  certipy template -template NewTemplate -create "
            "-source-template User -write-default-configuration <SID> "
            "[connection options]\n"
            "  certipy template -template NewTemplate -create "
            "-source-template User -write-configuration template.json "
            "[connection options]\n\n"
            "Creation performs LDAP ADD followed by a separate DACL update. If the "
            "DACL phase fails, the new object remains in Active Directory and "
            "Certipy reports partial completion."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Required template name argument
    subparser.add_argument(
        "-template",
        action="store",
        metavar="template name",
        required=True,
        help="Name of the certificate template to operate on (case-sensitive)",
    )

    creation_group = subparser.add_argument_group("creation options")
    creation_group.add_argument(
        "-create",
        action="store_true",
        help=(
            "Create a new pKICertificateTemplate object. This requires CreateChild "
            "permission on the Certificate Templates container and never overwrites "
            "an existing object. A unique OID is generated unless -template-oid is "
            "specified. The template is not published to a CA."
        ),
    )
    creation_group.add_argument(
        "-source-template",
        action="store",
        metavar="template name",
        help=(
            "Existing certificate template to clone when using -create. Its schema "
            "and configuration are copied unless an explicit configuration override "
            "is supplied."
        ),
    )
    creation_group.add_argument(
        "-template-oid",
        action="store",
        metavar="OID",
        help=(
            "Explicit unique dotted-decimal OID for the new template. By default, "
            "Certipy generates one below the forest enterprise OID prefix."
        ),
    )

    # Group configuration-related options
    config_group = subparser.add_argument_group("configuration options")
    write_group = config_group.add_mutually_exclusive_group()
    write_group.add_argument(
        "-write-configuration",
        action="store",
        metavar="configuration file",
        help=(
            "Apply configuration from a JSON file to the certificate template. "
            "Use this option to restore a previous configuration or apply custom settings. "
            "The file should contain the template configuration in valid JSON format."
        ),
    )
    write_group.add_argument(
        "-write-default-configuration",
        nargs="?",
        const="S-1-5-11",
        default=None,
        metavar="target sid",
        help=(
            "Explicitly apply the default Certipy ESC1 configuration to the certificate template. "
            "This configures the template to be vulnerable to ESC1 attack. "
            "It accepts an optional argument for the target sid that should get ESC1 permissions "
            "(default S-1-5-11 for authenticated users). "
            "CAREFUL: If you specify a SID of an account not under your control, you lose the ability to restore!"
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
            "Use this option to apply modifications or creation without user interaction. "
            "It never permits replacing an existing template."
        ),
    )

    # Add standard target arguments (domain, username, etc.) from shared module
    target.add_argument_group(subparser)

    return NAME, entry
