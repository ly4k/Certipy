"""
Formatting utilities for Certipy.

This module provides functions for formatting data into human-readable formats,
including pretty printing dictionaries, case conversion, and certificate information display.
"""

import datetime
from typing import Any, Callable, Dict, List, Tuple

from certipy.lib.logger import logging

# Type aliases for better readability
PrintFunc = Callable[..., Any]
JsonLike = Dict[str, Any]
CertIdentification = Tuple[str, str]


def to_pascal_case(snake_str: str) -> str:
    """
    Convert a snake_case string to PascalCase.

    Args:
        snake_str: String in snake_case format

    Returns:
        String converted to PascalCase

    Example:
        >>> to_pascal_case("hello_world")
        "HelloWorld"
    """
    components = snake_str.split("_")
    return "".join(x.title() for x in components)


def pretty_print(
    data: JsonLike, indent: int = 0, padding: int = 40, print_func: PrintFunc = print
) -> None:
    """
    Pretty print a dictionary with customizable indentation and padding.

    Handles nested dictionaries, lists, and various data types with appropriate formatting.

    Args:
        data: Dictionary to print
        indent: Initial indentation level
        padding: Left padding for values
        print_func: Function to use for printing (default: built-in print)

    Raises:
        TypeError: If input is not a dictionary or contains unsupported types
    """
    indent_str = "  " * indent

    for key, value in data.items():
        key_str = f"{indent_str}{key}"
        padded_key = key_str.ljust(padding, " ")

        if isinstance(value, (str, int, float, bool)):
            # Simple scalar types
            print_func(f"{padded_key}: {value}")

        elif isinstance(value, datetime.datetime):
            # Format datetime as ISO format
            print_func(f"{padded_key}: {value.isoformat()}")

        elif isinstance(value, dict):
            # Handle nested dictionaries
            print_func(f"{key_str}")
            pretty_print(
                value, indent=indent + 1, padding=padding, print_func=print_func
            )

        elif isinstance(value, list):
            if len(value) > 0 and isinstance(value[0], dict):
                # List of dictionaries
                print_func(f"{key_str}")
                for item in value:
                    if isinstance(item, dict):
                        pretty_print(
                            item,
                            indent=indent + 1,
                            padding=padding,
                            print_func=print_func,
                        )
                    else:
                        print_func(f"{indent_str}  {item}")
            else:
                # Format list with line breaks if needed
                formatted_list = ("\n" + " " * padding + "  ").join(
                    str(x) for x in value
                )
                print_func(f"{padded_key}: {formatted_list}")

        elif isinstance(value, tuple):
            # Handle tuples (similar to lists of dictionaries)
            print_func(f"{key_str}")
            for item in value:
                if isinstance(item, dict):
                    pretty_print(
                        item, indent=indent + 1, padding=padding, print_func=print_func
                    )
                else:
                    print_func(f"{indent_str}  {item}")

        elif value is None:
            # Skip None values
            continue

        else:
            # Unsupported type
            raise TypeError(
                f"Unsupported type for pretty printing: {type(value).__name__}"
            )


def print_certificate_identifications(
    identifications: List[CertIdentification],
) -> None:
    """
    Print certificate identification information with appropriate formatting.

    Args:
        identifications: List of tuples containing (identification_type, identification_value)
    """
    if len(identifications) > 1:
        logging.info("Got certificate with multiple identifications")
        for id_type, id_value in identifications:
            print(f"    {id_type}: {repr(id_value)}")

    elif len(identifications) == 1:
        id_type, id_value = identifications[0]
        logging.info(f"Got certificate with {id_type} {repr(id_value)}")

    else:
        logging.info("Got certificate without identification")
