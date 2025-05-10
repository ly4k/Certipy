"""
Formatting utilities for Certipy.

This module provides functions for formatting data into human-readable formats,
including pretty printing dictionaries, and case conversion.
"""

import datetime
from typing import Any, Callable, Dict

# Type aliases for better readability
PrintFunc = Callable[..., Any]
JsonLike = Dict[str, Any]


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


REMAP = {
    "http": "HTTP",
    "https": "HTTPS",
    "enabled": "Enabled",
    "channel_binding": "Channel Binding (EPA)",
}


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
        if key in REMAP:
            # Remap keys if needed
            key = REMAP[key]

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
