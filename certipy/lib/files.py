"""
File handling utilities for Certipy.

This module provides functions for safely writing data to files
with appropriate fallback mechanisms.
"""

import base64
import os
import uuid
from typing import Union

from certipy.lib.logger import logging


def try_to_save_file(data: Union[bytes, str], output_path: str) -> str:
    """
    Try to write data to a file or stdout if file writing fails.

    This function attempts to save data to the specified path. If writing fails,
    it outputs to stdout instead. If the file already exists, the user is
    prompted to confirm overwriting.

    Args:
        data: Data to write (either binary bytes or text string)
        output_path: Path to output file
    """
    logging.debug(f"Attempting to write data to {output_path!r}")

    # Clean up the output path
    output_path = output_path.replace("\\", "_").replace("/", "_").replace(":", "_")

    # Handle file existence check and overwrite confirmation
    output_path = _handle_file_exists(output_path)

    # Write to file with appropriate mode
    try:
        mode = "wb" if isinstance(data, bytes) else "w"
        with open(output_path, mode) as f:
            f.write(data)
        logging.debug(f"Data written to {output_path!r}")
        return output_path
    except Exception as e:
        logging.error(f"Error writing output file: {e}. Dumping to stdout instead")
        _write_to_stdout(data)
        return "stdout"


def _handle_file_exists(path: str) -> str:
    """
    Handle the case where a file already exists.

    Prompts the user to confirm overwriting or generates a new unique filename.

    Args:
        path: Original file path

    Returns:
        Final path to use (either original or new unique path)
    """
    if os.path.exists(path):
        overwrite = input(f"File {path!r} already exists. Overwrite? (y/n): ")
        if overwrite.strip().lower() != "y":
            # Generate a unique filename
            base, ext = os.path.splitext(path)
            new_path = f"{base}_{uuid.uuid4()}{ext}"
            return new_path
    return path


def _write_to_stdout(data: Union[bytes, str]) -> None:
    """
    Write data to stdout, encoding binary data as base64 if needed.

    Args:
        data: Data to output (binary data will be base64 encoded)
    """
    if isinstance(data, bytes):
        print(base64.b64encode(data).decode())
    else:
        print(data)
