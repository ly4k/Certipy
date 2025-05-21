"""
Error code translation utilities for Certipy.

This module provides functions for translating numeric error codes from Windows APIs
and Kerberos services into human-readable messages. It acts as a wrapper around
the error code mappings provided by the impacket library.

Functions:
    translate_error_code: Convert a Windows error code to a readable message
"""

import traceback
from typing import Dict, Tuple

from impacket import hresult_errors
from impacket.krb5.kerberosv5 import constants as krb5_constants

from certipy.lib.logger import is_verbose, logging

# Import Kerberos error message dictionary for easier access
KRB5_ERROR_MESSAGES: Dict[int, Tuple[str, str]] = krb5_constants.ERROR_MESSAGES


def translate_error_code(error_code: int) -> str:
    """
    Translate a Windows API error code to a human-readable string.

    Args:
        error_code: Windows API error code (HRESULT)

    Returns:
        Formatted error message with code, short description, and detailed explanation

    Example:
        >>> translate_error_code(0x80090311)
        'code: 0x80090311 - SEC_E_LOGON_DENIED - The token supplied to the function is invalid'
    """
    # Mask to 32 bits to handle sign extension issues
    masked_code = error_code & 0xFFFFFFFF

    # Look up in the impacket error dictionary
    if masked_code in hresult_errors.ERROR_MESSAGES:
        error_tuple: Tuple[str, str] = hresult_errors.ERROR_MESSAGES[masked_code]
        error_short, error_detail = error_tuple

        # Format the message with all information
        return f"code: 0x{masked_code:x} - {error_short} - {error_detail}"
    else:
        # Handle unknown error codes
        return f"unknown error code: 0x{masked_code:x}"


def handle_error(is_warning: bool = False) -> None:
    """
    Handle errors by printing the error message and exiting the program.

    This function is a placeholder for error handling logic. It can be extended
    to include logging, user notifications, or other actions as needed.
    """
    if is_verbose():
        # Print the full traceback for debugging
        traceback.print_exc()
    else:
        msg = "Use -debug to print a stacktrace"
        if is_warning:
            logging.warning(msg)
        else:
            logging.error(msg)
