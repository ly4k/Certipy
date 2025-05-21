"""
Certificate Processing Module for Certipy.

This module provides utility functions for working with certificates:
- Converting between different certificate formats (PEM, DER, PFX)
- Loading certificates and private keys
- Exporting certificates in various formats

It serves as a command-line utility for certificate manipulation tasks.
"""

import argparse
import sys
from typing import Optional, Union

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from certipy.lib.certificate import (
    cert_to_pem,
    create_pfx,
    der_to_cert,
    der_to_key,
    key_to_pem,
    load_pfx,
    pem_to_cert,
    pem_to_key,
)
from certipy.lib.errors import handle_error
from certipy.lib.logger import logging


def load_certificate_file(file_path: str) -> bytes:
    """
    Load certificate data from a file.

    Args:
        file_path: Path to certificate file

    Returns:
        Certificate data as bytes
    """
    logging.debug(f"Loading certificate from {file_path!r}")
    try:
        with open(file_path, "rb") as f:
            cert_data = f.read()
        return cert_data
    except FileNotFoundError:
        logging.error(f"Certificate file not found: {file_path!r}")
        raise
    except IOError as e:
        logging.error(f"Error reading certificate file: {e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error reading certificate file: {e}")
        raise


def load_key_file(file_path: str) -> bytes:
    """
    Load private key data from a file.

    Args:
        file_path: Path to private key file

    Returns:
        Private key data as bytes
    """
    logging.debug(f"Loading private key from {file_path!r}")
    try:
        with open(file_path, "rb") as f:
            key_data = f.read()
        return key_data
    except FileNotFoundError:
        logging.error(f"Private key file not found: {file_path!r}")
        raise
    except IOError as e:
        logging.error(f"Error reading private key file: {e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error reading private key file: {e}")
        raise


def parse_certificate(cert_data: bytes) -> x509.Certificate:
    """
    Parse certificate data from PEM or DER format.

    Args:
        cert_data: Raw certificate data

    Returns:
        Parsed certificate object
    """
    try:
        # Try PEM format first
        return pem_to_cert(cert_data)
    except Exception:
        # Fall back to DER format
        try:
            return der_to_cert(cert_data)
        except Exception as e:
            logging.error(f"Failed to parse certificate: {e}")
            raise ValueError("Certificate is not in a valid PEM or DER format")


def parse_key(key_data: bytes) -> PrivateKeyTypes:
    """
    Parse private key data from PEM or DER format.

    Args:
        key_data: Raw private key data

    Returns:
        Parsed private key object
    """
    try:
        # Try PEM format first
        return pem_to_key(key_data)
    except Exception:
        # Fall back to DER format
        try:
            return der_to_key(key_data)
        except Exception as e:
            logging.error(f"Failed to parse private key: {e}")
            raise ValueError("Private key is not in a valid PEM or DER format")


def write_output(data: Union[bytes, str], output_path: Optional[str] = None) -> None:
    """
    Write data to a file or stdout.

    Args:
        data: Data to write
        output_path: Path to output file or None for stdout
    """
    if output_path:
        # Determine if we need binary mode
        mode = "wb" if isinstance(data, bytes) else "w"
        try:
            with open(output_path, mode) as f:
                _ = f.write(data)
            logging.info(f"Data written to {output_path!r}")
        except IOError as e:
            logging.error(f"Error writing output file: {e}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error writing output file: {e}")
            raise
    else:
        # Write to stdout
        if isinstance(data, bytes):
            _ = sys.stdout.buffer.write(data)
        else:
            print(data)


def entry(options: argparse.Namespace) -> None:
    """
    Entry point for the 'cert' command.

    Processes certificates and private keys according to specified options.

    Args:
        options: Command-line arguments
    """
    cert, key = None, None

    # Validate inputs
    if not any([options.pfx, options.cert, options.key]):
        logging.error("-pfx, -cert, or -key is required")
        return

    # Process PFX input if provided
    if options.pfx:
        try:
            password = options.password.encode() if options.password else None
            log_msg = (
                f"Loading PFX {options.pfx!r} with password"
                if password
                else f"Loading PFX {options.pfx!r} without password"
            )
            logging.debug(log_msg)

            with open(options.pfx, "rb") as f:
                pfx = f.read()

            key, cert = load_pfx(pfx, password)
        except Exception as e:
            logging.error(f"Failed to load PFX file: {e}")
            handle_error()
            return

    # Process certificate input if provided
    if options.cert:
        try:
            cert_data = load_certificate_file(options.cert)
            cert = parse_certificate(cert_data)
        except Exception as e:
            logging.error(f"Failed to process certificate: {e}")
            handle_error()
            return

    # Process private key input if provided
    if options.key:
        try:
            key_data = load_key_file(options.key)
            key = parse_key(key_data)
        except Exception as e:
            logging.error(f"Failed to process private key: {e}")
            handle_error()
            return

    # Export in PFX format
    if options.export:
        if not (key and cert):
            logging.error(
                "Both certificate and private key are required for PFX export"
            )
            return

        try:
            pfx = create_pfx(key, cert, options.export_password)
            write_output(pfx, options.out)
        except Exception as e:
            logging.error(f"Failed to create PFX: {e}")
            handle_error()
            return
    # Export in PEM format
    else:
        output_parts = []
        output_types = []

        # Add certificate to output if available and not suppressed
        if cert and not options.nocert:
            output_parts.append(cert_to_pem(cert).decode())
            output_types.append("certificate")

        # Add private key to output if available and not suppressed
        if key and not options.nokey:
            output_parts.append(key_to_pem(key).decode())
            output_types.append("private key")

        # Combine all parts
        output = "".join(output_parts)

        # Check if output is empty
        if not output:
            logging.error("Output is empty")
            return

        # Format log message for what's being written
        log_str = " and ".join(output_types)

        try:
            write_output(output, options.out)
            if options.out:
                logging.info(f"Writing {log_str} to {options.out!r}")
        except Exception as e:
            logging.error(f"Failed to write output: {e}")
            handle_error()
