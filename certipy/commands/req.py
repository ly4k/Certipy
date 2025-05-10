"""
Certificate request module for Certipy.

This module provides functionality for:
- Requesting certificates from Active Directory Certificate Services (AD CS)
- Retrieving pending or issued certificates
- Supporting various request methods (RPC, DCOM, Web Enrollment)
- Handling certificate templates and custom attributes
- Supporting certificate renewal, key archival, and on-behalf-of requests

Key components:
- Request: Main class for certificate operations
- RequestInterface: Abstract base class for different request protocols
- RPCRequestInterface: Certificate requests via MS-ICPR
- DCOMRequestInterface: Certificate requests via DCOM
- WebRequestInterface: Certificate requests via Web Enrollment
"""

import argparse

from certipy.lib.files import try_to_save_file
from certipy.lib.logger import logging
from certipy.lib.req import Request
from certipy.lib.target import Target

# =========================================================================
# Command-line entry point
# =========================================================================


def entry(options: argparse.Namespace) -> None:
    """
    Command-line entry point for certificate operations.

    Args:
        options: Command-line arguments
    """
    # Create target from options
    target = Target.from_options(options)
    options.__delattr__("target")

    # Create request object
    request = Request(target=target, **vars(options))

    # Handle CAX certificate retrieval
    if options.cax_cert:
        if not options.out:
            logging.error("Please specify an output file for the CAX certificate!")
            return

        cax = request.get_cax()
        if isinstance(cax, bytes):
            logging.info(f"Saving CAX certificate to {options.out!r}")
            output_path = try_to_save_file(cax, options.out)
            logging.info(f"Wrote CAX certificate to {output_path!r}")
        return

    # Handle certificate retrieval or request
    if options.retrieve:
        _ = request.retrieve()
    else:
        _ = request.request()
