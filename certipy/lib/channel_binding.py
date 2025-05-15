import hashlib
import ssl

import httpx


def get_channel_binding_data(server_cert: bytes) -> bytes:
    """
    Generate channel binding token (CBT) from a server certificate.

    This implements the tls-server-end-point channel binding type as described
    in RFC 5929 section 4. The binding token is created by:
    1. Hashing the server certificate with SHA-256
    2. Creating a channel binding structure with the hash
    3. Computing an MD5 hash of the structure

    Args:
        server_cert: Raw server certificate bytes

    Returns:
        MD5 hash of the channel binding structure (16 bytes)

    References:
        - RFC 5929: https://datatracker.ietf.org/doc/html/rfc5929#section-4
    """
    # Hash the certificate with SHA-256 as required by the RFC
    cert_hash = hashlib.sha256(server_cert).digest()

    # Initialize the channel binding structure with empty addresses
    # These fields are defined in the RFC but not used for TLS bindings
    initiator_address = b"\x00" * 8
    acceptor_address = b"\x00" * 8

    # Create the application data with the "tls-server-end-point:" prefix
    application_data_raw = b"tls-server-end-point:" + cert_hash

    # Add the length prefix to the application data (little-endian 32-bit integer)
    len_application_data = len(application_data_raw).to_bytes(
        4, byteorder="little", signed=False
    )
    application_data = len_application_data + application_data_raw

    # Assemble the complete channel binding structure
    channel_binding_struct = initiator_address + acceptor_address + application_data

    # Return the MD5 hash of the structure
    return hashlib.md5(channel_binding_struct).digest()


def get_channel_binding_data_from_response(response: httpx.Response) -> bytes:
    """
    Extract channel binding data from an HTTPX response.

    This function extracts the server certificate from an HTTPX response
    and generates the channel binding token used for authentication.

    Args:
        response: The HTTPX response object containing TLS connection information

    Returns:
        The channel binding token as bytes

    Raises:
        ValueError: If unable to extract required TLS information from the response
    """
    # Check if network stream is available in response extensions
    if "network_stream" not in response.extensions:
        raise ValueError(
            "No network stream found in response - TLS information unavailable"
        )

    # Extract the TLS/SSL object from the network stream
    network_stream = response.extensions["network_stream"]
    ssl_object = network_stream.get_extra_info("ssl_object")

    if ssl_object is None:
        raise ValueError(
            "No SSL object found in network stream - connection may not be using TLS"
        )

    # Get the peer/server certificate in binary (DER) format
    peer_cert = ssl_object.getpeercert(True)

    if peer_cert is None:
        raise ValueError(
            "No peer certificate found in SSL object - server may not have presented a certificate"
        )

    # Generate and return channel binding data using the server certificate
    return get_channel_binding_data(peer_cert)


def get_channel_binding_data_from_ssl_socket(ssl_socket: ssl.SSLSocket) -> bytes:
    """
    Extract channel binding data from an SSL socket.

    This function extracts the server certificate from an SSL socket
    and generates the channel binding token used for authentication.

    Args:
        ssl_socket: The SSL socket object containing TLS connection information

    Returns:
        The channel binding token as bytes

    Raises:
        ValueError: If unable to extract required TLS information from the socket
    """
    # Get the peer/server certificate in binary (DER) format
    peer_cert = ssl_socket.getpeercert(True)

    if peer_cert is None:
        raise ValueError(
            "No peer certificate found in SSL socket - server may not have presented a certificate"
        )

    # Generate and return channel binding data using the server certificate
    return get_channel_binding_data(peer_cert)
