import hashlib

import httpx


def get_channel_binding_data(
    server_cert: bytes,
) -> bytes:
    server_cert = hashlib.sha256(server_cert).digest()

    channel_binding_struct = b""
    initiator_address = b"\x00" * 8
    acceptor_address = b"\x00" * 8

    # https://datatracker.ietf.org/doc/html/rfc5929#section-4
    application_data_raw = b"tls-server-end-point:" + server_cert
    len_application_data = len(application_data_raw).to_bytes(
        4, byteorder="little", signed=False
    )
    application_data = len_application_data
    application_data += application_data_raw
    channel_binding_struct += initiator_address
    channel_binding_struct += acceptor_address
    channel_binding_struct += application_data

    return hashlib.md5(channel_binding_struct).digest()


def get_channel_binding_data_from_response(
    response: httpx.Response,
) -> bytes:
    """
    Extract channel binding data from the HTTPX response.

    Args:
        response: The HTTPX response object

    Returns:
        The channel binding data if available, otherwise None
    """
    if "network_stream" not in response.extensions:
        raise ValueError("No network stream found in response")

    # Extract the TLS/SSL object from the network stream
    ssl_object = response.extensions["network_stream"].get_extra_info("ssl_object")
    if ssl_object is None:
        raise ValueError("No SSL object found in network stream")
    # Get the peer/server certificate from the TLS/SSL object
    peer_cert = ssl_object.getpeercert(True)
    if peer_cert is None:
        raise ValueError("No peer certificate found in SSL object")
    # Generate channel binding data using the peer certificate
    channel_binding_data = get_channel_binding_data(peer_cert)
    return channel_binding_data
