import hashlib
import ssl
import warnings

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def _normalize_hash_name(hash_algorithm: hashes.HashAlgorithm) -> str:
    return hash_algorithm.name.lower().replace("-", "")


def _rfc5929_cert_hash(server_cert: bytes) -> bytes:
    """
    Compute the certificate hash according to RFC 5929 section 4.

    RFC 5929 defines the hash algorithm for tls-server-end-point as follows:
    1. If the certificate's signatureAlgorithm uses MD5 or SHA-1, use SHA-256.
    2. If it uses another single hash function, use that hash function.
    3. If it uses no hash function or multiple hash functions, the channel
       binding is undefined. For compatibility, this implementation falls
       back to SHA-256 and emits a warning.
    """
    cert = x509.load_der_x509_certificate(server_cert)
    hash_algorithms = set()

    sig_hash = cert.signature_hash_algorithm

    if sig_hash is not None:
        hash_algorithms.add(_normalize_hash_name(sig_hash))

    sig_params = getattr(cert, "signature_algorithm_parameters", None)

    # RSASSA-PSS can contain an additional MGF1 hash algorithm.
    # If that hash differs from the main signature hash, this falls under
    # RFC 5929's "multiple hash functions" undefined case.
    if isinstance(sig_params, padding.PSS):
        mgf = getattr(sig_params, "mgf", None)
        mgf_hash = getattr(mgf, "_algorithm", None)

        if mgf_hash is not None:
            hash_algorithms.add(_normalize_hash_name(mgf_hash))

    if len(hash_algorithms) == 0:
        warnings.warn(
            "The certificate's signatureAlgorithm uses no hash function. "
            "RFC 5929 defines tls-server-end-point channel bindings as undefined "
            "for this case. Falling back to SHA-256.",
            RuntimeWarning,
            stacklevel=2,
        )
        alg = "sha256"

    elif len(hash_algorithms) > 1:
        warnings.warn(
            "The certificate's signatureAlgorithm uses multiple hash functions. "
            "RFC 5929 defines tls-server-end-point channel bindings as undefined "
            "for this case. Falling back to SHA-256.",
            RuntimeWarning,
            stacklevel=2,
        )
        alg = "sha256"

    else:
        alg = next(iter(hash_algorithms))

        if alg in ("md5", "sha1"):
            alg = "sha256"

    try:
        return hashlib.new(alg, server_cert).digest()
    except ValueError:
        warnings.warn(
            f"The certificate's signature hash algorithm '{alg}' is not supported "
            "by hashlib. Falling back to SHA-256.",
            RuntimeWarning,
            stacklevel=2,
        )
        return hashlib.sha256(server_cert).digest()


def get_channel_binding_data(server_cert: bytes) -> bytes:
    """
    Generate channel binding token (CBT) from a server certificate.

    This implements the tls-server-end-point channel binding type as described
    in RFC 5929 section 4. The binding token is created by:
    1. Multiple scenarios for hashing the server certificate:
        1.1 If the certificate's signature algorithm is MD5 or SHA-1, hash the certificate with SHA-256
        1.2 Otherwise, hash the certificate with the same algorithm as the certificate's signature
        1.3 If the signatureAlgorithm uses no hash function or uses multiple hash functions, the behavior is implementation-defined. In this implementation, we will default to SHA-256 for any unsupported or unknown signature algorithms.
    2. Creating a channel binding structure with the hash
    3. Computing an MD5 hash of the structure

    Args:
        server_cert: Raw server certificate bytes

    Returns:
        MD5 hash of the channel binding structure (16 bytes)

    References:
        - RFC 5929: https://datatracker.ietf.org/doc/html/rfc5929#section-4
    """
    cert_hash = _rfc5929_cert_hash(server_cert)

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
