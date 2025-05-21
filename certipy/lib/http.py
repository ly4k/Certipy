from typing import Literal


def get_authentication_method(
    authenticate_header: str,
) -> Literal["NTLM", "Negotiate"]:
    """
    Get the authentication method from the WWW-Authenticate header.

    Args:
        authenticate_header: The WWW-Authenticate header value

    Returns:
        The authentication method (e.g., "NTLM", "Negotiate")
    """
    authenticate_header = authenticate_header.lower()
    if "ntlm" in authenticate_header:
        return "NTLM"
    elif "negotiate" in authenticate_header:
        return "Negotiate"
    else:
        raise ValueError(f"Unsupported authentication method: {authenticate_header}")
