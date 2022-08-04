from impacket import hresult_errors
from impacket.krb5.kerberosv5 import constants as krb5_constants

"""
// RFC 4556
77: "KDC_ERR_INCONSISTENT_KEY_PURPOSE"
78: "KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED"
79: "KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED"
80: "KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED"
81: "KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED"
 // RFC 6113
90: "KDC_ERR_PREAUTH_EXPIRED"
91: "KDC_ERR_MORE_PREAUTH_DATA_REQUIRED"
92: "KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET"
93: "KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS"
"""

KRB5_ERROR_MESSAGES = krb5_constants.ERROR_MESSAGES
if 77 not in KRB5_ERROR_MESSAGES:
    KRB5_ERROR_MESSAGES.update(
        {
            77: (
                "KDC_ERR_INCONSISTENT_KEY_PURPOSE",
                "Certificate cannot be used for PKINIT client authentication",
            ),
            78: (
                "KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED",
                "Digest algorithm for the public key in the certificate is not acceptable by the KDC",
            ),
            79: (
                "KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED",
                "The paChecksum filed in the request is not present",
            ),
            80: (
                "KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED",
                "The digest algorithm used by the id-pkinit-authData is not acceptable by the KDC",
            ),
            81: (
                "KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED",
                "The KDC does not support the public key encryption key delivery method",
            ),
            90: (
                "KDC_ERR_PREAUTH_EXPIRED",
                "The conversation is too old and needs to restart",
            ),
            91: (
                "KDC_ERR_MORE_PREAUTH_DATA_REQUIRED",
                "Additional pre-authentication required",
            ),
            92: (
                "KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET",
                "KDC cannot accommodate requested padata element",
            ),
            93: ("KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS", "Unknown critical option"),
        }
    )


def translate_error_code(error_code: int) -> str:
    error_code &= 0xFFFFFFFF
    if error_code in hresult_errors.ERROR_MESSAGES:
        error_msg_short = hresult_errors.ERROR_MESSAGES[error_code][0]
        error_msg_verbose = hresult_errors.ERROR_MESSAGES[error_code][1]
        return "code: 0x%x - %s - %s" % (
            error_code,
            error_msg_short,
            error_msg_verbose,
        )
    else:
        return "unknown error code: 0x%x" % error_code
