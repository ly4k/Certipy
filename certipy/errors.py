from impacket import hresult_errors


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
