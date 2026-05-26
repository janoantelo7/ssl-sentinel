class SSLSentinelError(Exception):
    """Base exception."""

    pass


class CertificateFetchError(SSLSentinelError):
    """Raised when a connection to the server or socket cannot be established."""

    pass


class CertificateParseError(SSLSentinelError):
    """Raised when the server response is not valid or cannot be parsed."""

    pass
