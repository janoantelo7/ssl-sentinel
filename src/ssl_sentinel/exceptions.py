class SSLSentinelError(Exception):
    """Base exception."""

    pass


class CertificateFetchError(SSLSentinelError):
    """Raised when it can't connect with the server or socket."""

    pass


class CertificateParseError(SSLSentinelError):
    """Raised when the responde is not valid."""

    pass
