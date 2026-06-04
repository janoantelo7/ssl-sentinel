import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from ssl_sentinel.exceptions import CertificateFetchError, CertificateParseError
from ssl_sentinel.models import CertificateStatus


def parse_url_or_host(target: str) -> tuple[str, int]:
    """

    Return:
        tuple
    """
    target = target.strip()

    if "://" not in target:
        parsed = urlparse("https://" + target)
    else:
        parsed = urlparse(target)

    clean_hostname = parsed.hostname or target
    port = parsed.port if parsed.port is not None else 443

    return clean_hostname, port


def fetch_certificate_status(
    hostname: str, threshold: int = 30, timeout: float = 0.5
) -> CertificateStatus:
    """
    Fetch and parse the SSL certificate status for a given hostname.

    Args:
        hostname (str): The domain name to fetch the certificate for.
        threshold (int): The number of days remaining to consider the certificate as expiring soon. Default is 30.
        timeout (float): The timeout in seconds for the socket connection. Default is 0.5.

    Returns:
        CertificateStatus: An object containing the certificate status details.

    Raises:
        CertificateFetchError: If the connection to the server fails.
        CertificateParseError: If the server does not return a certificate or if the certificate cannot be parsed.
    """

    clean_hostname, port = parse_url_or_host(hostname)

    context = ssl.create_default_context()
    try:
        with socket.create_connection((clean_hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=clean_hostname) as ssock:
                cert = ssock.getpeercert()
    except (OSError, ssl.SSLError, ValueError) as e:
        raise CertificateFetchError(f"Could not connect to {clean_hostname}: {e}")

    if not cert:
        raise CertificateParseError("The server did not return a certificate.")

    try:
        expiry_date_str = cert.get("notAfter")
        if not expiry_date_str:
            raise ValueError("Value 'notAfter' not found in the certificate.")
        expiry_date = datetime.strptime(str(expiry_date_str), "%b %d %H:%M:%S %Y %Z")
    except (ValueError, KeyError) as e:
        raise CertificateParseError(
            f"Issue analyzing the certificate for {hostname}: {e}"
        )

    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)

    days_left = (expiry_date - now_utc).days

    return CertificateStatus(
        hostname=hostname,
        days_left=days_left,
        expiry_date=expiry_date,
        threshold=threshold,
    )
