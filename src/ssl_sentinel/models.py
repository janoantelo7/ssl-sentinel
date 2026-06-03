from dataclasses import dataclass
from datetime import datetime


@dataclass
class CertificateStatus:
    """
    Data class to represent the status of an SSL certificate.

    Attributes:
        hostname (str): The domain name associated with the certificate.
        days_left (int): The number of days remaining until the certificate expires.
        expiry_date (datetime): The exact date and time when the certificate expires.
        threshold (int): The number of days used as a threshold to determine if the certificate is expiring soon.
    """

    hostname: str
    days_left: int
    expiry_date: datetime
    threshold: int

    @property
    def is_expiring_soon(self) -> bool:
        """
        Check if the certificate is near expiry or if it has already expired based on the threshold.

        Returns:
            bool: True if the certificate expires within the threshold number of days, False otherwise.
        """
        return self.days_left <= self.threshold

    @property
    def status_label(self) -> str:
        """
        Returns the corresponding status label for the certificate.

        Returns:
            str: "WARNING" if the certificate is expiring soon, otherwise "OK".
        """
        if self.is_expiring_soon:
            return "WARNING"
        else:
            return "OK"


@dataclass
class CheckResult:
    """
    Data class to represent the final status of checking a certificate.

    Attributes:
        hostname (str): The domain name that was checked.
        success (bool): Whether the certificate check succeeded.
        status (str): The check status ("OK", "WARNING", or "ERROR").
        days_left (int | None): Days remaining until expiration, or None if check failed.
        expiry_date (datetime | None): Expiration date/time, or None if check failed.
        error (str | None): The exception error message if the check failed.
    """

    hostname: str
    success: bool
    status: str
    days_left: int | None = None
    expiry_date: datetime | None = None
    error: str | None = None
