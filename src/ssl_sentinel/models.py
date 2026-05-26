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
