from dataclasses import dataclass
from datetime import datetime


@dataclass
class CertificateStatus:
    hostname: str
    days_left: int
    expiry_date: datetime.datetime
    threshold: int

    @property
    def is_expiring_soon(self) -> bool:
        """
        Check if the certificate is near to expiry or if it's expired based in the threshold.

        Returns:
            bool
        """
        return self.days_left <= self.threshold

    @property
    def status_label(self) -> str:
        """Returns the corresponding status label."""
        if self.is_expiring_soon:
            return "WARNING"
        else:
            return "OK"
