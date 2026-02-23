import unittest
import sys
import os
import datetime
from unittest.mock import MagicMock, patch

# Add src to path so we can import ssl_sentinel
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from ssl_sentinel.certificate import Certificate

class TestCertificate(unittest.TestCase):

    @patch('ssl_sentinel.certificate.ssl')
    @patch('ssl_sentinel.certificate.socket')
    def test_fetch_certificate_success(self, mock_socket, mock_ssl):
        """Test successful certificate retrieval."""
        # Fix SSLError issue
        mock_ssl.SSLError = Exception

        # Setup mocks BEFORE instantiation
        mock_sock_obj = MagicMock()
        mock_socket.create_connection.return_value.__enter__.return_value = mock_sock_obj

        mock_ssl_context = MagicMock()
        mock_ssl.create_default_context.return_value = mock_ssl_context

        mock_ssock = MagicMock()
        mock_ssl_context.wrap_socket.return_value.__enter__.return_value = mock_ssock

        # Mock certificate data
        expected_expiry_str = "May 26 00:00:00 2024 GMT"
        mock_ssock.getpeercert.return_value = {"notAfter": expected_expiry_str}

        hostname = "example.com"
        cert_instance = Certificate(hostname)

        # Call fetch certificate (indirectly or directly)
        cert_instance._fetch_certificate()

        self.assertIsNotNone(cert_instance._cert)
        self.assertEqual(cert_instance._cert["notAfter"], expected_expiry_str)

    @patch('ssl_sentinel.certificate.ssl')
    @patch('ssl_sentinel.certificate.socket')
    def test_fetch_certificate_connection_error(self, mock_socket, mock_ssl):
        """Test handling of connection error during fetch."""
        # Fix SSLError issue
        mock_ssl.SSLError = Exception

        # Simulate socket error
        mock_socket.create_connection.side_effect = OSError("Connection refused")

        hostname = "example.com"
        cert_instance = Certificate(hostname)

        with self.assertRaises(ConnectionError):
            cert_instance._fetch_certificate()

    @patch('ssl_sentinel.certificate.ssl')
    @patch('ssl_sentinel.certificate.socket')
    def test_get_expiry_date_timezone_aware(self, mock_socket, mock_ssl):
        """Test that expiry date is timezone aware (UTC)."""
        # Fix SSLError issue
        mock_ssl.SSLError = Exception

        # Mock fetch process
        mock_sock_obj = MagicMock()
        mock_socket.create_connection.return_value.__enter__.return_value = mock_sock_obj

        mock_ssl_context = MagicMock()
        mock_ssl.create_default_context.return_value = mock_ssl_context

        mock_ssock = MagicMock()
        mock_ssl_context.wrap_socket.return_value.__enter__.return_value = mock_ssock

        mock_ssock.getpeercert.return_value = {"notAfter": "May 26 00:00:00 2024 GMT"}

        hostname = "example.com"
        cert_instance = Certificate(hostname)

        expiry_date = cert_instance._get_expiry_date()

        # Assert it is timezone aware and UTC
        self.assertIsNotNone(expiry_date.tzinfo)
        self.assertEqual(expiry_date.tzinfo, datetime.timezone.utc)

        # Check date value
        expected_date = datetime.datetime(2024, 5, 26, 0, 0, 0, tzinfo=datetime.timezone.utc)
        self.assertEqual(expiry_date, expected_date)

    @patch('ssl_sentinel.certificate.ssl')
    @patch('ssl_sentinel.certificate.socket')
    def test_get_expiry_status_success(self, mock_socket, mock_ssl):
        """Test get_expiry_status returns OK for valid future date."""
        # Fix SSLError issue
        mock_ssl.SSLError = Exception

        # Mock logic
        mock_sock_obj = MagicMock()
        mock_socket.create_connection.return_value.__enter__.return_value = mock_sock_obj
        mock_ssl_context = MagicMock()
        mock_ssl.create_default_context.return_value = mock_ssl_context
        mock_ssock = MagicMock()
        mock_ssl_context.wrap_socket.return_value.__enter__.return_value = mock_ssock

        # Set a future date far enough
        future_date = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=100)
        future_date_str = future_date.strftime("%b %d %H:%M:%S %Y GMT")
        mock_ssock.getpeercert.return_value = {"notAfter": future_date_str}

        hostname = "example.com"
        cert_instance = Certificate(hostname)

        status = cert_instance.get_expiry_status()

        self.assertEqual(status["status"], "OK")
        self.assertIsNone(status["error"])
        self.assertIsInstance(status["days_left"], int)
        self.assertGreater(status["days_left"], 30)

    @patch('ssl_sentinel.certificate.ssl')
    @patch('ssl_sentinel.certificate.socket')
    def test_get_expiry_status_connection_error(self, mock_socket, mock_ssl):
        """Test get_expiry_status returns ERROR on ConnectionError."""
        # Fix SSLError issue
        mock_ssl.SSLError = Exception

        # Simulate connection error
        mock_socket.create_connection.side_effect = OSError("Connection refused")

        hostname = "example.com"
        cert_instance = Certificate(hostname)

        # Expectation: Currently it raises ConnectionError, but we want it to return ERROR dict
        try:
            status = cert_instance.get_expiry_status()
            self.assertEqual(status["status"], "ERROR")
            self.assertIn("Connection refused", status["error"])
        except ConnectionError:
            self.fail("get_expiry_status raised ConnectionError instead of returning ERROR status")

    @patch('ssl_sentinel.certificate.ssl')
    @patch('ssl_sentinel.certificate.socket')
    def test_get_expiry_status_value_error(self, mock_socket, mock_ssl):
        """Test get_expiry_status returns ERROR on ValueError (invalid date)."""
        # Fix SSLError issue
        mock_ssl.SSLError = Exception

        # Mock logic
        mock_sock_obj = MagicMock()
        mock_socket.create_connection.return_value.__enter__.return_value = mock_sock_obj
        mock_ssl_context = MagicMock()
        mock_ssl.create_default_context.return_value = mock_ssl_context
        mock_ssock = MagicMock()
        mock_ssl_context.wrap_socket.return_value.__enter__.return_value = mock_ssock

        # Invalid date format
        mock_ssock.getpeercert.return_value = {"notAfter": "Invalid Date String"}

        hostname = "example.com"
        cert_instance = Certificate(hostname)

        status = cert_instance.get_expiry_status()

        self.assertEqual(status["status"], "ERROR")
        self.assertIsNotNone(status["error"])

if __name__ == '__main__':
    unittest.main()
