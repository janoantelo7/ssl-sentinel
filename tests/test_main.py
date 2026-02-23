import unittest
import sys
import os
import datetime
from unittest.mock import MagicMock, patch
import io

# Add src to path so we can import ssl_sentinel
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from ssl_sentinel.main import process_hostname

class TestMain(unittest.TestCase):

    @patch('ssl_sentinel.main.Certificate')
    def test_process_hostname_success(self, mock_certificate):
        """Test process_hostname with valid certificate."""
        # Setup mock
        mock_instance = mock_certificate.return_value
        expiry_date = datetime.datetime.now() + datetime.timedelta(days=100)
        mock_instance.get_expiry_status.return_value = {
            "status": "OK",
            "days_left": 100,
            "expiry_date": expiry_date,
            "error": None
        }

        # Capture stdout
        with patch('sys.stdout', new=io.StringIO()) as fake_out:
            result = process_hostname("example.com", 30)

            self.assertTrue(result)
            output = fake_out.getvalue()
            self.assertIn("Checking certificate for example.com", output)
            self.assertIn("Expires in 100 days", output)

    @patch('ssl_sentinel.main.Certificate')
    def test_process_hostname_error_status(self, mock_certificate):
        """Test process_hostname handles ERROR status gracefully."""
        # Setup mock
        mock_instance = mock_certificate.return_value
        mock_instance.get_expiry_status.return_value = {
            "status": "ERROR",
            "days_left": None,
            "expiry_date": None,
            "error": "Connection failed"
        }

        with patch('sys.stderr', new=io.StringIO()) as fake_err:
             # Capture stdout as well to avoid clutter
            with patch('sys.stdout', new=io.StringIO()) as fake_out:
                try:
                    result = process_hostname("example.com", 30)
                    # If fixed, it should return True (as per existing error handling logic)
                    self.assertTrue(result)

                    # Verify stderr was written to if we fix logic to print error
                    # Wait, in the proposed fix, we should print error.
                    # In current buggy code, it crashes.
                except AttributeError:
                    self.fail("process_hostname raised AttributeError on ERROR status")

    @patch('ssl_sentinel.main.Certificate')
    def test_process_hostname_expiring_soon_filter(self, mock_certificate):
        """Test expiring_soon filter."""
        # Setup mock for OK status (not expiring)
        mock_instance = mock_certificate.return_value
        expiry_date = datetime.datetime.now() + datetime.timedelta(days=100)
        mock_instance.get_expiry_status.return_value = {
            "status": "OK",
            "days_left": 100,
            "expiry_date": expiry_date,
            "error": None
        }

        # expiring_soon=True, status=OK -> Should return False (filtered out)
        result = process_hostname("example.com", 30, expiring_soon=True)
        self.assertFalse(result)

        # Setup mock for WARNING status (expiring)
        mock_instance.get_expiry_status.return_value = {
            "status": "WARNING",
            "days_left": 10,
            "expiry_date": expiry_date,
            "error": None
        }

        # expiring_soon=True, status=WARNING -> Should return True (shown)
        with patch('sys.stdout', new=io.StringIO()):
            result = process_hostname("example.com", 30, expiring_soon=True)
            self.assertTrue(result)

if __name__ == '__main__':
    unittest.main()
