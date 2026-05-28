import sys
import os
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
import requests

# Ensure the current directory is in python path for local imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import check_ise_cert

def raise_system_exit(code=None, *args, **kwargs):
    raise SystemExit(code)

class TestCertChecker(unittest.TestCase):

    @patch('sys.stderr')
    @patch('sys.stdout')
    @patch('sys.exit')
    def test_no_arguments_prints_usage_guide(self, mock_exit, mock_stdout, mock_stderr):
        """Test that running with no arguments prints the usage guide and exits with code 3 (UNKNOWN)."""
        mock_exit.side_effect = raise_system_exit
        
        with patch('sys.argv', ['check_ise_cert.py']):
            with self.assertRaises(SystemExit) as cm:
                check_ise_cert.main()
            
            # Verify exit code was 3
            self.assertEqual(cm.exception.code, 3)
            
            # Verify that the usage guide was printed to stderr (guide begins with "Cisco ISE Certificate")
            stderr_calls = "".join(call.args[0] for call in mock_stderr.write.call_args_list)
            self.assertIn("Cisco ISE Certificate Expiration Checker", stderr_calls)

    @patch('sys.stdout')
    @patch('sys.exit')
    @patch('requests.get')
    def test_primary_pan_unauthorized(self, mock_get, mock_exit, mock_stdout):
        """Test that a 401 Unauthorized from the primary PAN outputs a clear CRITICAL and exits with 2."""
        mock_exit.side_effect = raise_system_exit
        
        # Mock a 401 response
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            "401 Client Error: Unauthorized", response=mock_response
        )
        mock_get.return_value = mock_response

        with patch('sys.argv', ['check_ise_cert.py', '-H', 'ise.local', '-u', 'user', '-p', 'pass', '-m', 'Admin']):
            with self.assertRaises(SystemExit) as cm:
                check_ise_cert.main()
            
            self.assertEqual(cm.exception.code, 2)
            stdout_calls = "".join(call.args[0] for call in mock_stdout.write.call_args_list)
            self.assertIn("CRITICAL: Primary PAN ise.local returned 401 Unauthorized", stdout_calls)

    @patch('sys.stdout')
    @patch('sys.exit')
    @patch('requests.get')
    def test_primary_pan_connection_error(self, mock_get, mock_exit, mock_stdout):
        """Test connection failure on primary PAN exits with code 2."""
        mock_exit.side_effect = raise_system_exit
        mock_get.side_effect = requests.exceptions.ConnectionError("Connection refused")

        with patch('sys.argv', ['check_ise_cert.py', '-H', 'ise.local', '-u', 'user', '-p', 'pass', '-m', 'Admin']):
            with self.assertRaises(SystemExit) as cm:
                check_ise_cert.main()
            
            self.assertEqual(cm.exception.code, 2)
            stdout_calls = "".join(call.args[0] for call in mock_stdout.write.call_args_list)
            self.assertIn("CRITICAL: Primary PAN ise.local is unreachable", stdout_calls)

    @patch('sys.stdout')
    @patch('sys.exit')
    @patch('requests.get')
    def test_certificates_ok(self, mock_get, mock_exit, mock_stdout):
        """Test that valid certificates return OK status with correct metrics."""
        mock_exit.side_effect = raise_system_exit
        
        # 1. Mock deployment/node response
        nodes_response = MagicMock()
        nodes_response.status_code = 200
        nodes_response.json.return_value = {
            "response": [
                {"hostname": "ise-node1"}
            ]
        }

        # 2. Mock cert response (valid for 50 days). Add 1 hour buffer to avoid rounding down.
        expiry_date = (datetime.now() + timedelta(days=50, hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        cert_response = MagicMock()
        cert_response.status_code = 200
        cert_response.json.return_value = {
            "response": [
                {
                    "id": "cert-1",
                    "friendlyName": "ISE Admin Cert",
                    "expirationDate": expiry_date,
                    "usedBy": "Admin, Portal"
                }
            ]
        }

        # Configure mock_get side effect
        mock_get.side_effect = [nodes_response, cert_response]

        with patch('sys.argv', ['check_ise_cert.py', '-H', 'ise.local', '-u', 'user', '-p', 'pass', '-m', 'Admin']):
            with self.assertRaises(SystemExit) as cm:
                check_ise_cert.main()
            
            self.assertEqual(cm.exception.code, 0)
            stdout_calls = "".join(call.args[0] for call in mock_stdout.write.call_args_list)
            self.assertIn("OK: Checked 1 certs for 'Admin' across 1 nodes.", stdout_calls)
            # Check for Nagios performance data
            self.assertIn("| min_days_left=50;30;15;0;", stdout_calls)

    @patch('sys.stdout')
    @patch('sys.exit')
    @patch('requests.get')
    def test_certificates_expiring(self, mock_get, mock_exit, mock_stdout):
        """Test warning and critical alerts when certificates are expiring."""
        mock_exit.side_effect = raise_system_exit
        
        # Mock deployment/node response with two nodes
        nodes_response = MagicMock()
        nodes_response.status_code = 200
        nodes_response.json.return_value = {
            "response": [
                {"hostname": "ise-node1"},
                {"hostname": "ise-node2"}
            ]
        }

        # Mock cert response for ise-node1 (critical: 10 days remaining). Add 1 hour buffer.
        crit_expiry = (datetime.now() + timedelta(days=10, hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        cert1_response = MagicMock()
        cert1_response.status_code = 200
        cert1_response.json.return_value = {
            "response": [
                {
                    "id": "cert-1",
                    "friendlyName": "Node1 Admin Cert",
                    "expirationDate": crit_expiry,
                    "usedBy": ["Admin"] # test list format
                }
            ]
        }

        # Mock cert response for ise-node2 (warning: 25 days remaining). Add 1 hour buffer.
        warn_expiry = (datetime.now() + timedelta(days=25, hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        cert2_response = MagicMock()
        cert2_response.status_code = 200
        cert2_response.json.return_value = {
            "response": [
                {
                    "id": "cert-2",
                    "friendlyName": "Node2 Admin Cert",
                    "expirationDate": warn_expiry,
                    "usedBy": "Admin, EAP" # test string format
                }
            ]
        }

        mock_get.side_effect = [nodes_response, cert1_response, cert2_response]

        with patch('sys.argv', ['check_ise_cert.py', '-H', 'ise.local', '-u', 'user', '-p', 'pass', '-m', 'Admin', '-w', '30', '-c', '15']):
            with self.assertRaises(SystemExit) as cm:
                check_ise_cert.main()
            
            # Since critical exists, exit code must be 2
            self.assertEqual(cm.exception.code, 2)
            stdout_calls = "".join(call.args[0] for call in mock_stdout.write.call_args_list)
            
            # Output should contain both alerts separated by a comma (no pipe characters except for perf data)
            self.assertIn("CRIT: [ise-node1] Node1 Admin Cert (10d)", stdout_calls)
            self.assertIn("WARN: [ise-node2] Node2 Admin Cert (25d)", stdout_calls)
            self.assertIn(", ", stdout_calls)
            self.assertNotIn("CRIT: [ise-node1] Node1 Admin Cert (10d) | WARN", stdout_calls)
            
            # Check performance metrics (should track the minimum: 10 days)
            self.assertIn("| min_days_left=10;30;15;0;", stdout_calls)

    @patch('sys.stdout')
    @patch('sys.exit')
    @patch('requests.get')
    def test_secondary_node_unreachable(self, mock_get, mock_exit, mock_stdout):
        """Test secondary node unreachable handles error gracefully and returns WARNING."""
        mock_exit.side_effect = raise_system_exit
        
        nodes_response = MagicMock()
        nodes_response.status_code = 200
        nodes_response.json.return_value = {
            "response": [
                {"hostname": "ise-node1"},
                {"hostname": "ise-node2"}
            ]
        }

        # Node1 response ok. Add 1 hour buffer.
        expiry = (datetime.now() + timedelta(days=50, hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        cert1_response = MagicMock()
        cert1_response.status_code = 200
        cert1_response.json.return_value = {
            "response": [
                {
                    "id": "cert-1",
                    "friendlyName": "Node1 Admin",
                    "expirationDate": expiry,
                    "usedBy": "Admin"
                }
            ]
        }

        # Node2 fails with HTTP 500
        mock_node2_error_resp = MagicMock()
        mock_node2_error_resp.status_code = 500
        node2_error = requests.exceptions.HTTPError("Internal Server Error", response=mock_node2_error_resp)

        mock_get.side_effect = [nodes_response, cert1_response, node2_error]

        with patch('sys.argv', ['check_ise_cert.py', '-H', 'ise.local', '-u', 'user', '-p', 'pass', '-m', 'Admin']):
            with self.assertRaises(SystemExit) as cm:
                check_ise_cert.main()
            
            # Exit code must be 1 (WARNING) because a node was unreachable
            self.assertEqual(cm.exception.code, 1)
            stdout_calls = "".join(call.args[0] for call in mock_stdout.write.call_args_list)
            
            self.assertIn("Unreachable: ise-node2 (HTTP 500)", stdout_calls)
            self.assertIn("| min_days_left=50;30;15;0;", stdout_calls)

    @patch('sys.stdout')
    @patch('sys.exit')
    @patch('requests.get')
    def test_unparsable_date_format(self, mock_get, mock_exit, mock_stdout):
        """Test that a certificate with an unparsable date is reported as UNKNOWN."""
        mock_exit.side_effect = raise_system_exit
        
        nodes_response = MagicMock()
        nodes_response.status_code = 200
        nodes_response.json.return_value = {
            "response": [
                {"hostname": "ise-node1"}
            ]
        }

        cert_response = MagicMock()
        cert_response.status_code = 200
        cert_response.json.return_value = {
            "response": [
                {
                    "id": "cert-1",
                    "friendlyName": "Bad Date Cert",
                    "expirationDate": "31-12-2026", # Unsupported format
                    "usedBy": "Admin"
                }
            ]
        }

        mock_get.side_effect = [nodes_response, cert_response]

        with patch('sys.argv', ['check_ise_cert.py', '-H', 'ise.local', '-u', 'user', '-p', 'pass', '-m', 'Admin']):
            with self.assertRaises(SystemExit) as cm:
                check_ise_cert.main()
            
            self.assertEqual(cm.exception.code, 3) # UNKNOWN
            stdout_calls = "".join(call.args[0] for call in mock_stdout.write.call_args_list)
            self.assertIn("UNKNOWN: [ise-node1] Bad Date Cert expiration date '31-12-2026' format not recognized", stdout_calls)

    @patch('sys.stdout')
    @patch('sys.exit')
    @patch('requests.get')
    def test_timezone_date_parsing_fallback(self, mock_get, mock_exit, mock_stdout):
        """Test that a certificate with CEST-style timezone date is parsed successfully."""
        mock_exit.side_effect = raise_system_exit
        
        nodes_response = MagicMock()
        nodes_response.status_code = 200
        nodes_response.json.return_value = {
            "response": [{"hostname": "ise-node1"}]
        }

        # Generate a dynamic date with CEST format (e.g. "Thu Sep 03 10:11:48 CEST 2026")
        expiry_dt = datetime.now() + timedelta(days=50, hours=1)
        expiry_str = expiry_dt.strftime("%a %b %d %H:%M:%S CEST %Y")

        cert_response = MagicMock()
        cert_response.status_code = 200
        cert_response.json.return_value = {
            "response": [
                {
                    "id": "cert-1",
                    "friendlyName": "CEST Cert",
                    "expirationDate": expiry_str,
                    "usedBy": "Admin"
                }
            ]
        }

        mock_get.side_effect = [nodes_response, cert_response]

        with patch('sys.argv', ['check_ise_cert.py', '-H', 'ise.local', '-u', 'user', '-p', 'pass', '-m', 'Admin']):
            with self.assertRaises(SystemExit) as cm:
                check_ise_cert.main()
            
            self.assertEqual(cm.exception.code, 0)
            stdout_calls = "".join(call.args[0] for call in mock_stdout.write.call_args_list)
            self.assertIn("OK: Checked 1 certs for 'Admin' across 1 nodes.", stdout_calls)
            self.assertIn("| min_days_left=50;30;15;0;", stdout_calls)

    @patch('check_ise_cert.check_certs')
    def test_dotenv_fallback_loading(self, mock_check_certs):
        """Test that arguments can be successfully parsed from a .env file."""
        env_content = """
        # Cisco ISE Configuration
        ISE_HOST = env-host.local
        ISE_USER = 'env-user'
        ISE_PASSWORD = "env-password"
        ISE_USAGE = "Admin, RADIUS"
        ISE_WARNING = 40
        ISE_CRITICAL = 20
        ISE_SSL_VERIFY = true
        """
        env_file_path = ".env"
        
        # Write temporary .env
        with open(env_file_path, "w") as f:
            f.write(env_content)
            
        try:
            # We patch sys.argv to simulate running with no arguments.
            # It should load the values from .env instead of failing on required check.
            # Also clear os.environ to ensure it reads purely from our .env file.
            with patch.dict(os.environ, {}, clear=True):
                with patch('sys.argv', ['check_ise_cert.py']):
                    check_ise_cert.main()
                    
                    mock_check_certs.assert_called_once_with(
                        host="env-host.local",
                        user="env-user",
                        password="env-password",
                        usage_input="Admin, RADIUS",
                        warn=40,
                        crit=20,
                        ssl_verify=True,
                        verbose=False
                    )
        finally:
            if os.path.exists(env_file_path):
                os.remove(env_file_path)

if __name__ == '__main__':
    unittest.main()
