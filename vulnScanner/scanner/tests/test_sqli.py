import unittest
from unittest.mock import patch, MagicMock
import responses
from ..sqli import SQLiScanner

class TestSQLiScanner(unittest.TestCase):
    def setUp(self):
        self.target_url = "https://example.com"
        self.scanner = SQLiScanner(self.target_url)

    @responses.activate
    def test_form_detection(self):
        # Mock HTML with login form
        html_content = """
        <form action="/login" method="POST">
            <input type="text" name="username">
            <input type="password" name="password">
            <input type="submit" value="Login">
        </form>
        """
        responses.add(
            responses.GET,
            self.target_url,
            body=html_content,
            status=200,
            content_type='text/html'
        )

        forms = self.scanner.detect_forms()
        self.assertGreater(len(forms), 0)
        self.assertEqual(forms[0]['action'], '/login')
        self.assertEqual(len(forms[0]['inputs']), 2)

    @responses.activate
    def test_error_based_detection(self):
        # Mock vulnerable response
        responses.add(
            responses.POST,
            f"{self.target_url}/login",
            body="SQL syntax error in query",
            status=200
        )

        result = self.scanner.test_error_based_injection(
            "/login",
            {"username": "' OR '1'='1", "password": "test"}
        )
        self.assertTrue(result['vulnerable'])
        self.assertIn('SQL syntax error', result['evidence'])

    @responses.activate
    def test_boolean_based_detection(self):
        # Mock different responses for true/false conditions
        responses.add(
            responses.POST,
            f"{self.target_url}/login",
            body="Welcome back",
            status=200
        )
        
        responses.add(
            responses.POST,
            f"{self.target_url}/login",
            body="Invalid credentials",
            status=401
        )

        result = self.scanner.test_boolean_based_injection(
            "/login",
            {"username": "admin' OR '1'='1", "password": "test"}
        )
        self.assertTrue(result['vulnerable'])
        self.assertIn('different responses', result['evidence'])

    def test_generate_payloads(self):
        payloads = self.scanner.generate_payloads()
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        self.assertIn("' OR '1'='1", payloads)

    @responses.activate
    def test_full_scan(self):
        # Mock form page
        responses.add(
            responses.GET,
            self.target_url,
            body='<form action="/login" method="POST"><input name="username"></form>',
            status=200
        )

        # Mock form submission
        responses.add(
            responses.POST,
            f"{self.target_url}/login",
            body="SQL syntax error",
            status=200
        )

        results = self.scanner.run_scan()
        self.assertIsInstance(results, dict)
        self.assertIn('forms_tested', results)
        self.assertIn('vulnerabilities', results)

if __name__ == '__main__':
    unittest.main()