import unittest
from unittest.mock import patch, MagicMock
import responses
from ..xss import XSSScanner

class TestXSSScanner(unittest.TestCase):
    def setUp(self):
        self.target_url = "https://example.com"
        self.scanner = XSSScanner(self.target_url)

    @responses.activate
    def test_form_detection(self):
        # Mock HTML with form containing potential XSS targets
        html_content = """
        <form action="/search" method="GET">
            <input type="text" name="q">
            <textarea name="comment"></textarea>
            <input type="submit" value="Search">
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
        self.assertEqual(forms[0]['action'], '/search')
        self.assertEqual(len(forms[0]['inputs']), 2)

    @responses.activate
    def test_reflected_xss_detection(self):
        # Mock reflected XSS response
        test_payload = "<script>alert(1)</script>"
        responses.add(
            responses.GET,
            f"{self.target_url}/search",
            body=f"Search results for: {test_payload}",
            status=200
        )

        result = self.scanner.test_reflected_xss(
            "/search",
            {"q": test_payload}
        )
        self.assertTrue(result['vulnerable'])
        self.assertIn(test_payload, result['evidence'])

    @responses.activate
    def test_stored_xss_detection(self):
        # Mock comment submission and retrieval
        responses.add(
            responses.POST,
            f"{self.target_url}/comment",
            body="Comment posted successfully",
            status=200
        )

        responses.add(
            responses.GET,
            f"{self.target_url}/comments",
            body='<div class="comment"><script>alert(1)</script></div>',
            status=200
        )

        result = self.scanner.test_stored_xss(
            "/comment",
            {"comment": "<script>alert(1)</script>"}
        )
        self.assertTrue(result['vulnerable'])
        self.assertIn('script', result['evidence'])

    def test_generate_payloads(self):
        payloads = self.scanner.generate_payloads()
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        self.assertTrue(any('<script>' in p for p in payloads))
        self.assertTrue(any('onerror=' in p for p in payloads))

    @responses.activate
    def test_dom_xss_detection(self):
        # Mock page with potential DOM XSS
        html_content = """
        <script>
            var name = location.hash.substring(1);
            document.write("Hello " + name);
        </script>
        """
        responses.add(
            responses.GET,
            self.target_url,
            body=html_content,
            status=200
        )

        result = self.scanner.test_dom_xss()
        self.assertIsInstance(result, dict)
        self.assertIn('vulnerable_sources', result)
        self.assertIn('vulnerable_sinks', result)

    @responses.activate
    def test_full_scan(self):
        # Mock initial page
        responses.add(
            responses.GET,
            self.target_url,
            body='<form action="/search"><input name="q"></form>',
            status=200
        )

        # Mock search results
        responses.add(
            responses.GET,
            f"{self.target_url}/search",
            body='<script>alert(1)</script>',
            status=200
        )

        results = self.scanner.run_scan()
        self.assertIsInstance(results, dict)
        self.assertIn('forms_tested', results)
        self.assertIn('vulnerabilities', results)
        self.assertIn('payloads_tested', results)

if __name__ == '__main__':
    unittest.main()