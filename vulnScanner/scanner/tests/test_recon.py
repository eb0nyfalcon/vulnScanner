import unittest
from ..recon import ReconScanner
import responses
import dns.resolver
from unittest.mock import patch, MagicMock

class TestReconScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = ReconScanner("https://example.com")
        self.test_domain = "example.com"

    @patch('whois.whois')
    def test_whois_scan(self, mock_whois):
        # Mock WHOIS response
        mock_whois_response = MagicMock()
        mock_whois_response.domain_name = "example.com"
        mock_whois_response.registrar = "Test Registrar"
        mock_whois_response.creation_date = "2020-01-01"
        mock_whois_response.expiration_date = "2025-01-01"
        mock_whois_response.name_servers = ["ns1.example.com"]
        mock_whois.return_value = mock_whois_response

        result = self.scanner.scan_whois()
        self.assertIsInstance(result, dict)
        self.assertEqual(result['domain_name'], "example.com")
        self.assertEqual(result['registrar'], "Test Registrar")

    @patch('dns.resolver.resolve')
    def test_dns_scan(self, mock_resolve):
        # Mock DNS response
        mock_dns_response = MagicMock()
        mock_dns_response.__str__.return_value = "93.184.216.34"
        mock_resolve.return_value = [mock_dns_response]

        result = self.scanner.scan_dns()
        self.assertIsInstance(result, dict)
        self.assertIn('A', result)
        self.assertIsInstance(result['A'], list)

    @responses.activate
    def test_headers_scan(self):
        # Mock HTTP response headers
        responses.add(
            responses.HEAD,
            'https://example.com',
            headers={
                'Server': 'nginx',
                'X-Frame-Options': 'DENY',
                'Content-Type': 'text/html'
            },
            status=200
        )

        result = self.scanner.scan_headers()
        self.assertIsInstance(result, dict)
        self.assertIn('Server', result)
        # Check for security headers detection
        self.assertIn('Missing-Content-Security-Policy', result)

    @responses.activate
    def test_robots_txt(self):
        # Mock robots.txt response
        test_robots = "User-agent: *\nDisallow: /admin/"
        responses.add(
            responses.GET,
            'https://example.com/robots.txt',
            body=test_robots,
            status=200
        )

        result = self.scanner.get_robots_txt()
        self.assertEqual(result, test_robots)

    @patch('whois.whois')
    @patch('dns.resolver.resolve')
    @responses.activate
    def test_run_all_scans(self, mock_resolve, mock_whois):
        # Setup all mocks
        mock_whois_response = MagicMock()
        mock_whois_response.domain_name = "example.com"
        mock_whois.return_value = mock_whois_response

        mock_dns_response = MagicMock()
        mock_dns_response.__str__.return_value = "93.184.216.34"
        mock_resolve.return_value = [mock_dns_response]

        responses.add(
            responses.HEAD,
            'https://example.com',
            headers={'Server': 'nginx'},
            status=200
        )
        
        responses.add(
            responses.GET,
            'https://example.com/robots.txt',
            body="User-agent: *",
            status=200
        )

        results = self.scanner.run_all_scans()
        self.assertIsInstance(results, dict)
        self.assertIn('whois', results)
        self.assertIn('dns', results)
        self.assertIn('headers', results)
        self.assertIn('robots_txt', results)

if __name__ == '__main__':
    unittest.main()