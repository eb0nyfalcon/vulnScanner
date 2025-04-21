import unittest
from unittest.mock import patch, MagicMock
import responses
from ..dir_bruteforce import DirBruteforceScanner

class TestDirBruteforceScanner(unittest.TestCase):
    def setUp(self):
        self.target_url = "https://example.com"
        self.scanner = DirBruteforceScanner(self.target_url)

    def test_load_wordlist(self):
        # Test with sample paths
        sample_paths = [
            "admin",
            "wp-admin",
            "login",
            "backup",
            ".git"
        ]
        with patch('builtins.open', unittest.mock.mock_open(read_data="\n".join(sample_paths))):
            wordlist = self.scanner.load_wordlist("sample_wordlist.txt")
            self.assertEqual(len(wordlist), 5)
            self.assertIn("admin", wordlist)
            self.assertIn(".git", wordlist)

    @responses.activate
    def test_check_path(self):
        # Mock responses for different HTTP statuses
        responses.add(
            responses.GET,
            f"{self.target_url}/admin",
            status=200
        )
        responses.add(
            responses.GET,
            f"{self.target_url}/notfound",
            status=404
        )
        responses.add(
            responses.GET,
            f"{self.target_url}/forbidden",
            status=403
        )

        # Test found directory
        result = self.scanner.check_path("admin")
        self.assertTrue(result['exists'])
        self.assertEqual(result['status_code'], 200)

        # Test not found
        result = self.scanner.check_path("notfound")
        self.assertFalse(result['exists'])
        self.assertEqual(result['status_code'], 404)

        # Test forbidden
        result = self.scanner.check_path("forbidden")
        self.assertTrue(result['exists'])
        self.assertEqual(result['status_code'], 403)

    @responses.activate
    def test_content_length_analysis(self):
        # Mock responses with different content lengths
        responses.add(
            responses.GET,
            f"{self.target_url}/page1",
            body="Short content",
            status=200
        )
        responses.add(
            responses.GET,
            f"{self.target_url}/page2",
            body="A" * 1000,  # Long content
            status=200
        )

        result1 = self.scanner.analyze_response_size("page1")
        result2 = self.scanner.analyze_response_size("page2")
        
        self.assertNotEqual(result1['size'], result2['size'])
        self.assertGreater(result2['size'], result1['size'])

    @responses.activate
    def test_recursive_scanning(self):
        # Mock responses for recursive directory scanning
        responses.add(
            responses.GET,
            f"{self.target_url}/admin",
            status=200
        )
        responses.add(
            responses.GET,
            f"{self.target_url}/admin/config",
            status=200
        )

        results = self.scanner.scan_recursively("admin", depth=1)
        self.assertIsInstance(results, list)
        self.assertTrue(any(r['path'] == 'admin/config' for r in results))

    @responses.activate
    def test_extension_bruteforce(self):
        # Mock responses for different file extensions
        responses.add(
            responses.GET,
            f"{self.target_url}/config.php",
            status=200
        )
        responses.add(
            responses.GET,
            f"{self.target_url}/config.bak",
            status=200
        )

        results = self.scanner.bruteforce_extensions("config", [".php", ".bak"])
        self.assertEqual(len(results), 2)
        self.assertTrue(any(r['path'].endswith('.php') for r in results))
        self.assertTrue(any(r['path'].endswith('.bak') for r in results))

    @responses.activate
    def test_full_scan(self):
        # Mock various responses for full scan
        responses.add(
            responses.GET,
            f"{self.target_url}/admin",
            status=200
        )
        responses.add(
            responses.GET,
            f"{self.target_url}/config.php",
            status=403
        )
        responses.add(
            responses.GET,
            f"{self.target_url}/backup",
            status=404
        )

        with patch('builtins.open', unittest.mock.mock_open(read_data="admin\nconfig.php\nbackup")):
            results = self.scanner.run_scan(wordlist_path="sample_wordlist.txt")
            self.assertIsInstance(results, dict)
            self.assertIn('directories_found', results)
            self.assertIn('files_found', results)
            self.assertIn('total_requests', results)
            self.assertGreater(len(results['directories_found']), 0)

    @responses.activate
    def test_rate_limiting_handling(self):
        # Mock rate limit response
        responses.add(
            responses.GET,
            f"{self.target_url}/admin",
            status=429  # Too Many Requests
        )

        result = self.scanner.check_path("admin", retry_count=1)
        self.assertIn('rate_limited', result)
        self.assertTrue(result['rate_limited'])

if __name__ == '__main__':
    unittest.main()