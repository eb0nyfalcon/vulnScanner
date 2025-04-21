import whois
import dns.resolver
import requests
from typing import Dict, Any, List
from urllib.parse import urljoin
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

class ReconScanner:
    def __init__(self, target_url: str):
        """Initialize ReconScanner with target URL"""
        self.target_url = target_url
        self.domain = self._extract_domain(target_url)
        self.results = {
            'whois': {},
            'dns': {},
            'headers': {},
            'robots_txt': '',
            'scan_time': datetime.now().isoformat()
        }

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        return url.split('//')[-1].split('/')[0]

    def scan_whois(self) -> Dict[str, Any]:
        """Perform WHOIS lookup"""
        try:
            w = whois.whois(self.domain)
            self.results['whois'] = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails,
                'dnssec': w.dnssec,
                'name': w.name,
                'org': w.org,
                'address': w.address,
                'city': w.city,
                'state': w.state,
                'zipcode': w.zipcode,
                'country': w.country
            }
        except Exception as e:
            self.results['whois'] = {'error': str(e)}
        return self.results['whois']

    def scan_dns(self) -> Dict[str, List[str]]:
        """Perform DNS enumeration"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        dns_results = {}

        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                dns_results[record_type] = [str(rdata) for rdata in answers]
            except Exception as e:
                dns_results[record_type] = [f'Error: {str(e)}']

        self.results['dns'] = dns_results
        return dns_results

    def scan_headers(self) -> Dict[str, str]:
        """Get HTTP headers"""
        try:
            response = requests.head(
                self.target_url, 
                allow_redirects=True,
                timeout=10,
                verify=False  # For testing purposes
            )
            headers = dict(response.headers)
            # Add security headers check
            security_headers = {
                'X-XSS-Protection',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'Referrer-Policy'
            }
            for header in security_headers:
                if header not in headers:
                    headers[f'Missing-{header}'] = 'Not Set'
            
            self.results['headers'] = headers
        except Exception as e:
            self.results['headers'] = {'error': str(e)}
        return self.results['headers']

    def get_robots_txt(self) -> str:
        """Get robots.txt content"""
        try:
            robots_url = urljoin(self.target_url, '/robots.txt')
            response = requests.get(
                robots_url,
                timeout=10,
                verify=False  # For testing purposes
            )
            if response.status_code == 200:
                self.results['robots_txt'] = response.text
            else:
                self.results['robots_txt'] = f'No robots.txt found (Status: {response.status_code})'
        except Exception as e:
            self.results['robots_txt'] = f'Error: {str(e)}'
        return self.results['robots_txt']

    def run_all_scans(self) -> Dict[str, Any]:
        """Run all reconnaissance scans concurrently"""
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(self.scan_whois),
                executor.submit(self.scan_dns),
                executor.submit(self.scan_headers),
                executor.submit(self.get_robots_txt)
            ]
            # Wait for all scans to complete
            [f.result() for f in futures]
        
        return self.results