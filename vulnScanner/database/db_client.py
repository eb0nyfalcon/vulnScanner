from supabase import create_client
import os
from datetime import datetime
from dotenv import load_dotenv
from typing import Dict, Any, List, Optional

# Load environment variables
load_dotenv()

class DatabaseError(Exception):
    """Custom exception for database operations"""
    pass

class SupabaseClient:
    def __init__(self):
        self.url = os.getenv("SUPABASE_URL")
        self.key = os.getenv("SUPABASE_KEY")
        
        if not self.url or not self.key:
            raise DatabaseError("Missing Supabase credentials in .env file")
        
        try:
            self.client = create_client(self.url, self.key)
        except Exception as e:
            raise DatabaseError(f"Failed to initialize Supabase client: {str(e)}")

    def create_scan_session(self, target_url: str, scan_options: Dict) -> str:
        """Create a new scan session and return its ID"""
        try:
            current_time = datetime.utcnow().isoformat()
            data = {
                'target_url': target_url,
                'scan_options': scan_options,
                'status': 'in_progress'
                # Let the database handle timestamps with DEFAULT NOW()
            }
            result = self.client.table('scan_sessions').insert(data).execute()
            if not result.data:
                raise DatabaseError("No data returned from scan session creation")
            return result.data[0]['id']
        except Exception as e:
            if hasattr(e, 'message'):
                raise DatabaseError(f"Failed to create scan session: {e.message}")
            raise DatabaseError(f"Failed to create scan session: {str(e)}")

    def update_scan_status(self, scan_id: str, status: str):
        """Update scan session status"""
        try:
            data = {
                'status': status,
                'completed_at': datetime.utcnow().isoformat() if status == 'completed' else None
            }
            result = self.client.table('scan_sessions').update(data).eq('id', scan_id).execute()
            if not result.data:
                raise DatabaseError(f"Failed to update scan status for session {scan_id}")
        except Exception as e:
            raise DatabaseError(f"Failed to update scan status: {str(e)}")

    def store_recon_results(self, scan_id: str, results: Dict[str, Any]):
        """Store reconnaissance results"""
        try:
            data = {
                'scan_id': scan_id,
                'whois_data': results.get('whois', {}),
                'dns_records': results.get('dns', {}),
                'http_headers': results.get('headers', {}),
                'robots_txt': results.get('robots_txt', '')
            }
            self.client.table('recon_results').insert(data).execute()
        except Exception as e:
            raise DatabaseError(f"Failed to store recon results: {str(e)}")

    def store_vulnerability(self, scan_id: str, vuln_type: str, description: str, 
                          severity: str, affected_url: str, payload: Optional[str] = None, 
                          evidence: Optional[str] = None):
        """Store vulnerability finding"""
        try:
            data = {
                'scan_id': scan_id,
                'vulnerability_type': vuln_type,
                'description': description,
                'severity': severity,
                'affected_url': affected_url,
                'payload': payload,
                'evidence': evidence
            }
            self.client.table('vulnerability_findings').insert(data).execute()
        except Exception as e:
            raise DatabaseError(f"Failed to store vulnerability: {str(e)}")

    def store_directory_result(self, scan_id: str, path: str, 
                             status_code: int, response_size: Optional[int] = None):
        """Store directory bruteforce result"""
        try:
            data = {
                'scan_id': scan_id,
                'path': path,
                'status_code': status_code,
                'response_size': response_size
            }
            self.client.table('directory_results').insert(data).execute()
        except Exception as e:
            raise DatabaseError(f"Failed to store directory result: {str(e)}")

    def store_report(self, scan_id: str, report_path: str):
        """Store report metadata"""
        try:
            data = {
                'scan_id': scan_id,
                'report_path': report_path
            }
            self.client.table('reports').insert(data).execute()
        except Exception as e:
            raise DatabaseError(f"Failed to store report metadata: {str(e)}")

    def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
        """Retrieve all results for a scan session"""
        try:
            scan = self.client.table('scan_sessions').select('*').eq('id', scan_id).execute()
            recon = self.client.table('recon_results').select('*').eq('scan_id', scan_id).execute()
            vulns = self.client.table('vulnerability_findings').select('*').eq('scan_id', scan_id).execute()
            dirs = self.client.table('directory_results').select('*').eq('scan_id', scan_id).execute()
            report = self.client.table('reports').select('*').eq('scan_id', scan_id).execute()

            return {
                'scan_info': scan.data[0] if scan.data else None,
                'recon_results': recon.data[0] if recon.data else None,
                'vulnerabilities': vulns.data,
                'directory_results': dirs.data,
                'report': report.data[0] if report.data else None
            }
        except Exception as e:
            raise DatabaseError(f"Failed to retrieve scan results: {str(e)}")

    def get_recent_scans(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Retrieve recent scan sessions"""
        try:
            result = self.client.table('scan_sessions')\
                .select('*')\
                .order('created_at', desc=True)\
                .limit(limit)\
                .execute()
            return result.data
        except Exception as e:
            raise DatabaseError(f"Failed to retrieve recent scans: {str(e)}")