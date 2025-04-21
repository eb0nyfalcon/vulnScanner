from db_client import SupabaseClient
import json

def test_database_connection():
    try:
        # Initialize client
        db = SupabaseClient()
        
        # Test scan session creation
        scan_id = db.create_scan_session(
            "https://test.com",
            {"recon": True, "sqli": True}
        )
        print(f"Created scan session with ID: {scan_id}")
        
        # Test storing recon results
        db.store_recon_results(scan_id, {
            "whois": {"domain": "test.com"},
            "dns": {"A": ["1.1.1.1"]},
            "headers": {"Server": "nginx"},
            "robots_txt": "User-agent: *"
        })
        print("Stored recon results")
        
        # Test retrieving results
        results = db.get_scan_results(scan_id)
        print("\nRetrieved results:")
        print(json.dumps(results, indent=2))
        
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    test_database_connection()