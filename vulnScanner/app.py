import streamlit as st
from dotenv import load_dotenv
import os
from database.db_client import SupabaseClient
from scanner.recon import ReconScanner
from datetime import datetime
import json
from reports.report_generator import ReportGenerator

# Load environment variables
load_dotenv()

# Initialize database client and report generator
db = SupabaseClient()
report_gen = ReportGenerator()

def initialize_session_state():
    if 'scan_id' not in st.session_state:
        st.session_state['scan_id'] = None
    if 'scan_status' not in st.session_state:
        st.session_state['scan_status'] = None
    if 'recon_results' not in st.session_state:
        st.session_state['recon_results'] = None

def display_recon_results(results):
    """Display reconnaissance results in an organized manner"""
    if not results:
        return

    # WHOIS Information
    if 'whois' in results:
        st.markdown("### 🔍 WHOIS Information")
        whois_data = results['whois']
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Domain Information**")
            st.write(f"Domain Name: {whois_data.get('domain_name', 'N/A')}")
            st.write(f"Registrar: {whois_data.get('registrar', 'N/A')}")
            st.write(f"Creation Date: {whois_data.get('creation_date', 'N/A')}")
            st.write(f"Expiration Date: {whois_data.get('expiration_date', 'N/A')}")
        
        with col2:
            st.write("**Registrant Information**")
            st.write(f"Organization: {whois_data.get('org', 'N/A')}")
            st.write(f"Country: {whois_data.get('country', 'N/A')}")
            st.write(f"Email: {whois_data.get('emails', 'N/A')}")

    # DNS Records
    if 'dns' in results:
        st.markdown("### 🌐 DNS Records")
        dns_data = results['dns']
        for record_type, records in dns_data.items():
            if records and not str(records[0]).startswith('Error'):
                st.write(f"**{record_type} Records:**")
                for record in records:
                    st.code(record)

    # HTTP Headers
    if 'headers' in results:
        st.markdown("### 🔒 HTTP Headers Analysis")
        headers = results['headers']
        
        # Security Headers Check
        security_headers = {k: v for k, v in headers.items() if k.startswith('Missing-')}
        if security_headers:
            st.warning("**Missing Security Headers:**")
            for header in security_headers:
                st.write(f"- {header.replace('Missing-', '')}")
        
        # Display all headers
        st.write("**All Headers:**")
        st.json(headers)

    # Robots.txt
    if 'robots_txt' in results:
        st.markdown("### 🤖 Robots.txt Content")
        robots_content = results['robots_txt']
        if robots_content:
            st.code(robots_content, language='text')
        else:
            st.info("No robots.txt found")

def display_results(scan_id):
    """Display scan results in the UI"""
    try:
        results = db.get_scan_results(scan_id)
        
        # Display scan info
        st.subheader("📊 Scan Details")
        st.json(results['scan_info'])
        
        # Display reconnaissance results
        if results.get('recon_results'):
            st.subheader("🔍 Reconnaissance Results")
            display_recon_results(results['recon_results'])
        
        # Display vulnerabilities
        if results.get('vulnerabilities'):
            st.subheader("⚠️ Vulnerabilities Found")
            for vuln in results['vulnerabilities']:
                st.error(f"**Type**: {vuln['vulnerability_type']}")
                st.write(f"**Severity**: {vuln['severity']}")
                st.write(f"**URL**: {vuln['affected_url']}")
                st.markdown("---")
        
        # Display directory scan results
        if results.get('directory_results'):
            st.subheader("📁 Directory Scan Results")
            st.dataframe(results['directory_results'])

        # Add Generate Report button
        if st.button("📄 Generate PDF Report"):
            try:
                with st.spinner("Generating report..."):
                    report_path = report_gen.generate_report(results)
                    # Store report metadata in database
                    db.store_report(scan_id, report_path)
                    # Get filename from path
                    report_filename = os.path.basename(report_path)
                    # Read the PDF file
                    with open(report_path, "rb") as pdf_file:
                        pdf_bytes = pdf_file.read()
                    # Create download button
                    st.download_button(
                        label="⬇️ Download Report",
                        data=pdf_bytes,
                        file_name=report_filename,
                        mime="application/pdf"
                    )
            except Exception as e:
                st.error(f"Error generating report: {str(e)}")
                
    except Exception as e:
        st.error(f"Error retrieving results: {str(e)}")

def perform_recon_scan(target_url, scan_id):
    """Perform reconnaissance scan and store results"""
    with st.status("🔍 Performing Reconnaissance...", expanded=True) as status:
        try:
            scanner = ReconScanner(target_url)
            
            # Update status for each scan phase
            st.write("Scanning WHOIS information...")
            scanner.scan_whois()
            
            st.write("Analyzing DNS records...")
            scanner.scan_dns()
            
            st.write("Checking HTTP headers...")
            scanner.scan_headers()
            
            st.write("Retrieving robots.txt...")
            scanner.get_robots_txt()
            
            # Store results in database
            results = scanner.results
            db.store_recon_results(scan_id, results)
            st.session_state['recon_results'] = results
            
            status.update(label="✅ Reconnaissance Complete!", state="complete", expanded=False)
            return True
            
        except Exception as e:
            status.update(label=f"❌ Reconnaissance Failed: {str(e)}", state="error")
            return False

def main():
    initialize_session_state()
    
    st.set_page_config(
        page_title="Web Vulnerability Scanner",
        page_icon="🛡️",
        layout="wide"
    )
    
    st.title("🛡️ Web Vulnerability Scanner")
    
    # Create two columns for layout
    left_col, right_col = st.columns([2, 1])
    
    with left_col:
        # URL Input
        target_url = st.text_input("Enter Target URL", "https://example.com")
        
        # Scan Options
        st.subheader("Select Scan Options")
        col1, col2 = st.columns(2)
        
        with col1:
            recon = st.checkbox("Reconnaissance", True)
            sqli = st.checkbox("SQL Injection")
            xss = st.checkbox("XSS Detection")
        
        with col2:
            lfi_rfi = st.checkbox("LFI/RFI Detection")
            dir_bruteforce = st.checkbox("Directory Bruteforce")
        
        # Scan Button
        if st.button("Start Scan"):
            if not any([recon, sqli, xss, lfi_rfi, dir_bruteforce]):
                st.error("Please select at least one scan option!")
                return
            
            scan_options = {
                "recon": recon,
                "sqli": sqli,
                "xss": xss,
                "lfi_rfi": lfi_rfi,
                "dir_bruteforce": dir_bruteforce
            }
            
            try:
                # Create scan session in database
                scan_id = db.create_scan_session(target_url, scan_options)
                st.session_state['scan_id'] = scan_id
                st.session_state['scan_status'] = 'running'
                st.success(f"Scan initiated! Scan ID: {scan_id}")
                
                # Perform selected scans
                if recon:
                    if perform_recon_scan(target_url, scan_id):
                        st.success("Reconnaissance scan completed successfully!")
                    else:
                        st.error("Reconnaissance scan failed!")
                
                # Update scan status
                st.session_state['scan_status'] = 'completed'
                db.update_scan_status(scan_id, 'completed')
                
            except Exception as e:
                st.error(f"Error starting scan: {str(e)}")
    
    with right_col:
        st.subheader("Recent Scans")
        try:
            recent_scans = db.get_recent_scans(5)
            for scan in recent_scans:
                with st.expander(f"Scan: {scan['target_url']}", expanded=False):
                    st.write(f"Status: {scan['status']}")
                    st.write(f"Date: {scan['started_at']}")
                    if st.button("View Results", key=scan['id']):
                        display_results(scan['id'])
        except Exception as e:
            st.error(f"Error loading recent scans: {str(e)}")
    
    # Display results if scan is completed
    if st.session_state['scan_id'] and st.session_state['scan_status'] == 'completed':
        display_results(st.session_state['scan_id'])

if __name__ == "__main__":
    main()