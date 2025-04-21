from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from datetime import datetime
import os
from typing import Dict, Any, List
import json

class ReportGenerator:
    def __init__(self, reports_dir: str = "reports"):
        """Initialize report generator with reports directory"""
        self.reports_dir = reports_dir
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
        
        self.styles = getSampleStyleSheet()
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30
        )
        self.heading_style = ParagraphStyle(
            'CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12
        )
        self.normal_style = self.styles['Normal']
        
    def create_vulnerability_summary(self, vulnerabilities: List[Dict]) -> Drawing:
        """Create a pie chart of vulnerability severities"""
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Info')
            severity_counts[severity] += 1
        
        drawing = Drawing(400, 200)
        pie = Pie()
        pie.x = 150
        pie.y = 25
        pie.width = 150
        pie.height = 150
        
        pie.data = [count for count in severity_counts.values() if count > 0]
        pie.labels = [sev for sev, count in severity_counts.items() if count > 0]
        
        pie.slices.strokeWidth = 0.5
        colors_map = {
            'Critical': colors.red,
            'High': colors.orange,
            'Medium': colors.yellow,
            'Low': colors.lightgreen,
            'Info': colors.lightblue
        }
        pie.slices[0].fillColor = colors_map['Critical']
        pie.slices[1].fillColor = colors_map['High']
        pie.slices[2].fillColor = colors_map['Medium']
        pie.slices[3].fillColor = colors_map['Low']
        pie.slices[4].fillColor = colors_map['Info']
        
        drawing.add(pie)
        return drawing

    def create_findings_table(self, vulnerabilities: List[Dict]) -> Table:
        """Create a table of vulnerability findings"""
        table_data = [['Type', 'Severity', 'URL', 'Description']]
        
        for vuln in vulnerabilities:
            table_data.append([
                vuln.get('vulnerability_type', 'Unknown'),
                vuln.get('severity', 'Info'),
                vuln.get('affected_url', 'N/A'),
                vuln.get('description', 'No description provided')
            ])
        
        table = Table(table_data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        return table

    def format_recon_results(self, recon_results: Dict[str, Any]) -> List[Paragraph]:
        """Format reconnaissance results for the report"""
        paragraphs = []
        
        # WHOIS Information
        if 'whois' in recon_results:
            paragraphs.append(Paragraph('WHOIS Information', self.heading_style))
            whois_data = recon_results['whois']
            whois_text = [
                f"Domain Name: {whois_data.get('domain_name', 'N/A')}",
                f"Registrar: {whois_data.get('registrar', 'N/A')}",
                f"Creation Date: {whois_data.get('creation_date', 'N/A')}",
                f"Expiration Date: {whois_data.get('expiration_date', 'N/A')}",
                f"Organization: {whois_data.get('org', 'N/A')}",
                f"Country: {whois_data.get('country', 'N/A')}"
            ]
            paragraphs.append(Paragraph('<br/>'.join(whois_text), self.normal_style))
            paragraphs.append(Spacer(1, 12))
        
        # DNS Records
        if 'dns' in recon_results:
            paragraphs.append(Paragraph('DNS Records', self.heading_style))
            dns_data = recon_results['dns']
            for record_type, records in dns_data.items():
                if records and not str(records[0]).startswith('Error'):
                    paragraphs.append(Paragraph(f"<b>{record_type} Records:</b>", self.normal_style))
                    for record in records:
                        paragraphs.append(Paragraph(f"• {record}", self.normal_style))
            paragraphs.append(Spacer(1, 12))
        
        # HTTP Headers
        if 'headers' in recon_results:
            paragraphs.append(Paragraph('HTTP Headers Analysis', self.heading_style))
            headers = recon_results['headers']
            
            # Missing Security Headers
            missing_headers = [k for k in headers if k.startswith('Missing-')]
            if missing_headers:
                paragraphs.append(Paragraph('<b>Missing Security Headers:</b>', self.normal_style))
                for header in missing_headers:
                    paragraphs.append(Paragraph(f"• {header.replace('Missing-', '')}", self.normal_style))
            
            paragraphs.append(Paragraph('<b>All Headers:</b>', self.normal_style))
            headers_text = [f"{k}: {v}" for k, v in headers.items() if not k.startswith('Missing-')]
            paragraphs.append(Paragraph('<br/>'.join(headers_text), self.normal_style))
            paragraphs.append(Spacer(1, 12))
        
        return paragraphs

    def generate_report(self, scan_results: Dict[str, Any], output_filename: str = None) -> str:
        """Generate a PDF report from scan results"""
        if output_filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_filename = f"scan_report_{timestamp}.pdf"
        
        output_path = os.path.join(self.reports_dir, output_filename)
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        story = []
        
        # Title
        title = f"Web Vulnerability Scan Report"
        story.append(Paragraph(title, self.title_style))
        story.append(Spacer(1, 12))
        
        # Scan Information
        scan_info = scan_results.get('scan_info', {})
        scan_details = [
            f"Target URL: {scan_info.get('target_url', 'N/A')}",
            f"Scan Date: {scan_info.get('started_at', 'N/A')}",
            f"Scan Status: {scan_info.get('status', 'N/A')}",
            f"Scan Options: {json.dumps(scan_info.get('scan_options', {}), indent=2)}"
        ]
        for detail in scan_details:
            story.append(Paragraph(detail, self.normal_style))
        story.append(Spacer(1, 20))
        
        # Vulnerability Summary
        if scan_results.get('vulnerabilities'):
            story.append(Paragraph('Vulnerability Summary', self.heading_style))
            story.append(self.create_vulnerability_summary(scan_results['vulnerabilities']))
            story.append(Spacer(1, 20))
            
            # Detailed Findings
            story.append(Paragraph('Detailed Findings', self.heading_style))
            story.append(self.create_findings_table(scan_results['vulnerabilities']))
            story.append(Spacer(1, 20))
        
        # Reconnaissance Results
        if scan_results.get('recon_results'):
            story.append(Paragraph('Reconnaissance Results', self.heading_style))
            story.extend(self.format_recon_results(scan_results['recon_results']))
        
        # Directory Scan Results
        if scan_results.get('directory_results'):
            story.append(Paragraph('Directory Scan Results', self.heading_style))
            dir_data = [['Path', 'Status Code', 'Size']]
            for result in scan_results['directory_results']:
                dir_data.append([
                    result.get('path', 'N/A'),
                    str(result.get('status_code', 'N/A')),
                    str(result.get('response_size', 'N/A'))
                ])
            dir_table = Table(dir_data)
            dir_table.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ]))
            story.append(dir_table)
        
        # Generate PDF
        doc.build(story)
        return output_path