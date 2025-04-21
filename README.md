# 🛡️ Custom Web Vulnerability Scanner

A powerful, local web vulnerability scanner built with Python and Streamlit that performs reconnaissance, vulnerability scanning, and generates detailed reports.

## 🌟 Features

- 🔍 **Reconnaissance**
  - WHOIS Lookup
  - DNS Records Analysis
  - HTTP Headers Inspection
  - robots.txt Parser

- 🔒 **Vulnerability Scanning**
  - SQL Injection Detection
  - XSS (Cross-Site Scripting) Testing
  - LFI/RFI (Local/Remote File Inclusion) Detection
  - Directory Bruteforce

- 📊 **Reporting**
  - Detailed PDF Reports
  - Severity Classifications
  - Timestamp Tracking
  - Result History

- 🎯 **User Interface**
  - Web-based Dashboard using Streamlit
  - Real-time Scan Progress
  - Interactive Result Display

## 🛠️ Prerequisites

- Python 3.8+
- pip (Python package manager)
- Git
- Docker (optional)

## ⚙️ Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/eb0nyfalcon/vulScanner.git
   cd vuln-scanner
   ```

2. **Create a virtual environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # For MacOS/Linux
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Supabase**
   Create a `.env` file in the project root:
   ```bash
   SUPABASE_URL="https://dqknvxqmkxwnxeiluiki.supabase.co"
   SUPABASE_KEY="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRxa252eHFta3h3bnhlaWx1aWtpIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDUyMDgwNTMsImV4cCI6MjA2MDc4NDA1M30.KzFPg_fWa0FRdyqub8s4FR0Xkn4C7lWgS1tHdVMSBgc"
   ```

## 🚀 Usage

1. **Start the application**
   ```bash
   streamlit run app.py
   ```

2. **Access the dashboard**
   - Open your browser and navigate to `http://localhost:8501`
   - Enter the target URL
   - Select desired scan options
   - Click "Start Scan"

## 📁 Project Structure

```
vuln-scanner/
├── app.py                    # Main Streamlit application
├── scanner/                  # Core scanning modules
│   ├── recon.py
│   ├── sqli.py
│   ├── lfi_rfi.py
│   ├── xss.py
│   └── dir_bruteforce.py
├── reports/                  # Report generation
├── database/                 # Database operations
└── assets/                  # Resources
```

## 🐳 Docker Support

```bash
# Build the container
docker build -t vuln-scanner .

# Run the container
docker run -p 8501:8501 vuln-scanner
```

## 📝 Dependencies

```
streamlit>=1.10.0
requests>=2.28.0
beautifulsoup4>=4.11.0
python-whois>=0.8.0
reportlab>=3.6.0
supabase>=0.7.0
python-dotenv>=0.20.0
```

## ⚠️ Disclaimer

This tool is intended for educational purposes and authorized security testing only. Always obtain proper authorization before scanning any web applications.

## 👤 Author

**Thanish P.**
- Email: thanishp0208@gmail.com
- LinkedIn: [Thanish P](https://linkedin.com/in/thanish-p)

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
