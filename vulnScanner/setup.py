from setuptools import setup, find_packages

setup(
    name="vulnScanner",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        'streamlit>=1.10.0',
        'requests>=2.28.0',
        'beautifulsoup4>=4.11.0',
        'python-whois>=0.8.0',
        'reportlab>=3.6.0',
        'supabase>=0.7.0',
        'python-dotenv>=0.20.0',
        'dnspython>=2.3.0',
        'responses>=0.25.0',  # For testing
        'pytest>=8.0.0',      # For testing
        'pytest-mock>=3.14.0' # For testing
    ]
)