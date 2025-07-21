#!/usr/bin/env python3
"""
Falcon AI Setup Script
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def print_banner():
    print("""
    ███████╗ █████╗ ██╗      ██████╗ ██████╗ ███╗   ██╗    █████╗ ██╗
    ██╔════╝██╔══██╗██║     ██╔════╝██╔═══██╗████╗  ██║   ██╔══██╗██║
    █████╗  ███████║██║     ██║     ██║   ██║██╔██╗ ██║   ███████║██║
    ██╔══╝  ██╔══██║██║     ██║     ██║   ██║██║╚██╗██║   ██╔══██║██║
    ██║     ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╗██║  ██║██║
    ╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝╚═╝
    
    🦅 AI-Enhanced Vulnerability Scanner Setup
    """)

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 7):
        print("❌ Python 3.7 or higher is required")
        print(f"Current version: {sys.version}")
        return False
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")
    return True

def check_system():
    """Check system requirements"""
    system = platform.system()
    print(f"🖥️  Operating System: {system} {platform.release()}")
    
    if system == "Windows":
        print("📝 Note: Some features work best on Linux/macOS")
    
    return True

def install_requirements():
    """Install Python requirements"""
    print("📦 Installing Python requirements...")
    
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", 
            "--upgrade", "pip", "setuptools", "wheel"
        ])
        
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", 
            "-r", "requirements.txt"
        ])
        
        print("✅ Python requirements installed successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install requirements: {e}")
        return False

def create_directories():
    """Create necessary directories"""
    print("📁 Creating directories...")
    
    directories = [
        "logs",
        "output", 
        "data/models",
        "data/payloads",
        "data/wordlists",
        "config"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"   Created: {directory}")
    
    print("✅ Directories created successfully")

def create_sample_config():
    """Create sample configuration file"""
    print("⚙️  Creating sample configuration...")
    
    config_content = """# Falcon AI Configuration
general:
  user_agent: 'Falcon-AI/1.0 (Security Scanner)'
  timeout: 30
  retries: 3
  threads: 10
  verify_ssl: false

scanning:
  default_modules: ['xss', 'sqli', 'ssrf', 'rce']
  crawl_depth: 3
  autopilot: false
  aggressive_mode: false

ai_engine:
  confidence_threshold: 0.7
  enable_training: true
  auto_update: true

output:
  default_format: 'txt'
  color_output: true
  verbose_level: 1

logging:
  level: 'INFO'
  file: 'logs/falcon.log'

# Tool paths (will be auto-detected)
tools:
  subfinder:
    enabled: true
    path: '/usr/local/bin/subfinder'
  whatweb:
    enabled: true
    path: '/usr/local/bin/whatweb'
  arjun:
    enabled: true
    path: '/usr/local/bin/arjun'
"""
    
    with open("config/falcon.yaml", "w") as f:
        f.write(config_content)
    
    print("✅ Sample configuration created at config/falcon.yaml")

def create_sample_data():
    """Create sample payloads and wordlists"""
    print("📋 Creating sample data files...")
    
    # XSS payloads
    xss_payloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        'javascript:alert("XSS")',
        '<svg onload=alert("XSS")>',
        '"><script>alert("XSS")</script>',
        "';alert('XSS');//",
        '<iframe src="javascript:alert(`XSS`)">',
        '<object data="javascript:alert(`XSS`)">'
    ]
    
    with open("data/payloads/xss.txt", "w") as f:
        f.write("# XSS Payloads for Falcon AI\n")
        for payload in xss_payloads:
            f.write(f"{payload}\n")
    
    # SQLi payloads
    sqli_payloads = [
        "' OR '1'='1",
        "' UNION SELECT null,version(),null--",
        "'; DROP TABLE users--",
        "' OR SLEEP(5)--",
        "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
        "' UNION SELECT 1,2,3,4,5--",
        "' OR 1=1#",
        "') OR ('1'='1"
    ]
    
    with open("data/payloads/sqli.txt", "w") as f:
        f.write("# SQL Injection Payloads for Falcon AI\n")
        for payload in sqli_payloads:
            f.write(f"{payload}\n")
    
    # Parameter wordlist
    parameters = [
        'id', 'user', 'name', 'email', 'password', 'token', 'key', 'api_key',
        'session', 'csrf', 'debug', 'test', 'dev', 'admin', 'action', 'cmd',
        'file', 'path', 'url', 'redirect', 'callback', 'format', 'type',
        'method', 'mode', 'sort', 'page', 'limit', 'search', 'query'
    ]
    
    with open("data/wordlists/parameters.txt", "w") as f:
        f.write("# Common Parameters for Falcon AI\n")
        for param in parameters:
            f.write(f"{param}\n")
    
    print("✅ Sample data files created")

def check_external_tools():
    """Check for external security tools"""
    print("🔧 Checking for external tools...")
    
    tools = {
        'subfinder': 'Subdomain enumeration',
        'whatweb': 'Technology detection', 
        'arjun': 'Parameter discovery',
        'katana': 'Web crawling'
    }
    
    found_tools = []
    missing_tools = []
    
    for tool, description in tools.items():
        try:
            subprocess.run([tool, '--help'], 
                         capture_output=True, check=True, timeout=5)
            print(f"   ✅ {tool} - {description}")
            found_tools.append(tool)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            print(f"   ❌ {tool} - {description} (not found)")
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"\n📝 Missing tools: {', '.join(missing_tools)}")
        print("💡 Consider installing missing tools for full functionality")
        print("🐳 Use Docker for a complete environment with all tools")
    
    return found_tools, missing_tools

def test_installation():
    """Test the installation"""
    print("🧪 Testing installation...")
    
    try:
        # Test imports
        import sys
        sys.path.insert(0, '.')
        
        from core.config import config
        from core.logger import setup_logger
        from ai_engine.ai_core import AIEngine
        
        print("✅ Core modules imported successfully")
        
        # Test AI engine initialization
        ai_engine = AIEngine()
        print("✅ AI engine initialized successfully")
        
        # Test logger
        logger = setup_logger()
        logger.info("Test log message")
        print("✅ Logging system working")
        
        return True
        
    except Exception as e:
        print(f"❌ Installation test failed: {e}")
        return False

def print_usage_instructions():
    """Print usage instructions"""
    print("""
🎉 Installation completed successfully!

🚀 Quick Start:
  # Basic scan
  python main.py scan --url https://example.com
  
  # Technology detection
  python main.py tech --url https://example.com
  
  # Subdomain enumeration  
  python main.py subdomains --domain example.com
  
  # Full scan with AI autopilot
  python main.py scan --url https://example.com --autopilot --output json

📖 Documentation:
  # Show help
  python main.py --help
  
  # Show scan options
  python main.py scan --help

🐳 Docker Usage:
  # Build container
  docker build -t falcon-ai .
  
  # Run scan
  docker run -it falcon-ai scan --url https://example.com

⚙️  Configuration:
  Edit config/falcon.yaml to customize settings

📝 Logs:
  Check logs/ directory for detailed logs

🔧 Tools:
  Install missing external tools for enhanced functionality
  
🦅 Happy hunting with Falcon AI!
    """)

def main():
    """Main setup function"""
    print_banner()
    
    if not check_python_version():
        sys.exit(1)
    
    check_system()
    
    create_directories()
    create_sample_config()
    create_sample_data()
    
    if "--skip-deps" not in sys.argv:
        if not install_requirements():
            print("⚠️  Requirements installation failed. Try running:")
            print("   pip install -r requirements.txt")
    
    check_external_tools()
    
    if test_installation():
        print_usage_instructions()
    else:
        print("❌ Setup completed with errors. Check the error messages above.")

if __name__ == "__main__":
    main()
