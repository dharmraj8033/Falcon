#!/bin/bash

# Falcon AI-Enhanced Vulnerability Scanner Installation Script
# This script sets up Falcon and its dependencies

set -e

echo "🦅 Falcon AI-Enhanced Vulnerability Scanner Setup"
echo "================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check Python version
check_python() {
    print_status "Checking Python installation..."
    
    if command_exists python3; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)
        
        if [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -ge 8 ]; then
            print_success "Python $PYTHON_VERSION found"
            PYTHON_CMD="python3"
        else
            print_error "Python 3.8+ required, found $PYTHON_VERSION"
            exit 1
        fi
    elif command_exists python; then
        PYTHON_VERSION=$(python --version 2>&1 | cut -d' ' -f2)
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)
        
        if [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -ge 8 ]; then
            print_success "Python $PYTHON_VERSION found"
            PYTHON_CMD="python"
        else
            print_error "Python 3.8+ required, found $PYTHON_VERSION"
            exit 1
        fi
    else
        print_error "Python not found. Please install Python 3.8+"
        exit 1
    fi
}

# Check Go installation
check_go() {
    print_status "Checking Go installation..."
    
    if command_exists go; then
        GO_VERSION=$(go version | cut -d' ' -f3)
        print_success "Go $GO_VERSION found"
    else
        print_warning "Go not found. Some tools require Go for installation."
        print_status "You can install Go from: https://golang.org/doc/install"
        read -p "Continue without Go? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Check Git installation
check_git() {
    print_status "Checking Git installation..."
    
    if command_exists git; then
        GIT_VERSION=$(git --version | cut -d' ' -f3)
        print_success "Git $GIT_VERSION found"
    else
        print_error "Git not found. Please install Git."
        exit 1
    fi
}

# Install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."
    
    # Create virtual environment (optional)
    read -p "Create virtual environment? (recommended) (Y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        print_status "Creating virtual environment..."
        $PYTHON_CMD -m venv falcon-env
        
        # Activate virtual environment
        if [ -f "falcon-env/bin/activate" ]; then
            source falcon-env/bin/activate
            print_success "Virtual environment activated"
        elif [ -f "falcon-env/Scripts/activate" ]; then
            source falcon-env/Scripts/activate
            print_success "Virtual environment activated"
        else
            print_warning "Could not activate virtual environment"
        fi
    fi
    
    # Upgrade pip
    $PYTHON_CMD -m pip install --upgrade pip
    
    # Install requirements
    if [ -f "requirements.txt" ]; then
        $PYTHON_CMD -m pip install -r requirements.txt
        print_success "Python dependencies installed"
    else
        print_error "requirements.txt not found"
        exit 1
    fi
}

# Install Go tools
install_go_tools() {
    if ! command_exists go; then
        print_warning "Skipping Go tools installation (Go not found)"
        return
    fi
    
    print_status "Installing Go-based security tools..."
    
    # Subfinder
    print_status "Installing Subfinder..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    
    # Nuclei
    print_status "Installing Nuclei..."
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    
    # Katana
    print_status "Installing Katana..."
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    
    # Httpx
    print_status "Installing Httpx..."
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    
    print_success "Go tools installed"
}

# Create directories
create_directories() {
    print_status "Creating directory structure..."
    
    directories=(
        "data/wordlists"
        "data/payloads"
        "data/signatures"
        "ai_engine/models"
        "ai_engine/datasets"
        "output"
        "sessions"
        "logs"
        "config"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
    done
    
    print_success "Directory structure created"
}

# Setup configuration
setup_config() {
    print_status "Setting up configuration..."
    
    if [ ! -f "config/falcon.yaml" ]; then
        cat > config/falcon.yaml << 'EOF'
# Falcon Configuration File
version: "1.0.0"

# General settings
general:
  threads: 20
  timeout: 30
  user_agent: "Falcon-Scanner/1.0 (AI-Enhanced Security Scanner)"
  rate_limit: 10
  max_retries: 3
  output_dir: "./output"
  session_dir: "./sessions"

# AI engine settings
ai:
  enabled: true
  model_path: "./ai_engine/models"
  confidence_threshold: 0.7
  learning_mode: true
  auto_update: true
  explain_mode: false

# Scanning modules
modules:
  subfinder:
    enabled: true
    sources: ["crtsh", "virustotal", "threatcrowd", "dnsdumpster"]
    timeout: 60
  
  tech_detection:
    enabled: true
    detailed: false
    cve_check: true
  
  crawling:
    enabled: true
    max_depth: 3
    max_pages: 1000
    include_static: false
  
  param_discovery:
    enabled: true
    wordlist: "./data/wordlists/params.txt"
    methods: ["GET", "POST"]
  
  vulnerability_scanner:
    enabled: true
    checks: ["xss", "sqli", "csrf", "rce", "ssrf", "idor", "open_redirect"]
    payload_file: "./data/payloads/all.json"

# Output settings
output:
  format: "json"
  include_raw: false
  screenshots: false
  compress: true

# Logging settings
logging:
  level: "INFO"
  file: "./logs/falcon.log"
  max_size: "100MB"
  backup_count: 5

# Network settings
network:
  proxy: null
  headers: {}
  cookies: {}
  verify_ssl: true
  follow_redirects: true
  max_redirects: 10

# Security settings
security:
  sandbox_mode: false
  max_request_size: "10MB"
  blocked_extensions: [".exe", ".zip", ".rar", ".tar"]
  allowed_domains: []
  blocked_domains: []
EOF
        print_success "Configuration file created"
    else
        print_warning "Configuration file already exists"
    fi
}

# Download wordlists and data
download_data() {
    print_status "Setting up wordlists and data..."
    
    # Use Python to create initial data
    $PYTHON_CMD -c "
import json
import os

# Create basic wordlists
wordlists = {
    'params.txt': [
        'id', 'user', 'admin', 'test', 'debug', 'action', 'cmd', 'exec',
        'file', 'path', 'dir', 'page', 'url', 'link', 'src', 'data',
        'key', 'value', 'name', 'type', 'mode', 'format', 'output',
        'callback', 'redirect', 'return', 'next', 'back', 'ref'
    ],
    'subdomains.txt': [
        'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging',
        'api', 'app', 'blog', 'shop', 'forum', 'support', 'help'
    ]
}

for filename, words in wordlists.items():
    with open(f'data/wordlists/{filename}', 'w') as f:
        f.write('\n'.join(words))

# Create basic payloads
payloads = {
    'xss': [
        '<script>alert(\"XSS\")</script>',
        '\"><script>alert(\"XSS\")</script>',
        '<img src=x onerror=alert(\"XSS\")>'
    ],
    'sqli': [
        \"' OR 1=1--\",
        '\" OR 1=1--',
        \"' UNION SELECT NULL--\"
    ]
}

with open('data/payloads/all.json', 'w') as f:
    json.dump(payloads, f, indent=2)

print('✅ Initial data created')
"
    
    print_success "Wordlists and data setup completed"
}

# Test installation
test_installation() {
    print_status "Testing installation..."
    
    # Test Falcon CLI
    if $PYTHON_CMD main.py --help > /dev/null 2>&1; then
        print_success "Falcon CLI is working"
    else
        print_error "Falcon CLI test failed"
        return 1
    fi
    
    # Test dependencies
    $PYTHON_CMD -c "
try:
    import aiohttp, requests, click, rich
    print('✅ Core dependencies working')
except ImportError as e:
    print(f'❌ Dependency issue: {e}')
    exit(1)
" || return 1
    
    print_success "Installation test passed"
}

# Main installation flow
main() {
    echo "Starting Falcon installation..."
    echo
    
    # Check prerequisites
    check_python
    check_go
    check_git
    
    echo
    print_status "Prerequisites check completed"
    echo
    
    # Install components
    install_python_deps
    install_go_tools
    create_directories
    setup_config
    download_data
    
    echo
    print_status "Running installation test..."
    test_installation
    
    echo
    print_success "🎉 Falcon installation completed successfully!"
    echo
    print_status "Quick Start:"
    echo "  1. Run: python main.py scan --url https://example.com"
    echo "  2. Run: python main.py --help for more options"
    echo "  3. Check config/falcon.yaml for settings"
    echo
    print_status "Documentation: https://github.com/dharmraj8033/Falcon"
    echo
}

# Run main installation
main "$@"
