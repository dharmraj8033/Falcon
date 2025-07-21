#!/bin/bash

# Falcon AI - Kali Linux Quick Setup Script
# Optimized for Kali Linux pentesting environment

echo "🦅 Falcon AI - Kali Linux Setup"
echo "================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${CYAN}[INFO]${NC} $1"
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

# Check if running on Kali Linux
if ! grep -q "Kali" /etc/os-release 2>/dev/null; then
    print_warning "This script is optimized for Kali Linux but will work on other Debian-based systems"
fi

# Update package lists
print_status "Updating package lists..."
sudo apt update

# Install system dependencies
print_status "Installing system dependencies..."
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    git \
    curl \
    wget \
    build-essential \
    libssl-dev \
    libffi-dev \
    golang-go

# Install Python dependencies
print_status "Installing Python dependencies..."
pip3 install --upgrade pip setuptools wheel
pip3 install -r requirements.txt

# Create virtual environment (optional but recommended)
print_status "Creating Python virtual environment..."
python3 -m venv falcon-env
source falcon-env/bin/activate
pip install -r requirements.txt

# Install external security tools
print_status "Installing external security tools..."

# Install Subfinder
print_status "Installing Subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install Katana
print_status "Installing Katana..."
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Install Arjun (parameter discovery)
print_status "Installing Arjun..."
pip3 install arjun

# Install WhatWeb (if not already installed in Kali)
if ! command -v whatweb &> /dev/null; then
    print_status "Installing WhatWeb..."
    sudo apt install -y whatweb
else
    print_success "WhatWeb already installed"
fi

# Install additional useful tools for Kali
print_status "Installing additional Kali tools..."
sudo apt install -y \
    nmap \
    masscan \
    nuclei \
    httpx \
    amass \
    gobuster \
    dirsearch

# Add Go bin to PATH if not already there
if ! echo $PATH | grep -q "$HOME/go/bin"; then
    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
    export PATH=$PATH:$HOME/go/bin
    print_success "Added Go bin to PATH"
fi

# Create necessary directories
print_status "Creating project directories..."
mkdir -p logs output data/models data/payloads data/wordlists config

# Set executable permissions
print_status "Setting executable permissions..."
chmod +x install.sh
chmod +x deploy_to_github.sh

# Create desktop shortcut (optional)
print_status "Creating desktop shortcut..."
cat > ~/Desktop/falcon-ai.desktop << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Falcon AI Scanner
Comment=AI-Enhanced Vulnerability Scanner
Exec=gnome-terminal -- bash -c 'cd $(pwd) && python3 main.py --help; exec bash'
Icon=applications-security
Terminal=true
Categories=Security;Network;
EOF

chmod +x ~/Desktop/falcon-ai.desktop

# Test installation
print_status "Testing installation..."
python3 test_installation.py

# Display success message and usage instructions
print_success "Falcon AI installation completed!"

echo ""
echo -e "${CYAN}🚀 Quick Start Commands:${NC}"
echo -e "${YELLOW}# Activate virtual environment (recommended):${NC}"
echo "source falcon-env/bin/activate"
echo ""
echo -e "${YELLOW}# Basic vulnerability scan:${NC}"
echo "python3 main.py scan --url https://example.com"
echo ""
echo -e "${YELLOW}# Technology detection:${NC}"
echo "python3 main.py tech --url https://example.com"
echo ""
echo -e "${YELLOW}# Subdomain enumeration:${NC}"
echo "python3 main.py subdomains --domain example.com"
echo ""
echo -e "${YELLOW}# Full AI-powered scan:${NC}"
echo "python3 main.py scan --url https://example.com --autopilot --ai-enhance"
echo ""
echo -e "${YELLOW}# Docker usage:${NC}"
echo "docker build -t falcon-ai ."
echo "docker run -it falcon-ai scan --url https://example.com"
echo ""
echo -e "${GREEN}🦅 Happy hunting with Falcon AI!${NC}"
echo -e "${BLUE}📚 Documentation: README.md and USAGE.md${NC}"
echo -e "${BLUE}🐛 Issues: https://github.com/dharmraj8033/Falcon/issues${NC}"
