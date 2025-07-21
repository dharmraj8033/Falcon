#!/bin/bash

# Falcon AI Quick Start Script

set -e

echo "🦅 Falcon AI - Quick Start"
echo "=========================="

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.7 or higher."
    exit 1
fi

echo "✅ Python detected: $(python3 --version)"

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is not installed. Please install pip3."
    exit 1
fi

echo "✅ pip3 detected"

# Install dependencies
echo "📦 Installing dependencies..."
pip3 install --user -r requirements.txt

# Run setup
echo "⚙️  Running setup..."
python3 setup.py

# Make main.py executable
chmod +x main.py

echo ""
echo "🎉 Setup complete!"
echo ""
echo "Quick commands:"
echo "  ./main.py --help                    # Show help"
echo "  ./main.py scan --url example.com    # Basic scan"
echo "  ./main.py tech --url example.com    # Tech detection"
echo ""
echo "🐳 For Docker users:"
echo "  docker build -t falcon-ai ."
echo "  docker run -it falcon-ai --help"
