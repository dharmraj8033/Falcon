# 🐧 Kali Linux Testing Guide for Falcon AI

## Quick Clone and Setup

```bash
# Clone the repository
git clone https://github.com/dharmraj8033/Falcon.git
cd Falcon

# Make setup script executable
chmod +x kali-setup.sh

# Run the Kali Linux optimized setup
./kali-setup.sh
```

## Manual Installation (Alternative)

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3 python3-pip python3-venv git curl wget golang-go

# Install Python requirements
pip3 install -r requirements.txt

# Install external tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
pip3 install arjun
sudo apt install -y whatweb

# Add Go bin to PATH
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

## Quick Test Commands

```bash
# Test installation
python3 test_installation.py

# Basic help
python3 main.py --help

# Quick vulnerability scan
python3 main.py scan --url https://httpbin.org/get

# Technology detection
python3 main.py tech --url https://httpbin.org

# Subdomain enumeration
python3 main.py subdomains --domain httpbin.org

# AI-enhanced scan
python3 main.py scan --url https://httpbin.org/get --autopilot
```

## Docker Testing

```bash
# Build container
docker build -t falcon-ai .

# Run basic scan
docker run -it --rm falcon-ai scan --url https://httpbin.org/get

# Interactive mode
docker run -it --rm falcon-ai bash
```

## Advanced Testing

```bash
# Test against DVWA (if you have it running)
python3 main.py scan --url http://localhost/dvwa --autopilot

# Test against WebGoat
python3 main.py scan --url http://localhost:8080/WebGoat --autopilot

# Full domain scan
python3 main.py scan --domain example.com --full-scope --output json
```

## Expected Output

You should see:
- ✅ Colorful terminal output with Falcon banner
- ✅ AI insights and recommendations
- ✅ Vulnerability detection results
- ✅ Technology stack identification
- ✅ Report generation in multiple formats

## Troubleshooting

### Common Issues:

1. **Import Errors**: Run `pip3 install -r requirements.txt`
2. **Missing Tools**: Run `./kali-setup.sh` to install all tools
3. **Permission Errors**: Run `chmod +x *.sh`
4. **Path Issues**: Run `source ~/.bashrc` after installation

### Performance Tips:

- Use `--threads 20` for faster scanning
- Use `--timeout 10` for quicker responses
- Use `--autopilot` for intelligent automation
- Use Docker for isolated testing environment

## Next Steps

1. ✅ Clone and setup completed
2. ✅ Run basic tests
3. 🚀 Start hunting for real vulnerabilities
4. 📊 Generate professional reports
5. 🤖 Leverage AI insights for better results

Happy hunting! 🦅
