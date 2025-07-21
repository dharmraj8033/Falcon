# 🔧 Troubleshooting Guide for Falcon AI

## Common Installation Issues

### 1. Python Import Errors

**Problem**: `ImportError: No module named 'colorama'` or similar
```bash
ModuleNotFoundError: No module named 'aiohttp'
```

**Solutions**:
```bash
# Option 1: Install all dependencies
pip3 install -r requirements.txt

# Option 2: Install minimal dependencies
pip3 install colorama aiohttp pyyaml requests

# Option 3: Use virtual environment (recommended)
python3 -m venv falcon-env
source falcon-env/bin/activate  # Linux/macOS
# or
falcon-env\Scripts\activate  # Windows
pip install -r requirements.txt
```

### 2. External Tool Missing

**Problem**: `whatweb: command not found` or similar
```bash
[ERROR] External tool 'subfinder' not found
```

**Solutions**:
```bash
# Kali Linux
sudo apt install whatweb
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Ubuntu/Debian
sudo apt update
sudo apt install golang-go
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Add Go bin to PATH
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### 3. Permission Errors

**Problem**: `Permission denied` when running scripts
```bash
bash: ./kali-setup.sh: Permission denied
```

**Solution**:
```bash
chmod +x kali-setup.sh
chmod +x install.sh
./kali-setup.sh
```

### 4. Docker Issues

**Problem**: Docker build fails or container won't start

**Solutions**:
```bash
# Check Docker service
sudo systemctl status docker
sudo systemctl start docker

# Build with verbose output
docker build --no-cache -t falcon-ai .

# Run with debug
docker run -it --rm falcon-ai bash
```

### 5. Configuration Errors

**Problem**: `Config file not found` or YAML parsing errors

**Solutions**:
```bash
# Create basic config
mkdir -p config
python3 setup.py  # This creates default config

# Or manually create minimal config
cat > config/falcon.yaml << EOF
general:
  timeout: 30
  threads: 10
scanning:
  default_modules: ['xss', 'sqli']
EOF
```

### 6. Memory/Performance Issues

**Problem**: Scanner runs out of memory or is very slow

**Solutions**:
```bash
# Reduce threads
python3 main.py scan --url target.com --threads 5

# Increase timeout
python3 main.py scan --url target.com --timeout 60

# Limit depth
python3 main.py scan --url target.com --depth 2
```

### 7. Network/Proxy Issues

**Problem**: Connection errors, timeouts, or proxy issues

**Solutions**:
```bash
# Use proxy
python3 main.py scan --url target.com --proxy http://127.0.0.1:8080

# Custom timeout
python3 main.py scan --url target.com --timeout 60

# Custom user agent
python3 main.py scan --url target.com --user-agent "Custom-Agent/1.0"
```

### 8. CI/CD Issues

**Problem**: GitHub Actions failing

**Common Issues & Solutions**:
- **Import errors**: Use `requirements-minimal.txt` for CI
- **Tool installation**: Use GitHub Actions setup-go for Go tools
- **Path issues**: Ensure `$HOME/go/bin` is in PATH
- **Timeout**: Increase timeout values in workflow

### 9. AI Engine Issues

**Problem**: AI features not working

**Solutions**:
```bash
# Check if AI models are available
ls -la data/models/

# Disable AI features temporarily
python3 main.py scan --url target.com --no-ai

# Use basic mode
python3 main.py scan --url target.com --basic-mode
```

### 10. Logging/Debug Issues

**Problem**: No logs or unclear errors

**Solutions**:
```bash
# Enable debug mode
python3 main.py --debug scan --url target.com

# Enable verbose output
python3 main.py --verbose scan --url target.com

# Check log files
tail -f logs/falcon.log

# Create logs directory if missing
mkdir -p logs output data/models
```

## Quick Diagnostic Commands

```bash
# Test basic functionality
python3 test_installation.py

# Test specific module
python3 -c "from core.scanner import FalconScanner; print('Scanner OK')"

# Check Python path
python3 -c "import sys; print(sys.path)"

# Check available tools
which subfinder katana whatweb arjun

# Check Python packages
pip3 list | grep -E "(colorama|aiohttp|yaml)"
```

## Getting Help

1. **Check logs**: `tail -f logs/falcon.log`
2. **Run diagnostics**: `python3 test_installation.py`
3. **Use debug mode**: `python3 main.py --debug --verbose`
4. **Check GitHub Issues**: https://github.com/dharmraj8033/Falcon/issues
5. **Review documentation**: `README.md`, `USAGE.md`, `KALI_TESTING.md`

## Still Having Issues?

Create an issue on GitHub with:
- Operating system and version
- Python version (`python3 --version`)
- Full error message
- Steps to reproduce
- Output of `python3 test_installation.py`
