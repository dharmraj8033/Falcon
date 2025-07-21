# Falcon AI Usage Examples

## Basic Usage

### 1. Simple Vulnerability Scan
```bash
# Basic scan of a target
python main.py scan --url https://example.com

# Scan with specific modules
python main.py scan --url https://example.com --modules xss sqli ssrf

# Verbose scan with AI explanations
python main.py scan --url https://example.com --verbose --explain
```

### 2. Technology Detection
```bash
# Detect technologies on a website
python main.py tech --url https://example.com

# Aggressive technology fingerprinting
python main.py tech --url https://example.com --aggressive --fingerprint
```

### 3. Subdomain Enumeration
```bash
# Find subdomains for a domain
python main.py subdomains --domain example.com

# Passive enumeration only
python main.py subdomains --domain example.com --passive

# Use custom wordlist
python main.py subdomains --domain example.com --wordlist custom_subs.txt
```

### 4. Parameter Discovery
```bash
# Discover hidden parameters
python main.py fuzz --url https://example.com/page

# Fuzz specific parameters
python main.py fuzz --url https://example.com --parameters id user admin

# Use custom wordlist
python main.py fuzz --url https://example.com --wordlist params.txt
```

## Advanced Usage

### 5. AI Autopilot Mode
```bash
# Let AI automatically configure the scan
python main.py scan --url https://example.com --autopilot

# Autopilot with custom depth
python main.py scan --url https://example.com --autopilot --depth 5 --threads 20
```

### 6. Custom Output Formats
```bash
# JSON output
python main.py scan --url https://example.com --output json --output-file results.json

# HTML report
python main.py scan --url https://example.com --output html --output-file report.html

# PDF report (requires additional tools)
python main.py scan --url https://example.com --output pdf --output-file report.pdf
```

### 7. Network Configuration
```bash
# Use proxy
python main.py scan --url https://example.com --proxy http://proxy:8080

# Custom headers
python main.py scan --url https://example.com --headers "Authorization: Bearer token" "X-API-Key: key123"

# Custom User-Agent
python main.py scan --url https://example.com --user-agent "Custom Bot 1.0"

# Add delay between requests
python main.py scan --url https://example.com --delay 2.5
```

### 8. Comprehensive Scanning
```bash
# Full scan with all modules
python main.py scan --url https://example.com --modules all --depth 4 --autopilot

# Scan with custom timeout and threads
python main.py scan --url https://example.com --timeout 60 --threads 15

# Aggressive scanning (be careful!)
python main.py scan --url https://example.com --modules all --threads 25 --depth 5
```

## AI Features

### 9. AI Training
```bash
# Train AI models with bug bounty data
python main.py ai-train --sources bugbounty cve --epochs 10

# Train with custom data
python main.py ai-train --sources custom --data-path /path/to/data --epochs 5

# Train specific model
python main.py ai-train --sources bugbounty --model-name custom_model
```

### 10. AI Analysis
```bash
# Get AI insights during scan
python main.py scan --url https://example.com --explain --verbose

# AI-powered false positive filtering (automatic)
python main.py scan --url https://example.com --autopilot
```

## Maintenance

### 11. Updates
```bash
# Update all components
python main.py update --all

# Update only AI data
python main.py update --ai-data

# Update payloads
python main.py update --payloads

# Update external tools
python main.py update --tools
```

### 12. Configuration Management
```bash
# Show current configuration
python main.py config --show

# Set configuration value
python main.py config --set scanning.crawl_depth 5

# Reset to defaults
python main.py config --reset
```

### 13. Profile Management
```bash
# Create scan profile
python main.py profile --create web_app_profile

# List available profiles
python main.py profile --list

# Use specific profile
python main.py profile --use web_app_profile scan --url https://example.com

# Delete profile
python main.py profile --delete old_profile
```

## Docker Usage

### 14. Docker Commands
```bash
# Build Falcon AI container
docker build -t falcon-ai .

# Run basic scan
docker run -it falcon-ai scan --url https://example.com

# Run with volume mounts for output
docker run -it -v $(pwd)/output:/app/output falcon-ai scan --url https://example.com --output json --output-file /app/output/results.json

# Interactive shell
docker run -it falcon-ai /bin/bash

# Using docker-compose
docker-compose up falcon-ai
docker-compose run falcon-ai scan --url https://example.com
```

### 15. Docker with Custom Config
```bash
# Run with custom configuration
docker run -it -v $(pwd)/config:/app/config falcon-ai --config /app/config/custom.yaml scan --url https://example.com

# Persistent data with database
docker-compose up -d falcon-db
docker-compose run falcon-ai scan --url https://example.com
```

## Specialized Scans

### 16. API Testing
```bash
# API endpoint discovery
python main.py crawl --url https://api.example.com --include-js --forms

# Test API endpoints
python main.py scan --url https://api.example.com/v1 --modules all --headers "Content-Type: application/json"
```

### 17. Large Scale Scanning
```bash
# Scan multiple subdomains
python main.py subdomains --domain example.com --active | while read subdomain; do
    python main.py scan --url "https://$subdomain" --output json --output-file "results_$subdomain.json"
done

# Batch scanning with rate limiting
python main.py scan --url https://example.com --delay 1 --threads 5 --timeout 30
```

### 18. Security-Focused Scanning
```bash
# Look for admin panels
python main.py crawl --url https://example.com --scope "admin|panel|dashboard" --depth 3

# Focus on authentication bypasses
python main.py scan --url https://example.com --modules csrf idor redirect --verbose

# Test for injection vulnerabilities
python main.py scan --url https://example.com --modules xss sqli rce ssrf
```

## Integration Examples

### 19. CI/CD Integration
```bash
# Exit with error code if critical vulnerabilities found
python main.py scan --url https://staging.example.com --output json --output-file security_report.json
if grep -q '"severity": "CRITICAL"' security_report.json; then
    echo "Critical vulnerabilities found!"
    exit 1
fi
```

### 20. Scripting Integration
```bash
#!/bin/bash
# Automated security pipeline

# Get subdomains
python main.py subdomains --domain $1 --output json --output-file subdomains.json

# Technology detection
python main.py tech --url https://$1 --output json --output-file tech_stack.json

# Vulnerability scan
python main.py scan --url https://$1 --autopilot --output html --output-file security_report.html

echo "Security assessment complete. Check security_report.html"
```

## Troubleshooting

### 21. Debug Mode
```bash
# Enable debug logging
python main.py --debug scan --url https://example.com

# Verbose output with timing
python main.py --verbose scan --url https://example.com

# Test specific module
python main.py scan --url https://example.com --modules xss --verbose --debug
```

### 22. Configuration Testing
```bash
# Test installation
python test_installation.py

# Validate configuration
python main.py config --show

# Check external tools
python setup.py
```

## Best Practices

1. **Start with reconnaissance**: Always begin with subdomain enumeration and technology detection
2. **Use autopilot mode**: Let AI optimize the scan based on target analysis
3. **Rate limiting**: Use delays for production targets to avoid being blocked
4. **Save results**: Always use output files for later analysis
5. **Regular updates**: Keep AI models and payloads updated
6. **Docker for isolation**: Use Docker containers for safer scanning
7. **Respect robots.txt**: Be ethical in your security testing
8. **Authorization**: Only scan targets you own or have permission to test

## Performance Tips

- Use `--threads 10-20` for faster scanning
- Set appropriate `--timeout` values
- Use `--depth 3-5` for balanced coverage
- Enable `--autopilot` for AI-optimized performance
- Mount volumes in Docker for persistent results
- Use profiles for repeated scan configurations
