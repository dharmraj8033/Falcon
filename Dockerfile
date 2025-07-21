# Use Python 3.9 slim image as base
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    DEBIAN_FRONTEND=noninteractive

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    build-essential \
    gcc \
    g++ \
    make \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    libjpeg-dev \
    libpng-dev \
    libfreetype6-dev \
    fontconfig \
    fonts-liberation \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install security tools
RUN mkdir -p /tools && cd /tools && \
    # Install Subfinder
    wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip && \
    unzip subfinder_2.6.3_linux_amd64.zip && \
    mv subfinder /usr/local/bin/ && \
    chmod +x /usr/local/bin/subfinder && \
    rm -f subfinder_2.6.3_linux_amd64.zip && \
    # Install httpx
    wget https://github.com/projectdiscovery/httpx/releases/download/v1.3.7/httpx_1.3.7_linux_amd64.zip && \
    unzip httpx_1.3.7_linux_amd64.zip && \
    mv httpx /usr/local/bin/ && \
    chmod +x /usr/local/bin/httpx && \
    rm -f httpx_1.3.7_linux_amd64.zip && \
    # Install Katana
    wget https://github.com/projectdiscovery/katana/releases/download/v1.0.4/katana_1.0.4_linux_amd64.zip && \
    unzip katana_1.0.4_linux_amd64.zip && \
    mv katana /usr/local/bin/ && \
    chmod +x /usr/local/bin/katana && \
    rm -f katana_1.0.4_linux_amd64.zip && \
    # Install Arjun
    git clone https://github.com/s0md3v/Arjun.git && \
    cd Arjun && \
    pip3 install -r requirements.txt && \
    ln -s /tools/Arjun/arjun.py /usr/local/bin/arjun && \
    chmod +x /usr/local/bin/arjun && \
    cd /tools && \
    # Install WhatWeb (Ruby-based)
    curl -s https://raw.githubusercontent.com/urbanadventurer/WhatWeb/master/whatweb > /usr/local/bin/whatweb && \
    chmod +x /usr/local/bin/whatweb && \
    # Clean up
    rm -rf /tools

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs output data/models data/payloads data/wordlists && \
    chmod +x main.py

# Create data files
RUN echo "# XSS Payloads\n<script>alert('XSS')</script>\n<img src=x onerror=alert('XSS')>\njavascript:alert('XSS')" > data/payloads/xss.txt && \
    echo "# SQLi Payloads\n' OR '1'='1\n' UNION SELECT null,version(),null--\n' OR SLEEP(5)--" > data/payloads/sqli.txt && \
    echo "# SSRF Payloads\nhttp://localhost\nhttp://127.0.0.1\nhttp://169.254.169.254/latest/meta-data/" > data/payloads/ssrf.txt && \
    echo "# RCE Payloads\n; whoami\n| id\n\`pwd\`\n\$(cat /etc/passwd)" > data/payloads/rce.txt && \
    echo "# Common Parameters\nid\nuser\nname\nemail\npassword\ntoken\nkey\napi_key\nsession\ncsrf\ndebug\ntest\ndev\nadmin" > data/wordlists/parameters.txt && \
    echo "# Common Subdomains\nwww\nmail\nftp\nadmin\napi\ntest\ndev\nstaging\nblog\napp\nmobile\nsecure\nvpn\ngit\njenkins" > data/wordlists/subdomains.txt

# Create a non-root user
RUN groupadd -r falcon && useradd -r -g falcon falcon && \
    chown -R falcon:falcon /app

# Switch to non-root user
USER falcon

# Expose port (if needed for web interface in future)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import sys; sys.exit(0)"

# Set entrypoint
ENTRYPOINT ["python3", "main.py"]

# Default command (show help)
CMD ["--help"]
