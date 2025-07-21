@echo off
REM Falcon AI-Enhanced Vulnerability Scanner Installation Script for Windows
REM This script sets up Falcon and its dependencies on Windows

echo.
echo 🦅 Falcon AI-Enhanced Vulnerability Scanner Setup
echo =================================================
echo.

REM Check Python installation
echo [INFO] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo [SUCCESS] Python %PYTHON_VERSION% found

REM Check if pip is available
echo [INFO] Checking pip installation...
python -m pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] pip not found. Please install pip
    pause
    exit /b 1
)
echo [SUCCESS] pip is available

REM Create virtual environment (optional)
set /p CREATE_VENV="Create virtual environment? (recommended) (Y/n): "
if /i not "%CREATE_VENV%"=="n" (
    echo [INFO] Creating virtual environment...
    python -m venv falcon-env
    
    echo [INFO] Activating virtual environment...
    call falcon-env\Scripts\activate.bat
    echo [SUCCESS] Virtual environment activated
)

REM Upgrade pip
echo [INFO] Upgrading pip...
python -m pip install --upgrade pip

REM Install Python dependencies
echo [INFO] Installing Python dependencies...
if exist requirements.txt (
    python -m pip install -r requirements.txt
    echo [SUCCESS] Python dependencies installed
) else (
    echo [ERROR] requirements.txt not found
    pause
    exit /b 1
)

REM Check Go installation
echo [INFO] Checking Go installation...
go version >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Go not found. Some tools require Go for installation.
    echo [INFO] You can install Go from: https://golang.org/doc/install
    set /p CONTINUE_WITHOUT_GO="Continue without Go? (y/N): "
    if /i not "%CONTINUE_WITHOUT_GO%"=="y" (
        exit /b 1
    )
) else (
    for /f "tokens=3" %%i in ('go version') do set GO_VERSION=%%i
    echo [SUCCESS] Go %GO_VERSION% found
    
    REM Install Go tools
    echo [INFO] Installing Go-based security tools...
    
    echo [INFO] Installing Subfinder...
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    
    echo [INFO] Installing Nuclei...
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    
    echo [INFO] Installing Katana...
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    
    echo [INFO] Installing Httpx...
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    
    echo [SUCCESS] Go tools installed
)

REM Create directories
echo [INFO] Creating directory structure...
if not exist "data\wordlists" mkdir "data\wordlists"
if not exist "data\payloads" mkdir "data\payloads"
if not exist "data\signatures" mkdir "data\signatures"
if not exist "ai_engine\models" mkdir "ai_engine\models"
if not exist "ai_engine\datasets" mkdir "ai_engine\datasets"
if not exist "output" mkdir "output"
if not exist "sessions" mkdir "sessions"
if not exist "logs" mkdir "logs"
if not exist "config" mkdir "config"
echo [SUCCESS] Directory structure created

REM Setup configuration
echo [INFO] Setting up configuration...
if not exist "config\falcon.yaml" (
    echo # Falcon Configuration File > "config\falcon.yaml"
    echo version: "1.0.0" >> "config\falcon.yaml"
    echo. >> "config\falcon.yaml"
    echo # General settings >> "config\falcon.yaml"
    echo general: >> "config\falcon.yaml"
    echo   threads: 20 >> "config\falcon.yaml"
    echo   timeout: 30 >> "config\falcon.yaml"
    echo   user_agent: "Falcon-Scanner/1.0 (AI-Enhanced Security Scanner)" >> "config\falcon.yaml"
    echo [SUCCESS] Configuration file created
) else (
    echo [WARNING] Configuration file already exists
)

REM Setup initial data
echo [INFO] Setting up wordlists and data...
python -c "
import json
import os

# Create basic wordlists
wordlists = {
    'params.txt': [
        'id', 'user', 'admin', 'test', 'debug', 'action', 'cmd', 'exec',
        'file', 'path', 'dir', 'page', 'url', 'link', 'src', 'data'
    ],
    'subdomains.txt': [
        'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api'
    ]
}

for filename, words in wordlists.items():
    with open(f'data/wordlists/{filename}', 'w') as f:
        f.write('\n'.join(words))

# Create basic payloads
payloads = {
    'xss': ['<script>alert(\"XSS\")</script>'],
    'sqli': [\"' OR 1=1--\", '\" OR 1=1--']
}

with open('data/payloads/all.json', 'w') as f:
    json.dump(payloads, f, indent=2)

print('✅ Initial data created')
"
echo [SUCCESS] Wordlists and data setup completed

REM Test installation
echo [INFO] Testing installation...
python main.py --help >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Falcon CLI test failed
    pause
    exit /b 1
)
echo [SUCCESS] Falcon CLI is working

echo.
echo [SUCCESS] 🎉 Falcon installation completed successfully!
echo.
echo [INFO] Quick Start:
echo   1. Run: python main.py scan --url https://example.com
echo   2. Run: python main.py --help for more options
echo   3. Check config\falcon.yaml for settings
echo.
echo [INFO] Documentation: https://github.com/dharmraj8033/Falcon
echo.
pause
