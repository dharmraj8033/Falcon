"""
Dependency Installer
Handles installation of required tools and dependencies
"""

import subprocess
import asyncio
import sys
import os
from pathlib import Path
from rich.console import Console

console = Console()

class DependencyInstaller:
    """Install and manage Falcon dependencies"""
    
    def __init__(self):
        self.required_tools = {
            'subfinder': {
                'check_cmd': ['subfinder', '-version'],
                'install_cmd': ['go', 'install', '-v', 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'],
                'description': 'Subdomain discovery tool'
            },
            'nuclei': {
                'check_cmd': ['nuclei', '-version'],
                'install_cmd': ['go', 'install', '-v', 'github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest'],
                'description': 'Vulnerability scanner'
            },
            'katana': {
                'check_cmd': ['katana', '-version'],
                'install_cmd': ['go', 'install', '-v', 'github.com/projectdiscovery/katana/cmd/katana@latest'],
                'description': 'Web crawler'
            },
            'arjun': {
                'check_cmd': ['arjun', '--help'],
                'install_cmd': ['pip', 'install', 'arjun'],
                'description': 'Parameter discovery tool'
            }
        }
    
    async def install(self, tools: str = None):
        """Install specified tools or all required tools"""
        
        if tools:
            tool_list = [tool.strip() for tool in tools.split(',')]
        else:
            tool_list = list(self.required_tools.keys())
        
        console.print("[cyan]📦 Installing Falcon dependencies...[/cyan]")
        
        # Check Go installation first
        if not await self._check_go_installation():
            console.print("[red]❌ Go is required but not installed. Please install Go first.[/red]")
            console.print("[info]📝 Install Go from: https://golang.org/doc/install[/info]")
            return False
        
        # Install Python dependencies
        await self._install_python_dependencies()
        
        # Install external tools
        for tool_name in tool_list:
            if tool_name in self.required_tools:
                await self._install_tool(tool_name)
            else:
                console.print(f"[yellow]⚠️  Unknown tool: {tool_name}[/yellow]")
        
        # Create data directories
        await self._setup_data_directories()
        
        # Download initial datasets
        await self._download_initial_data()
        
        console.print("[green]✅ Installation completed![/green]")
        return True
    
    async def _check_go_installation(self) -> bool:
        """Check if Go is installed"""
        
        try:
            result = subprocess.run(['go', 'version'], capture_output=True, text=True)
            if result.returncode == 0:
                version = result.stdout.strip()
                console.print(f"[green]✅ Go found: {version}[/green]")
                return True
        except FileNotFoundError:
            pass
        
        return False
    
    async def _install_python_dependencies(self):
        """Install Python dependencies"""
        
        console.print("[cyan]🐍 Installing Python dependencies...[/cyan]")
        
        try:
            # Install from requirements.txt
            result = subprocess.run([
                sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                console.print("[green]✅ Python dependencies installed[/green]")
            else:
                console.print(f"[red]❌ Failed to install Python dependencies: {result.stderr}[/red]")
        
        except Exception as e:
            console.print(f"[red]❌ Python dependency installation failed: {e}[/red]")
    
    async def _install_tool(self, tool_name: str):
        """Install a specific tool"""
        
        tool_info = self.required_tools[tool_name]
        console.print(f"[cyan]🔧 Installing {tool_name} ({tool_info['description']})...[/cyan]")
        
        # Check if already installed
        if await self._is_tool_installed(tool_name):
            console.print(f"[green]✅ {tool_name} is already installed[/green]")
            return
        
        try:
            # Install the tool
            result = subprocess.run(
                tool_info['install_cmd'],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            if result.returncode == 0:
                console.print(f"[green]✅ {tool_name} installed successfully[/green]")
            else:
                console.print(f"[red]❌ Failed to install {tool_name}: {result.stderr}[/red]")
        
        except subprocess.TimeoutExpired:
            console.print(f"[red]❌ {tool_name} installation timed out[/red]")
        except Exception as e:
            console.print(f"[red]❌ {tool_name} installation failed: {e}[/red]")
    
    async def _is_tool_installed(self, tool_name: str) -> bool:
        """Check if a tool is installed"""
        
        tool_info = self.required_tools[tool_name]
        
        try:
            result = subprocess.run(
                tool_info['check_cmd'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False
    
    async def _setup_data_directories(self):
        """Create necessary data directories"""
        
        console.print("[cyan]📁 Setting up data directories...[/cyan]")
        
        directories = [
            'data/wordlists',
            'data/payloads',
            'data/signatures',
            'ai_engine/models',
            'ai_engine/datasets',
            'output',
            'sessions',
            'logs',
            'config'
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
        
        console.print("[green]✅ Data directories created[/green]")
    
    async def _download_initial_data(self):
        """Download initial wordlists and datasets"""
        
        console.print("[cyan]📥 Downloading initial data...[/cyan]")
        
        # Create basic wordlists
        await self._create_basic_wordlists()
        
        # Create basic payloads
        await self._create_basic_payloads()
        
        # Create basic signatures
        await self._create_basic_signatures()
        
        console.print("[green]✅ Initial data setup completed[/green]")
    
    async def _create_basic_wordlists(self):
        """Create basic wordlists"""
        
        wordlists = {
            'params.txt': [
                'id', 'user', 'admin', 'test', 'debug', 'action', 'cmd', 'exec',
                'file', 'path', 'dir', 'page', 'url', 'link', 'src', 'data',
                'key', 'value', 'name', 'type', 'mode', 'format', 'output',
                'callback', 'redirect', 'return', 'next', 'back', 'ref',
                'search', 'query', 'q', 'keyword', 'term', 'filter',
                'sort', 'order', 'limit', 'offset', 'count', 'max', 'min'
            ],
            'subdomains.txt': [
                'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging',
                'api', 'app', 'blog', 'shop', 'forum', 'support', 'help',
                'docs', 'mobile', 'secure', 'vpn', 'remote', 'backup',
                'db', 'database', 'sql', 'mysql', 'postgres', 'mongo'
            ],
            'directories.txt': [
                'admin', 'administrator', 'login', 'panel', 'dashboard',
                'api', 'test', 'dev', 'staging', 'backup', 'old', 'tmp',
                'uploads', 'files', 'images', 'assets', 'static', 'public',
                'private', 'secret', 'hidden', 'config', 'conf', 'settings'
            ]
        }
        
        for filename, words in wordlists.items():
            filepath = Path('data/wordlists') / filename
            with open(filepath, 'w') as f:
                f.write('\n'.join(words))
    
    async def _create_basic_payloads(self):
        """Create basic vulnerability payloads"""
        
        import json
        
        payloads = {
            'xss': [
                '<script>alert("XSS")</script>',
                '"><script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                'javascript:alert("XSS")'
            ],
            'sqli': [
                "' OR 1=1--",
                '" OR 1=1--',
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
            ],
            'ssrf': [
                'http://localhost/',
                'http://127.0.0.1/',
                'http://169.254.169.254/',
                'file:///etc/passwd'
            ],
            'rce': [
                '; whoami',
                '| whoami',
                '`whoami`',
                '$(whoami)',
                '; id'
            ],
            'lfi': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '/etc/passwd'
            ]
        }
        
        with open('data/payloads/all.json', 'w') as f:
            json.dump(payloads, f, indent=2)
    
    async def _create_basic_signatures(self):
        """Create basic vulnerability signatures"""
        
        import json
        
        signatures = {
            'error_patterns': {
                'sql_errors': [
                    'SQL syntax.*MySQL',
                    'Warning.*mysql_.*',
                    'PostgreSQL.*ERROR',
                    'Oracle error'
                ],
                'php_errors': [
                    'Warning.*php',
                    'Notice.*php',
                    'Fatal error.*php'
                ],
                'asp_errors': [
                    'Microsoft.*ODBC.*error',
                    'ASP.*error'
                ]
            },
            'technology_signatures': {
                'cms': {
                    'wordpress': ['wp-content/', 'wp-includes/'],
                    'drupal': ['/sites/default/', '/modules/'],
                    'joomla': ['/components/', '/modules/']
                },
                'frameworks': {
                    'react': ['react', 'reactdom'],
                    'angular': ['ng-', 'angular'],
                    'vue': ['v-', 'vue']
                }
            }
        }
        
        with open('data/signatures/patterns.json', 'w') as f:
            json.dump(signatures, f, indent=2)
    
    async def check_installation(self) -> dict:
        """Check installation status of all tools"""
        
        status = {}
        
        # Check Python dependencies
        try:
            import aiohttp, requests, beautifulsoup4
            status['python_deps'] = True
        except ImportError:
            status['python_deps'] = False
        
        # Check external tools
        for tool_name in self.required_tools:
            status[tool_name] = await self._is_tool_installed(tool_name)
        
        return status
    
    async def show_status(self):
        """Show installation status"""
        
        console.print("[cyan]📋 Falcon Installation Status[/cyan]")
        status = await self.check_installation()
        
        for tool, installed in status.items():
            status_icon = "✅" if installed else "❌"
            status_text = "Installed" if installed else "Not installed"
            console.print(f"{status_icon} {tool}: {status_text}")
        
        # Show installation instructions for missing tools
        missing_tools = [tool for tool, installed in status.items() if not installed]
        
        if missing_tools:
            console.print("\n[yellow]📝 Installation Instructions:[/yellow]")
            console.print("Run: python main.py install-deps")
        else:
            console.print("\n[green]🎉 All dependencies are installed![/green]")
