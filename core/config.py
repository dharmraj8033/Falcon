"""
Falcon Configuration Management
Handles configuration loading, validation, and management
"""

import os
import json
import yaml
from pathlib import Path
from typing import Any, Dict, Optional
from rich.console import Console

console = Console()

class FalconConfig:
    """Falcon configuration manager"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._get_default_config_path()
        self.config_data = {}
        self.load_config()
    
    def _get_default_config_path(self) -> str:
        """Get default configuration file path"""
        home_dir = Path.home()
        falcon_dir = home_dir / ".falcon"
        falcon_dir.mkdir(exist_ok=True)
        return str(falcon_dir / "config.yaml")
    
    def load_config(self):
        """Load configuration from file"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    if self.config_path.endswith('.yaml') or self.config_path.endswith('.yml'):
                        self.config_data = yaml.safe_load(f) or {}
                    else:
                        self.config_data = json.load(f)
            except Exception as e:
                console.print(f"[yellow]Warning: Could not load config: {e}[/yellow]")
                self.config_data = {}
        
        # Merge with default configuration
        self.config_data = {**self._get_default_config(), **self.config_data}
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration values"""
        return {
            'version': '1.0.0',
            
            # General settings
            'general': {
                'threads': 20,
                'timeout': 30,
                'user_agent': 'Falcon-Scanner/1.0 (AI-Enhanced Security Scanner)',
                'rate_limit': 10,
                'max_retries': 3,
                'output_dir': './output',
                'session_dir': './sessions'
            },
            
            # AI engine settings
            'ai': {
                'enabled': True,
                'model_path': './ai_engine/models',
                'confidence_threshold': 0.7,
                'learning_mode': True,
                'auto_update': True,
                'explain_mode': False
            },
            
            # Scanning modules
            'modules': {
                'subfinder': {
                    'enabled': True,
                    'sources': ['crtsh', 'virustotal', 'threatcrowd', 'dnsdumpster'],
                    'timeout': 60
                },
                'tech_detection': {
                    'enabled': True,
                    'detailed': False,
                    'cve_check': True
                },
                'crawling': {
                    'enabled': True,
                    'max_depth': 3,
                    'max_pages': 1000,
                    'include_static': False
                },
                'param_discovery': {
                    'enabled': True,
                    'wordlist': './data/wordlists/params.txt',
                    'methods': ['GET', 'POST']
                },
                'vulnerability_scanner': {
                    'enabled': True,
                    'checks': ['xss', 'sqli', 'csrf', 'rce', 'ssrf', 'idor', 'open_redirect'],
                    'payload_file': './data/payloads/all.json'
                }
            },
            
            # Output settings
            'output': {
                'format': 'json',
                'include_raw': False,
                'screenshots': False,
                'compress': True
            },
            
            # Logging settings
            'logging': {
                'level': 'INFO',
                'file': './logs/falcon.log',
                'max_size': '100MB',
                'backup_count': 5
            },
            
            # CLI settings
            'cli': {
                'show_banner': True,
                'colored_output': True,
                'progress_bars': True,
                'auto_save_session': True
            },
            
            # Network settings
            'network': {
                'proxy': None,
                'headers': {},
                'cookies': {},
                'verify_ssl': True,
                'follow_redirects': True,
                'max_redirects': 10
            },
            
            # Security settings
            'security': {
                'sandbox_mode': False,
                'max_request_size': '10MB',
                'blocked_extensions': ['.exe', '.zip', '.rar', '.tar'],
                'allowed_domains': [],
                'blocked_domains': []
            },
            
            # Profiles
            'profiles': {
                'webapp': {
                    'modules': ['tech', 'crawl', 'params', 'vulns'],
                    'depth': 3,
                    'ai_mode': 'smart',
                    'intensity': 'medium'
                },
                'api': {
                    'modules': ['tech', 'params', 'vulns'],
                    'depth': 1,
                    'ai_mode': 'aggressive',
                    'intensity': 'high'
                },
                'bug-bounty': {
                    'modules': ['recon', 'tech', 'crawl', 'params', 'vulns'],
                    'depth': 4,
                    'ai_mode': 'aggressive',
                    'intensity': 'high'
                },
                'pentest': {
                    'modules': ['all'],
                    'depth': 5,
                    'ai_mode': 'aggressive',
                    'intensity': 'maximum'
                }
            }
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config_data
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value using dot notation"""
        keys = key.split('.')
        current = self.config_data
        
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        
        current[keys[-1]] = value
    
    def save(self):
        """Save configuration to file"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            
            with open(self.config_path, 'w', encoding='utf-8') as f:
                if self.config_path.endswith('.yaml') or self.config_path.endswith('.yml'):
                    yaml.dump(self.config_data, f, default_flow_style=False, indent=2)
                else:
                    json.dump(self.config_data, f, indent=2, ensure_ascii=False)
            
            console.print(f"[green]✅ Configuration saved to {self.config_path}[/green]")
        except Exception as e:
            console.print(f"[red]❌ Failed to save configuration: {e}[/red]")
    
    def reset(self):
        """Reset configuration to defaults"""
        self.config_data = self._get_default_config()
        self.save()
    
    def show(self):
        """Display current configuration"""
        console.print("[cyan]📋 Current Falcon Configuration:[/cyan]")
        
        def print_dict(d: dict, indent: int = 0):
            for key, value in d.items():
                spaces = "  " * indent
                if isinstance(value, dict):
                    console.print(f"[yellow]{spaces}{key}:[/yellow]")
                    print_dict(value, indent + 1)
                else:
                    console.print(f"[cyan]{spaces}{key}:[/cyan] [white]{value}[/white]")
        
        print_dict(self.config_data)
    
    def validate(self) -> bool:
        """Validate configuration"""
        required_sections = ['general', 'ai', 'modules', 'output', 'logging']
        
        for section in required_sections:
            if section not in self.config_data:
                console.print(f"[red]❌ Missing required section: {section}[/red]")
                return False
        
        # Validate AI settings
        ai_confidence = self.get('ai.confidence_threshold', 0.7)
        if not 0.0 <= ai_confidence <= 1.0:
            console.print("[red]❌ AI confidence threshold must be between 0.0 and 1.0[/red]")
            return False
        
        # Validate thread count
        threads = self.get('general.threads', 20)
        if not isinstance(threads, int) or threads <= 0:
            console.print("[red]❌ Thread count must be a positive integer[/red]")
            return False
        
        return True
    
    def get_profile(self, profile_name: str) -> Dict[str, Any]:
        """Get configuration for a specific profile"""
        profile = self.get(f'profiles.{profile_name}', {})
        if not profile:
            console.print(f"[yellow]⚠️  Profile '{profile_name}' not found, using defaults[/yellow]")
            return {}
        
        return profile
    
    def update_from_args(self, args):
        """Update configuration from command line arguments"""
        if hasattr(args, 'threads') and args.threads:
            self.set('general.threads', args.threads)
        
        if hasattr(args, 'timeout') and args.timeout:
            self.set('general.timeout', args.timeout)
        
        if hasattr(args, 'user_agent') and args.user_agent:
            self.set('general.user_agent', args.user_agent)
        
        if hasattr(args, 'proxy') and args.proxy:
            self.set('network.proxy', args.proxy)
        
        if hasattr(args, 'verbose') and args.verbose:
            self.set('logging.level', 'INFO')
        
        if hasattr(args, 'debug') and args.debug:
            self.set('logging.level', 'DEBUG')
    
    def create_directories(self):
        """Create necessary directories"""
        dirs_to_create = [
            self.get('general.output_dir'),
            self.get('general.session_dir'),
            self.get('ai.model_path'),
            os.path.dirname(self.get('logging.file'))
        ]
        
        for dir_path in dirs_to_create:
            if dir_path:
                os.makedirs(dir_path, exist_ok=True)
