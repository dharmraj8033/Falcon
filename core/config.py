"""
Core Configuration Management
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional, List

# Try to import yaml, fallback to json if not available
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

class Config:
    """Configuration manager for Falcon"""
    
    DEFAULT_CONFIG = {
        'general': {
            'user_agent': 'Falcon-AI/1.0 (Security Scanner)',
            'timeout': 30,
            'retries': 3,
            'delay': 0,
            'threads': 10,
            'max_redirects': 5,
            'verify_ssl': False
        },
        'scanning': {
            'default_modules': ['xss', 'sqli', 'ssrf', 'rce'],
            'crawl_depth': 3,
            'forms_detection': True,
            'js_analysis': True,
            'parameter_discovery': True,
            'autopilot': False,
            'aggressive_mode': False
        },
        'ai_engine': {
            'model_path': 'data/models/',
            'confidence_threshold': 0.7,
            'learning_rate': 0.001,
            'batch_size': 32,
            'max_sequence_length': 512,
            'enable_training': True,
            'auto_update': True
        },
        'output': {
            'default_format': 'txt',
            'color_output': True,
            'verbose_level': 1,
            'save_raw_responses': False,
            'report_template': 'detailed'
        },
        'network': {
            'proxy': None,
            'proxy_auth': None,
            'bind_address': None,
            'source_port': None,
            'interface': None
        },
        'payloads': {
            'xss_payloads': 'data/payloads/xss.txt',
            'sqli_payloads': 'data/payloads/sqli.txt',
            'ssrf_payloads': 'data/payloads/ssrf.txt',
            'rce_payloads': 'data/payloads/rce.txt',
            'custom_payloads': 'data/payloads/custom/',
            'encoding_methods': ['url', 'html', 'base64', 'unicode']
        },
        'wordlists': {
            'parameters': 'data/wordlists/parameters.txt',
            'directories': 'data/wordlists/directories.txt',
            'subdomains': 'data/wordlists/subdomains.txt',
            'files': 'data/wordlists/files.txt'
        },
        'tools': {
            'subfinder': {
                'enabled': True,
                'path': '/usr/local/bin/subfinder',
                'timeout': 60,
                'sources': ['crtsh', 'virustotal', 'sublist3r']
            },
            'whatweb': {
                'enabled': True,
                'path': '/usr/local/bin/whatweb',
                'aggression': 3
            },
            'arjun': {
                'enabled': True,
                'path': '/usr/local/bin/arjun',
                'threads': 5
            },
            'katana': {
                'enabled': True,
                'path': '/usr/local/bin/katana',
                'depth': 3
            }
        },
        'database': {
            'engine': 'sqlite',
            'path': 'data/falcon.db',
            'host': 'localhost',
            'port': 5432,
            'name': 'falcon',
            'user': 'falcon',
            'password': ''
        },
        'logging': {
            'level': 'INFO',
            'file': 'logs/falcon.log',
            'max_size': '10MB',
            'backup_count': 5,
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        }
    }
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._get_default_config_path()
        self.config = self.DEFAULT_CONFIG.copy()
        self.load_config()
    
    def _get_default_config_path(self) -> str:
        """Get the default configuration file path"""
        # Try various locations for config file
        possible_paths = [
            os.path.expanduser('~/.falcon/config.yaml'),
            os.path.expanduser('~/.config/falcon/config.yaml'),
            './config.yaml',
            './falcon.yaml'
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        # Return the first path as default
        return possible_paths[0]
    
    def load_config(self):
        """Load configuration from file"""
        if not os.path.exists(self.config_path):
            self.save_config()  # Create default config
            return
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                if self.config_path.endswith('.json'):
                    file_config = json.load(f)
                elif YAML_AVAILABLE:
                    file_config = yaml.safe_load(f)
                else:
                    # Fallback to JSON if YAML not available
                    file_config = json.load(f)
            
            # Merge with default config
            self._deep_merge(self.config, file_config)
            
        except Exception as e:
            print(f"Warning: Failed to load config from {self.config_path}: {e}")
            print("Using default configuration")
    
    def save_config(self):
        """Save current configuration to file"""
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                if self.config_path.endswith('.json'):
                    json.dump(self.config, f, indent=2)
                elif YAML_AVAILABLE:
                    yaml.dump(self.config, f, default_flow_style=False, indent=2)
                else:
                    # Fallback to JSON if YAML not available
                    json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"Warning: Failed to save config to {self.config_path}: {e}")
    
    def get(self, key: str, default=None) -> Any:
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value using dot notation"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def update(self, updates: Dict[str, Any]):
        """Update configuration with a dictionary"""
        self._deep_merge(self.config, updates)
    
    def reset(self):
        """Reset configuration to defaults"""
        self.config = self.DEFAULT_CONFIG.copy()
        self.save_config()
    
    def _deep_merge(self, base: Dict, update: Dict):
        """Deep merge two dictionaries"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def validate(self) -> List[str]:
        """Validate configuration and return list of errors"""
        errors = []
        
        # Check required paths exist
        model_path = self.get('ai_engine.model_path')
        if model_path and not os.path.exists(model_path):
            errors.append(f"AI model path does not exist: {model_path}")
        
        # Check tool paths
        for tool_name, tool_config in self.get('tools', {}).items():
            if tool_config.get('enabled') and tool_config.get('path'):
                if not os.path.exists(tool_config['path']):
                    errors.append(f"{tool_name} tool not found at: {tool_config['path']}")
        
        # Check wordlist files
        for wordlist_name, wordlist_path in self.get('wordlists', {}).items():
            if wordlist_path and not os.path.exists(wordlist_path):
                errors.append(f"Wordlist not found: {wordlist_path}")
        
        # Check payload files
        for payload_name, payload_path in self.get('payloads', {}).items():
            if isinstance(payload_path, str) and payload_path.endswith('.txt'):
                if not os.path.exists(payload_path):
                    errors.append(f"Payload file not found: {payload_path}")
        
        # Validate numeric ranges
        timeout = self.get('general.timeout')
        if timeout and (timeout < 1 or timeout > 300):
            errors.append("Timeout must be between 1 and 300 seconds")
        
        threads = self.get('general.threads')
        if threads and (threads < 1 or threads > 100):
            errors.append("Threads must be between 1 and 100")
        
        return errors
    
    def get_user_agent(self) -> str:
        """Get configured user agent string"""
        return self.get('general.user_agent', self.DEFAULT_CONFIG['general']['user_agent'])
    
    def get_timeout(self) -> int:
        """Get configured timeout"""
        return self.get('general.timeout', self.DEFAULT_CONFIG['general']['timeout'])
    
    def get_threads(self) -> int:
        """Get configured thread count"""
        return self.get('general.threads', self.DEFAULT_CONFIG['general']['threads'])
    
    def is_tool_enabled(self, tool_name: str) -> bool:
        """Check if a tool is enabled"""
        return self.get(f'tools.{tool_name}.enabled', False)
    
    def get_tool_path(self, tool_name: str) -> Optional[str]:
        """Get path to a tool"""
        return self.get(f'tools.{tool_name}.path')
    
    def get_wordlist_path(self, wordlist_type: str) -> Optional[str]:
        """Get path to a wordlist"""
        return self.get(f'wordlists.{wordlist_type}')
    
    def get_payload_path(self, payload_type: str) -> Optional[str]:
        """Get path to payload file"""
        return self.get(f'payloads.{payload_type}')
    
    def to_dict(self) -> Dict[str, Any]:
        """Return configuration as dictionary"""
        return self.config.copy()

# Global configuration instance
config = Config()
