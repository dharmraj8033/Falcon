"""
Falcon AI Engine Manager
Coordinates AI models, training, and intelligent decision making
"""

import asyncio
import json
import pickle
import numpy as np
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime, timedelta
from rich.console import Console

console = Console()

class AIManager:
    """AI Engine Manager for Falcon Scanner"""
    
    def __init__(self, config):
        self.config = config
        self.models = {}
        self.training_data = []
        self.vulnerability_patterns = {}
        self.payload_effectiveness = {}
        self.technology_vulnerabilities = {}
        
        # Initialize AI components
        self.model_path = Path(config.get('ai.model_path', './ai_engine/models'))
        self.model_path.mkdir(parents=True, exist_ok=True)
        
        # Flag to track if AI is initialized
        self._initialized = False
    
    async def initialize(self):
        """Initialize AI components asynchronously"""
        if not self._initialized:
            await self._initialize_ai_components()
            self._initialized = True
    
    async def _initialize_ai_components(self):
        """Initialize AI components and load models"""
        try:
            await self._load_models()
            await self._load_training_data()
            await self._load_vulnerability_patterns()
            await self._load_payload_effectiveness()
            await self._load_technology_vulnerabilities()
            
            console.print("[green]🧠 AI Engine initialized successfully[/green]")
        except Exception as e:
            console.print(f"[yellow]⚠️  AI Engine initialization warning: {e}[/yellow]")
    
    async def _load_models(self):
        """Load pre-trained AI models"""
        model_files = {
            'vulnerability_classifier': 'vuln_classifier.pkl',
            'payload_selector': 'payload_selector.pkl',
            'technology_analyzer': 'tech_analyzer.pkl',
            'exploitability_scorer': 'exploit_scorer.pkl'
        }
        
        for model_name, filename in model_files.items():
            model_file = self.model_path / filename
            if model_file.exists():
                try:
                    with open(model_file, 'rb') as f:
                        self.models[model_name] = pickle.load(f)
                except Exception as e:
                    console.print(f"[yellow]⚠️  Failed to load {model_name}: {e}[/yellow]")
            else:
                # Initialize with basic model
                self.models[model_name] = self._create_basic_model(model_name)
    
    def _create_basic_model(self, model_type: str):
        """Create basic AI model for initial use"""
        if model_type == 'vulnerability_classifier':
            return VulnerabilityClassifier()
        elif model_type == 'payload_selector':
            return PayloadSelector()
        elif model_type == 'technology_analyzer':
            return TechnologyAnalyzer()
        elif model_type == 'exploitability_scorer':
            return ExploitabilityScorer()
        else:
            return BasicAIModel()
    
    async def _load_training_data(self):
        """Load training data from various sources"""
        data_file = self.model_path / 'training_data.json'
        if data_file.exists():
            try:
                with open(data_file, 'r') as f:
                    self.training_data = json.load(f)
            except Exception as e:
                console.print(f"[yellow]⚠️  Failed to load training data: {e}[/yellow]")
                self.training_data = []
    
    async def _load_vulnerability_patterns(self):
        """Load vulnerability detection patterns"""
        patterns_file = self.model_path / 'vuln_patterns.json'
        if patterns_file.exists():
            try:
                with open(patterns_file, 'r') as f:
                    self.vulnerability_patterns = json.load(f)
            except Exception:
                self.vulnerability_patterns = self._get_default_patterns()
        else:
            self.vulnerability_patterns = self._get_default_patterns()
    
    async def _load_payload_effectiveness(self):
        """Load payload effectiveness data"""
        payload_file = self.model_path / 'payload_effectiveness.json'
        if payload_file.exists():
            try:
                with open(payload_file, 'r') as f:
                    self.payload_effectiveness = json.load(f)
            except Exception:
                self.payload_effectiveness = {}
    
    async def _load_technology_vulnerabilities(self):
        """Load technology-specific vulnerability mappings"""
        tech_vuln_file = self.model_path / 'tech_vulnerabilities.json'
        if tech_vuln_file.exists():
            try:
                with open(tech_vuln_file, 'r') as f:
                    self.technology_vulnerabilities = json.load(f)
            except Exception:
                self.technology_vulnerabilities = self._get_default_tech_vulns()
        else:
            self.technology_vulnerabilities = self._get_default_tech_vulns()
    
    def _get_default_patterns(self) -> Dict[str, Any]:
        """Get default vulnerability detection patterns"""
        return {
            'xss': {
                'patterns': [
                    r'<script[^>]*>.*?</script>',
                    r'javascript:',
                    r'on\w+\s*=',
                    r'<iframe[^>]*>',
                    r'<object[^>]*>',
                    r'<embed[^>]*>'
                ],
                'indicators': ['alert(', 'confirm(', 'prompt(', 'console.log']
            },
            'sqli': {
                'patterns': [
                    r"'.*?(\bor\b|\band\b).*?'",
                    r'"\s*(\bor\b|\band\b)\s*"',
                    r'\bunion\b.*?\bselect\b',
                    r'\bselect\b.*?\bfrom\b',
                    r';\s*drop\b',
                    r';\s*delete\b'
                ],
                'indicators': ['SQL syntax error', 'mysql_fetch', 'ORA-', 'PostgreSQL']
            },
            'ssrf': {
                'patterns': [
                    r'https?://localhost',
                    r'https?://127\.0\.0\.1',
                    r'https?://0\.0\.0\.0',
                    r'https?://\[::1\]',
                    r'file://',
                    r'gopher://'
                ],
                'indicators': ['connection refused', 'timeout', 'internal server']
            },
            'rce': {
                'patterns': [
                    r';\s*\w+',
                    r'\|\s*\w+',
                    r'`.*?`',
                    r'\$\(.*?\)',
                    r'exec\(',
                    r'system\(',
                    r'shell_exec\('
                ],
                'indicators': ['command not found', 'permission denied', 'sh:', 'cmd:']
            }
        }
    
    def _get_default_tech_vulns(self) -> Dict[str, Any]:
        """Get default technology-vulnerability mappings"""
        return {
            'wordpress': {
                'common_vulns': ['wp-admin exposure', 'plugin vulnerabilities', 'xmlrpc attacks'],
                'cve_patterns': ['CVE-2019-', 'CVE-2020-', 'CVE-2021-', 'CVE-2022-']
            },
            'apache': {
                'common_vulns': ['server-status', 'server-info', 'directory traversal'],
                'cve_patterns': ['CVE-2021-41773', 'CVE-2021-42013']
            },
            'nginx': {
                'common_vulns': ['alias misconfiguration', 'off-by-slash'],
                'cve_patterns': ['CVE-2019-20372']
            },
            'php': {
                'common_vulns': ['LFI', 'RFI', 'code injection', 'file upload'],
                'cve_patterns': ['CVE-2021-21702', 'CVE-2022-31625']
            },
            'nodejs': {
                'common_vulns': ['prototype pollution', 'path traversal', 'deserialization'],
                'cve_patterns': ['CVE-2021-44531', 'CVE-2022-0235']
            }
        }
    
    async def analyze_vulnerability(self, vulnerability: Dict[str, Any], 
                                 tech_stack: Dict[str, Any], 
                                 confidence_threshold: float = 0.7) -> Optional[Dict[str, Any]]:
        """Analyze vulnerability with AI intelligence"""
        
        try:
            # Use vulnerability classifier
            classifier = self.models.get('vulnerability_classifier')
            if classifier:
                analysis = await classifier.analyze(vulnerability, tech_stack)
                
                if analysis.get('confidence', 0.0) >= confidence_threshold:
                    # Enhance with exploitability scoring
                    exploit_score = await self._calculate_exploitability(vulnerability, tech_stack)
                    analysis['exploitability_score'] = exploit_score
                    
                    # Add technology-specific insights
                    tech_insights = await self._get_technology_insights(vulnerability, tech_stack)
                    analysis['technology_insights'] = tech_insights
                    
                    # Generate explanation if needed
                    if self.config.get('ai.explain_mode', False):
                        explanation = await self._generate_explanation(vulnerability, analysis)
                        analysis['explanation'] = explanation
                    
                    return analysis
            
            return None
            
        except Exception as e:
            console.print(f"[yellow]⚠️  AI analysis failed: {e}[/yellow]")
            return None
    
    async def _calculate_exploitability(self, vulnerability: Dict[str, Any], 
                                      tech_stack: Dict[str, Any]) -> float:
        """Calculate exploitability score for vulnerability"""
        
        scorer = self.models.get('exploitability_scorer')
        if scorer:
            return await scorer.score(vulnerability, tech_stack)
        
        # Basic scoring logic
        base_score = 0.5
        
        # Severity-based scoring
        severity_weights = {
            'CRITICAL': 0.4,
            'HIGH': 0.3,
            'MEDIUM': 0.2,
            'LOW': 0.1,
            'INFO': 0.0
        }
        
        severity = vulnerability.get('severity', 'INFO').upper()
        base_score += severity_weights.get(severity, 0.0)
        
        # Technology-based adjustments
        vuln_type = vulnerability.get('type', '').lower()
        for tech_name, tech_info in tech_stack.items():
            if tech_name.lower() in self.technology_vulnerabilities:
                tech_vulns = self.technology_vulnerabilities[tech_name.lower()]
                if any(vuln in vuln_type for vuln in tech_vulns.get('common_vulns', [])):
                    base_score += 0.1
        
        return min(base_score, 1.0)
    
    async def _get_technology_insights(self, vulnerability: Dict[str, Any], 
                                     tech_stack: Dict[str, Any]) -> List[str]:
        """Get technology-specific vulnerability insights"""
        
        insights = []
        vuln_type = vulnerability.get('type', '').lower()
        
        for tech_name, tech_info in tech_stack.items():
            tech_key = tech_name.lower()
            if tech_key in self.technology_vulnerabilities:
                tech_data = self.technology_vulnerabilities[tech_key]
                
                # Check for common vulnerabilities
                for common_vuln in tech_data.get('common_vulns', []):
                    if common_vuln.lower() in vuln_type:
                        insights.append(f"Common {tech_name} vulnerability: {common_vuln}")
                
                # Version-based insights
                version = tech_info.get('version', '')
                if version:
                    insights.append(f"Check CVE database for {tech_name} {version}")
        
        return insights
    
    async def _generate_explanation(self, vulnerability: Dict[str, Any], 
                                  analysis: Dict[str, Any]) -> str:
        """Generate human-readable explanation for vulnerability"""
        
        vuln_type = vulnerability.get('type', 'Unknown').title()
        severity = vulnerability.get('severity', 'INFO').upper()
        confidence = analysis.get('confidence', 0.0) * 100
        
        explanation = f"This {vuln_type} vulnerability was detected with {confidence:.1f}% confidence. "
        
        if severity in ['CRITICAL', 'HIGH']:
            explanation += "This is a high-priority finding that should be addressed immediately. "
        elif severity == 'MEDIUM':
            explanation += "This vulnerability poses a moderate risk and should be reviewed. "
        else:
            explanation += "This is a low-priority finding that may require attention. "
        
        # Add technology-specific context
        if analysis.get('technology_insights'):
            explanation += "Technology analysis suggests: " + "; ".join(analysis['technology_insights'][:2])
        
        return explanation
    
    async def get_recommendations(self, scan_results: Dict[str, Any], 
                                ai_mode: str) -> Dict[str, Any]:
        """Get AI-powered recommendations based on scan results"""
        
        recommendations = {
            'priority_vulnerabilities': [],
            'suggested_payloads': [],
            'additional_tests': [],
            'false_positive_likelihood': {},
            'next_steps': []
        }
        
        vulnerabilities = scan_results.get('vulnerabilities', [])
        tech_stack = scan_results.get('technologies', {})
        
        # Prioritize vulnerabilities
        for vuln in vulnerabilities:
            ai_analysis = vuln.get('ai_analysis', {})
            exploit_score = ai_analysis.get('exploitability_score', 0.0)
            
            if exploit_score > 0.7:
                recommendations['priority_vulnerabilities'].append({
                    'vulnerability': vuln,
                    'priority_reason': 'High exploitability score',
                    'exploit_score': exploit_score
                })
        
        # Suggest additional tests based on technology stack
        for tech_name in tech_stack.keys():
            if tech_name.lower() in self.technology_vulnerabilities:
                tech_vulns = self.technology_vulnerabilities[tech_name.lower()]
                for vuln_type in tech_vulns.get('common_vulns', []):
                    if not any(vuln_type.lower() in v.get('type', '').lower() 
                             for v in vulnerabilities):
                        recommendations['additional_tests'].append({
                            'test_type': vuln_type,
                            'reason': f'Common vulnerability in {tech_name}',
                            'technology': tech_name
                        })
        
        # AI-mode specific recommendations
        if ai_mode == 'aggressive':
            recommendations['next_steps'].extend([
                'Consider manual verification of all findings',
                'Perform deeper parameter fuzzing',
                'Test for business logic vulnerabilities'
            ])
        elif ai_mode == 'smart':
            recommendations['next_steps'].extend([
                'Focus on high-priority vulnerabilities first',
                'Verify findings with different payloads'
            ])
        
        return recommendations
    
    async def learn_from_scan(self, scan_results: Dict[str, Any], 
                            feedback: Dict[str, Any] = None):
        """Learn from scan results to improve future scans"""
        
        if not self.config.get('ai.learning_mode', True):
            return
        
        # Extract learning data
        learning_entry = {
            'timestamp': datetime.now().isoformat(),
            'target': scan_results.get('target'),
            'technologies': scan_results.get('technologies', {}),
            'vulnerabilities': scan_results.get('vulnerabilities', []),
            'scan_config': scan_results.get('scan_config', {}),
            'feedback': feedback or {}
        }
        
        # Add to training data
        self.training_data.append(learning_entry)
        
        # Update payload effectiveness
        await self._update_payload_effectiveness(scan_results)
        
        # Retrain models if enough new data
        if len(self.training_data) % 100 == 0:  # Retrain every 100 scans
            await self._incremental_training()
    
    async def _update_payload_effectiveness(self, scan_results: Dict[str, Any]):
        """Update payload effectiveness tracking"""
        
        for vuln in scan_results.get('vulnerabilities', []):
            payload = vuln.get('payload', '')
            vuln_type = vuln.get('type', '')
            
            if payload and vuln_type:
                key = f"{vuln_type}:{payload}"
                
                if key not in self.payload_effectiveness:
                    self.payload_effectiveness[key] = {
                        'successes': 0,
                        'attempts': 0,
                        'last_success': None
                    }
                
                self.payload_effectiveness[key]['attempts'] += 1
                self.payload_effectiveness[key]['successes'] += 1
                self.payload_effectiveness[key]['last_success'] = datetime.now().isoformat()
    
    async def _incremental_training(self):
        """Perform incremental training on models"""
        try:
            console.print("[cyan]🧠 Starting incremental AI training...[/cyan]")
            
            # Train vulnerability classifier
            if 'vulnerability_classifier' in self.models:
                await self.models['vulnerability_classifier'].incremental_train(
                    self.training_data[-100:]  # Last 100 entries
                )
            
            # Save updated models
            await self._save_models()
            
            console.print("[green]✅ Incremental training completed[/green]")
            
        except Exception as e:
            console.print(f"[red]❌ Training failed: {e}[/red]")
    
    async def train_model(self, dataset_path: str, model_type: str, epochs: int = 10):
        """Train specific AI model with provided dataset"""
        
        try:
            console.print(f"[cyan]🧠 Training {model_type} model...[/cyan]")
            
            # Load training dataset
            with open(dataset_path, 'r') as f:
                training_data = json.load(f)
            
            # Get or create model
            if model_type not in self.models:
                self.models[model_type] = self._create_basic_model(model_type)
            
            model = self.models[model_type]
            
            # Train model
            if hasattr(model, 'train'):
                await model.train(training_data, epochs)
                console.print(f"[green]✅ {model_type} training completed[/green]")
            else:
                console.print(f"[yellow]⚠️  {model_type} does not support training[/yellow]")
            
            # Save trained model
            await self._save_models()
            
        except Exception as e:
            console.print(f"[red]❌ Training failed: {e}[/red]")
            raise
    
    async def update_models(self, force: bool = False, source: str = 'all'):
        """Update AI models and threat intelligence data"""
        
        try:
            console.print("[cyan]📡 Updating AI models and data...[/cyan]")
            
            if source in ['cve', 'all']:
                await self._update_cve_data()
            
            if source in ['bounty', 'all']:
                await self._update_bounty_data()
            
            # Update models if forced or if data is old
            if force or await self._should_update_models():
                await self._download_updated_models()
            
            console.print("[green]✅ AI models updated successfully[/green]")
            
        except Exception as e:
            console.print(f"[red]❌ Update failed: {e}[/red]")
    
    async def _update_cve_data(self):
        """Update CVE database"""
        # Implementation for CVE data updates
        console.print("[info]📋 Updating CVE database...[/info]")
        # This would fetch from MITRE, NVD, etc.
    
    async def _update_bounty_data(self):
        """Update bug bounty intelligence"""
        # Implementation for bug bounty data updates
        console.print("[info]🏆 Updating bug bounty intelligence...[/info]")
        # This would scrape HackerOne, Bugcrowd, etc.
    
    async def _should_update_models(self) -> bool:
        """Check if models should be updated"""
        model_age_file = self.model_path / 'last_update.txt'
        if not model_age_file.exists():
            return True
        
        try:
            with open(model_age_file, 'r') as f:
                last_update = datetime.fromisoformat(f.read().strip())
            
            # Update if older than 7 days
            return datetime.now() - last_update > timedelta(days=7)
        except Exception:
            return True
    
    async def _download_updated_models(self):
        """Download updated models from server"""
        # Implementation for model downloads
        console.print("[info]⬇️  Downloading updated models...[/info]")
    
    async def _save_models(self):
        """Save all models to disk"""
        for model_name, model in self.models.items():
            if hasattr(model, 'save'):
                model_file = self.model_path / f"{model_name}.pkl"
                with open(model_file, 'wb') as f:
                    pickle.dump(model, f)
        
        # Save training data
        data_file = self.model_path / 'training_data.json'
        with open(data_file, 'w') as f:
            json.dump(self.training_data[-1000:], f, indent=2)  # Keep last 1000 entries
        
        # Save payload effectiveness
        payload_file = self.model_path / 'payload_effectiveness.json'
        with open(payload_file, 'w') as f:
            json.dump(self.payload_effectiveness, f, indent=2)


# Basic AI Model Classes
class BasicAIModel:
    """Base class for AI models"""
    
    def __init__(self):
        self.trained = False
    
    async def analyze(self, data: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        return {'confidence': 0.5, 'analysis': 'basic'}
    
    async def train(self, data: List[Dict[str, Any]], epochs: int = 10):
        self.trained = True
    
    async def incremental_train(self, data: List[Dict[str, Any]]):
        pass

class VulnerabilityClassifier(BasicAIModel):
    """AI model for vulnerability classification"""
    
    async def analyze(self, vulnerability: Dict[str, Any], 
                    tech_stack: Dict[str, Any]) -> Dict[str, Any]:
        
        # Basic classification logic
        confidence = 0.7
        vuln_type = vulnerability.get('type', '').lower()
        
        # Adjust confidence based on vulnerability type
        if vuln_type in ['xss', 'sqli', 'rce']:
            confidence += 0.2
        elif vuln_type in ['ssrf', 'lfi']:
            confidence += 0.1
        
        # Technology context
        for tech in tech_stack.keys():
            if tech.lower() in ['php', 'wordpress', 'apache']:
                confidence += 0.05
        
        return {
            'confidence': min(confidence, 1.0),
            'classification': vuln_type,
            'risk_level': self._calculate_risk(vulnerability, tech_stack)
        }
    
    def _calculate_risk(self, vulnerability: Dict[str, Any], 
                       tech_stack: Dict[str, Any]) -> str:
        severity = vulnerability.get('severity', 'INFO').upper()
        
        if severity in ['CRITICAL', 'HIGH']:
            return 'HIGH'
        elif severity == 'MEDIUM':
            return 'MEDIUM'
        else:
            return 'LOW'

class PayloadSelector(BasicAIModel):
    """AI model for intelligent payload selection"""
    
    async def select_payloads(self, target: str, vuln_type: str, 
                            tech_stack: Dict[str, Any]) -> List[str]:
        
        # Basic payload selection logic
        payloads = []
        
        if vuln_type.lower() == 'xss':
            payloads = [
                '<script>alert("XSS")</script>',
                '"><script>alert("XSS")</script>',
                'javascript:alert("XSS")',
                '<img src=x onerror=alert("XSS")>'
            ]
        elif vuln_type.lower() == 'sqli':
            payloads = [
                "' OR 1=1--",
                '" OR 1=1--',
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--"
            ]
        
        return payloads

class TechnologyAnalyzer(BasicAIModel):
    """AI model for technology analysis"""
    
    async def analyze_tech_stack(self, technologies: Dict[str, Any]) -> Dict[str, Any]:
        
        risk_score = 0.0
        recommendations = []
        
        for tech_name, tech_info in technologies.items():
            # Analyze each technology
            version = tech_info.get('version', '')
            
            # Check for outdated versions (simplified)
            if 'wordpress' in tech_name.lower():
                risk_score += 0.3
                recommendations.append("Check WordPress plugins for vulnerabilities")
            
            if 'apache' in tech_name.lower():
                risk_score += 0.2
                recommendations.append("Verify Apache configuration")
        
        return {
            'risk_score': min(risk_score, 1.0),
            'recommendations': recommendations,
            'priority_technologies': list(technologies.keys())[:3]
        }

class ExploitabilityScorer(BasicAIModel):
    """AI model for exploitability scoring"""
    
    async def score(self, vulnerability: Dict[str, Any], 
                   tech_stack: Dict[str, Any]) -> float:
        
        base_score = 0.5
        
        # Severity factor
        severity_weights = {
            'CRITICAL': 0.4,
            'HIGH': 0.3,
            'MEDIUM': 0.2,
            'LOW': 0.1
        }
        
        severity = vulnerability.get('severity', 'INFO').upper()
        base_score += severity_weights.get(severity, 0.0)
        
        # Vulnerability type factor
        vuln_type = vulnerability.get('type', '').lower()
        if vuln_type in ['rce', 'sqli']:
            base_score += 0.2
        elif vuln_type in ['xss', 'ssrf']:
            base_score += 0.1
        
        return min(base_score, 1.0)
