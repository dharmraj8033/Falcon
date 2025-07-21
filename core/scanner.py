"""
Core Scanner Engine
"""

import asyncio
import aiohttp
import time
import json
import hashlib
from urllib.parse import urljoin, urlparse, parse_qs
from typing import List, Dict, Any, Optional, Set
from pathlib import Path
import re

from .config import config
from .logger import setup_logger
from .http_client import HTTPClient
from .vulnerability_detector import VulnerabilityDetector
from ..modules.subdomain_finder import SubdomainFinder
from ..modules.technology_detector import TechnologyDetector
from ..modules.parameter_finder import ParameterFinder
from ..modules.crawler import WebCrawler
from ..ai_engine.ai_core import AIEngine

class ScanResult:
    """Container for scan results"""
    
    def __init__(self):
        self.vulnerabilities = []
        self.technologies = {}
        self.subdomains = []
        self.parameters = []
        self.urls = []
        self.forms = []
        self.scan_stats = {
            'start_time': time.time(),
            'end_time': None,
            'urls_scanned': 0,
            'requests_made': 0,
            'vulnerabilities_found': 0,
            'false_positives_filtered': 0
        }
        self.ai_insights = []
    
    def add_vulnerability(self, vuln: Dict[str, Any]):
        """Add vulnerability to results"""
        self.vulnerabilities.append(vuln)
        self.scan_stats['vulnerabilities_found'] += 1
    
    def add_ai_insight(self, insight: Dict[str, Any]):
        """Add AI insight to results"""
        self.ai_insights.append(insight)
    
    def finalize(self):
        """Finalize scan results"""
        self.scan_stats['end_time'] = time.time()
        self.scan_stats['duration'] = self.scan_stats['end_time'] - self.scan_stats['start_time']

class FalconScanner:
    """Main scanner engine"""
    
    def __init__(self, ai_engine: Optional[AIEngine] = None):
        self.logger = setup_logger('falcon-scanner')
        self.ai_engine = ai_engine or AIEngine()
        self.http_client = HTTPClient()
        self.vuln_detector = VulnerabilityDetector(self.ai_engine)
        
        # Initialize modules
        self.subdomain_finder = SubdomainFinder()
        self.tech_detector = TechnologyDetector()
        self.param_finder = ParameterFinder()
        self.crawler = WebCrawler()
        
        # Scan state
        self.is_scanning = False
        self.current_scan = None
        self.visited_urls = set()
        self.scan_queue = asyncio.Queue()
        
    async def scan(self, target: str, modules: List[str] = None, 
                  output_format: str = 'txt', output_file: str = None,
                  verbose: bool = False, autopilot: bool = False,
                  **kwargs) -> ScanResult:
        """Main scanning function"""
        self.logger.info(f"🎯 Starting scan on {target}")
        
        # Initialize scan result
        result = ScanResult()
        self.current_scan = result
        self.is_scanning = True
        
        try:
            # Phase 1: Reconnaissance
            await self._reconnaissance_phase(target, result, autopilot)
            
            # Phase 2: Technology Detection
            await self._technology_detection_phase(target, result)
            
            # Phase 3: Parameter Discovery
            await self._parameter_discovery_phase(target, result)
            
            # Phase 4: Vulnerability Scanning
            modules = modules or config.get('scanning.default_modules', ['all'])
            await self._vulnerability_scanning_phase(target, result, modules)
            
            # Phase 5: AI Analysis
            if self.ai_engine:
                await self._ai_analysis_phase(result)
            
            # Phase 6: Generate Report
            if output_file:
                await self._generate_report(result, output_format, output_file)
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            raise
        finally:
            self.is_scanning = False
            result.finalize()
            self.logger.info(f"✅ Scan completed in {result.scan_stats['duration']:.2f}s")
        
        return result
    
    async def _reconnaissance_phase(self, target: str, result: ScanResult, autopilot: bool):
        """Phase 1: Reconnaissance and subdomain enumeration"""
        self.logger.info("🔍 Phase 1: Reconnaissance")
        
        # Extract domain from target
        parsed = urlparse(target)
        domain = parsed.netloc
        
        # Subdomain enumeration
        if config.get('scanning.subdomain_enumeration', True):
            self.logger.info("📡 Enumerating subdomains...")
            subdomains = await self.subdomain_finder.find_subdomains(domain)
            result.subdomains = subdomains
            self.logger.info(f"Found {len(subdomains)} subdomains")
        
        # Web crawling
        self.logger.info("🕷️ Crawling target...")
        urls = await self.crawler.crawl(target, 
                                       depth=config.get('scanning.crawl_depth', 3))
        result.urls = urls
        result.scan_stats['urls_scanned'] = len(urls)
        self.logger.info(f"Discovered {len(urls)} URLs")
        
        # AI-powered target analysis if autopilot is enabled
        if autopilot and self.ai_engine:
            analysis = await self.ai_engine.analyze_target(target, {
                'subdomains': subdomains,
                'urls': urls
            })
            result.add_ai_insight({
                'type': 'target_analysis',
                'message': analysis.get('recommendations', ''),
                'confidence': analysis.get('confidence', 0)
            })
    
    async def _technology_detection_phase(self, target: str, result: ScanResult):
        """Phase 2: Technology stack detection"""
        self.logger.info("🔧 Phase 2: Technology Detection")
        
        tech_info = await self.tech_detector.detect_technologies(target)
        result.technologies = tech_info
        
        # Log detected technologies
        for category, items in tech_info.items():
            if items:
                self.logger.info(f"Detected {category}: {', '.join([item['name'] for item in items])}")
        
        # AI-powered technology analysis
        if self.ai_engine:
            vuln_suggestions = await self.ai_engine.analyze_technologies(tech_info)
            if vuln_suggestions:
                result.add_ai_insight({
                    'type': 'technology_analysis',
                    'message': f"Technology stack suggests testing for: {', '.join(vuln_suggestions)}",
                    'confidence': 85
                })
    
    async def _parameter_discovery_phase(self, target: str, result: ScanResult):
        """Phase 3: Parameter discovery"""
        self.logger.info("🔍 Phase 3: Parameter Discovery")
        
        # Discover parameters from various sources
        parameters = await self.param_finder.find_parameters(target, result.urls)
        result.parameters = parameters
        self.logger.info(f"Discovered {len(parameters)} parameters")
        
        # Form extraction
        forms = await self.crawler.extract_forms(result.urls)
        result.forms = forms
        self.logger.info(f"Found {len(forms)} forms")
    
    async def _vulnerability_scanning_phase(self, target: str, result: ScanResult, modules: List[str]):
        """Phase 4: Vulnerability scanning"""
        self.logger.info("🎯 Phase 4: Vulnerability Scanning")
        
        # Determine which modules to run
        if 'all' in modules:
            modules = ['xss', 'sqli', 'ssrf', 'rce', 'csrf', 'idor', 'redirect']
        
        # Create scanning tasks
        tasks = []
        for module in modules:
            if hasattr(self.vuln_detector, f'test_{module}'):
                task = self._run_vulnerability_module(module, target, result)
                tasks.append(task)
        
        # Run vulnerability tests concurrently
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _run_vulnerability_module(self, module: str, target: str, result: ScanResult):
        """Run a specific vulnerability testing module"""
        try:
            self.logger.info(f"🔍 Testing for {module.upper()} vulnerabilities...")
            
            # Get the test method
            test_method = getattr(self.vuln_detector, f'test_{module}')
            
            # Prepare test targets (URLs, parameters, forms)
            test_targets = self._prepare_test_targets(result, module)
            
            # Run tests
            vulnerabilities = await test_method(test_targets)
            
            # Filter and add results
            for vuln in vulnerabilities:
                # AI-powered false positive filtering
                if self.ai_engine:
                    is_false_positive = await self.ai_engine.is_false_positive(vuln)
                    if is_false_positive:
                        result.scan_stats['false_positives_filtered'] += 1
                        continue
                
                result.add_vulnerability(vuln)
                self.logger.vulnerability_found(
                    vuln['type'], 
                    vuln['severity'], 
                    vuln['url']
                )
                
        except Exception as e:
            self.logger.error(f"Error in {module} module: {e}")
    
    def _prepare_test_targets(self, result: ScanResult, module: str) -> Dict[str, Any]:
        """Prepare targets for vulnerability testing"""
        return {
            'urls': result.urls,
            'parameters': result.parameters,
            'forms': result.forms,
            'technologies': result.technologies
        }
    
    async def _ai_analysis_phase(self, result: ScanResult):
        """Phase 5: AI analysis and insights"""
        self.logger.info("🧠 Phase 5: AI Analysis")
        
        try:
            # Generate AI insights
            insights = await self.ai_engine.generate_insights(result)
            
            for insight in insights:
                result.add_ai_insight(insight)
                self.logger.ai_insight(
                    insight['type'], 
                    insight['message'], 
                    insight.get('confidence')
                )
                
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
    
    async def _generate_report(self, result: ScanResult, format: str, output_file: str):
        """Generate scan report"""
        from ..output.report_generator import ReportGenerator
        
        generator = ReportGenerator()
        await generator.generate_report(result, format, output_file)
        self.logger.success(f"Report saved to {output_file}")
    
    async def fuzz(self, target: str, wordlist: str = None, parameters: List[str] = None):
        """Perform parameter fuzzing"""
        self.logger.info(f"🎯 Starting fuzzing on {target}")
        
        # Implementation for fuzzing functionality
        pass
    
    async def detect_technology(self, target: str):
        """Standalone technology detection"""
        self.logger.info(f"🔧 Detecting technologies for {target}")
        
        tech_info = await self.tech_detector.detect_technologies(target)
        
        # Print results
        from ..cli.banner import print_tech_stack
        print_tech_stack(tech_info)
        
        return tech_info
    
    async def update_components(self):
        """Update scanner components"""
        self.logger.info("📦 Updating components...")
        
        # Update payloads
        await self._update_payloads()
        
        # Update tools
        await self._update_tools()
        
        # Update AI models
        if self.ai_engine:
            await self.ai_engine.update_models()
        
        self.logger.success("Components updated successfully")
    
    async def _update_payloads(self):
        """Update payload databases"""
        # Implementation for payload updates
        pass
    
    async def _update_tools(self):
        """Update integrated tools"""
        # Implementation for tool updates
        pass
    
    async def cleanup(self):
        """Cleanup resources"""
        self.is_scanning = False
        if self.http_client:
            await self.http_client.close()
        
        self.logger.info("🧹 Cleanup completed")
