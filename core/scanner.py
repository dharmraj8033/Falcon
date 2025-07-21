"""
Falcon Core Scanner Engine
Main scanning orchestrator that coordinates all modules
"""

import asyncio
import aiohttp
import time
from typing import Dict, List, Any, Optional
from pathlib import Path
from urllib.parse import urlparse
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from .config import FalconConfig
from .banner import show_scan_header, show_progress_info, show_success, show_error, show_vulnerability, show_stats
from ai_engine.manager import AIManager

console = Console()

class FalconScanner:
    """Main Falcon scanner engine"""
    
    def __init__(self, config: FalconConfig):
        self.config = config
        self.session = None
        self.ai_manager = AIManager(config)
        self.results = {}
        self.stats = {
            'total_requests': 0,
            'vulnerabilities_found': 0,
            'technologies_detected': 0,
            'urls_crawled': 0,
            'parameters_found': 0,
            'scan_duration': 0
        }
        
    async def __aenter__(self):
        """Async context manager entry"""
        # Initialize AI manager when event loop is running
        await self.ai_manager.initialize()
        
        connector = aiohttp.TCPConnector(
            limit=self.config.get('general.threads', 20),
            limit_per_host=10,
            ssl=self.config.get('network.verify_ssl', True)
        )
        
        timeout = aiohttp.ClientTimeout(
            total=self.config.get('general.timeout', 30)
        )
        
        headers = {
            'User-Agent': self.config.get('general.user_agent'),
            **self.config.get('network.headers', {})
        }
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers
        )
        
        return self
    
    async def initialize(self):
        """Initialize scanner components manually"""
        if not self.session:
            await self.__aenter__()
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def scan_url(self, url: str, scan_config: Dict[str, Any]):
        """Scan a single URL"""
        start_time = time.time()
        
        try:
            async with self:
                show_scan_header(url, "Single URL Scan")
                
                # Initialize results structure
                self.results = {
                    'target': url,
                    'scan_type': 'url',
                    'timestamp': time.time(),
                    'technologies': {},
                    'vulnerabilities': [],
                    'parameters': [],
                    'crawled_urls': [],
                    'ai_analysis': {}
                }
                
                # Load scan modules based on configuration
                modules = await self._load_modules(scan_config.get('modules', []))
                
                # Execute scan phases
                await self._execute_scan_phases(url, modules, scan_config)
                
                # AI analysis and post-processing
                if scan_config.get('ai_mode') != 'passive':
                    await self._run_ai_analysis(scan_config)
                
                # Generate and export results
                await self._finalize_results(scan_config)
                
        except Exception as e:
            show_error(f"Scan failed: {e}")
            raise
        finally:
            self.stats['scan_duration'] = time.time() - start_time
            show_stats(self.stats)
    
    async def scan_file(self, file_path: str, scan_config: Dict[str, Any]):
        """Scan multiple URLs from a file"""
        start_time = time.time()
        
        try:
            # Read URLs from file
            with open(file_path, 'r') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            show_scan_header(f"{len(urls)} URLs from {file_path}", "Batch URL Scan")
            
            # Process URLs in batches
            batch_size = self.config.get('general.threads', 20)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress:
                
                task = progress.add_task("Scanning URLs...", total=len(urls))
                
                for i in range(0, len(urls), batch_size):
                    batch = urls[i:i + batch_size]
                    
                    # Create tasks for batch
                    tasks = []
                    for url in batch:
                        tasks.append(self._scan_single_url_batch(url, scan_config))
                    
                    # Execute batch
                    await asyncio.gather(*tasks, return_exceptions=True)
                    progress.advance(task, len(batch))
            
        except Exception as e:
            show_error(f"Batch scan failed: {e}")
            raise
        finally:
            self.stats['scan_duration'] = time.time() - start_time
            show_stats(self.stats)
    
    async def scan_domain(self, domain: str, scan_config: Dict[str, Any]):
        """Scan a domain with subdomain enumeration"""
        start_time = time.time()
        
        try:
            show_scan_header(domain, "Domain Scan")
            
            # Step 1: Subdomain enumeration
            show_progress_info("Starting subdomain enumeration...")
            subdomains = await self._enumerate_subdomains(domain)
            
            # Step 2: Technology detection on main domain
            show_progress_info("Detecting technologies...")
            await self._detect_technologies(f"https://{domain}")
            
            # Step 3: Scan discovered subdomains
            if subdomains:
                show_progress_info(f"Scanning {len(subdomains)} discovered subdomains...")
                await self._scan_subdomains(subdomains, scan_config)
            
            # Step 4: AI analysis
            if scan_config.get('ai_mode') != 'passive':
                await self._run_ai_analysis(scan_config)
            
            # Finalize results
            await self._finalize_results(scan_config)
            
        except Exception as e:
            show_error(f"Domain scan failed: {e}")
            raise
        finally:
            self.stats['scan_duration'] = time.time() - start_time
            show_stats(self.stats)
    
    async def _load_modules(self, module_names: List[str]) -> Dict[str, Any]:
        """Load and initialize scanning modules"""
        modules = {}
        
        if 'tech' in module_names:
            from modules.tech_detection import TechDetectionModule
            modules['tech'] = TechDetectionModule(self.config)
        
        if 'crawl' in module_names:
            from modules.crawler import CrawlerModule
            modules['crawl'] = CrawlerModule(self.config)
        
        if 'params' in module_names:
            from modules.param_discovery import ParamDiscoveryModule
            modules['params'] = ParamDiscoveryModule(self.config)
        
        if 'vulns' in module_names:
            from modules.vulnerability_scanner import VulnerabilityModule
            modules['vulns'] = VulnerabilityModule(self.config)
        
        if 'recon' in module_names:
            from modules.recon import ReconModule
            modules['recon'] = ReconModule(self.config)
        
        return modules
    
    async def _execute_scan_phases(self, url: str, modules: Dict[str, Any], scan_config: Dict[str, Any]):
        """Execute scan phases in order"""
        
        # Phase 1: Technology Detection
        if 'tech' in modules:
            show_progress_info("Phase 1: Technology detection...")
            tech_results = await modules['tech'].scan(url)
            self.results['technologies'] = tech_results
            self.stats['technologies_detected'] = len(tech_results)
        
        # Phase 2: Web Crawling
        if 'crawl' in modules:
            show_progress_info("Phase 2: Web crawling...")
            crawl_results = await modules['crawl'].scan(url, scan_config.get('depth', 2))
            self.results['crawled_urls'] = crawl_results
            self.stats['urls_crawled'] = len(crawl_results)
        
        # Phase 3: Parameter Discovery
        if 'params' in modules:
            show_progress_info("Phase 3: Parameter discovery...")
            param_results = await modules['params'].scan(
                self.results.get('crawled_urls', [url])
            )
            self.results['parameters'] = param_results
            self.stats['parameters_found'] = len(param_results)
        
        # Phase 4: Vulnerability Scanning
        if 'vulns' in modules:
            show_progress_info("Phase 4: Vulnerability scanning...")
            vuln_results = await modules['vulns'].scan(
                self.results.get('crawled_urls', [url]),
                self.results.get('parameters', []),
                self.results.get('technologies', {})
            )
            self.results['vulnerabilities'] = vuln_results
            self.stats['vulnerabilities_found'] = len(vuln_results)
            
            # Display found vulnerabilities
            for vuln in vuln_results:
                show_vulnerability(vuln)
    
    async def _run_ai_analysis(self, scan_config: Dict[str, Any]):
        """Run AI analysis on scan results"""
        show_progress_info("Running AI analysis...")
        
        ai_mode = scan_config.get('ai_mode', 'smart')
        ai_confidence = scan_config.get('ai_confidence', 0.7)
        
        # Analyze vulnerabilities with AI
        enhanced_vulns = []
        for vuln in self.results.get('vulnerabilities', []):
            ai_analysis = await self.ai_manager.analyze_vulnerability(
                vuln, 
                self.results.get('technologies', {}),
                confidence_threshold=ai_confidence
            )
            
            if ai_analysis:
                vuln['ai_analysis'] = ai_analysis
                vuln['ai_confidence'] = ai_analysis.get('confidence', 0.0)
                
                if scan_config.get('ai_explain'):
                    vuln['ai_explanation'] = ai_analysis.get('explanation', '')
            
            enhanced_vulns.append(vuln)
        
        self.results['vulnerabilities'] = enhanced_vulns
        
        # Get AI recommendations
        self.results['ai_analysis'] = await self.ai_manager.get_recommendations(
            self.results,
            ai_mode
        )
    
    async def _finalize_results(self, scan_config: Dict[str, Any]):
        """Finalize and export scan results"""
        
        # Add scan metadata
        self.results['scan_config'] = scan_config
        self.results['stats'] = self.stats
        self.results['falcon_version'] = self.config.get('version', '1.0.0')
        
        # Export results
        export_formats = scan_config.get('export', [])
        if export_formats:
            await self._export_results(export_formats, scan_config.get('output'))
        
        # Save session if requested
        if scan_config.get('save_session'):
            await self._save_session()
        
        show_success(f"Scan completed! Found {self.stats['vulnerabilities_found']} vulnerabilities")
    
    async def _export_results(self, formats: List[str], output_dir: Optional[str]):
        """Export results in specified formats"""
        from core.exporter import ResultExporter
        
        exporter = ResultExporter(self.config)
        
        for fmt in formats:
            try:
                await exporter.export(self.results, fmt, output_dir)
                show_success(f"Results exported to {fmt.upper()} format")
            except Exception as e:
                show_error(f"Failed to export {fmt}: {e}")
    
    async def _save_session(self):
        """Save scan session for later resume"""
        import json
        import uuid
        
        session_id = str(uuid.uuid4())[:8]
        session_dir = Path(self.config.get('general.session_dir', './sessions'))
        session_dir.mkdir(exist_ok=True)
        
        session_file = session_dir / f"falcon_session_{session_id}.json"
        
        try:
            with open(session_file, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            
            show_success(f"Session saved: {session_file}")
        except Exception as e:
            show_error(f"Failed to save session: {e}")
    
    async def _scan_single_url_batch(self, url: str, scan_config: Dict[str, Any]):
        """Scan a single URL in batch mode"""
        try:
            # Simplified batch scanning logic
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    self.stats['total_requests'] += 1
                    # Process response here
                    return {'url': url, 'status': response.status}
        except Exception as e:
            return {'url': url, 'error': str(e)}
    
    async def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains for a domain"""
        from modules.recon import ReconModule
        
        recon = ReconModule(self.config)
        return await recon.enumerate_subdomains(domain)
    
    async def _detect_technologies(self, url: str) -> Dict[str, Any]:
        """Detect technologies for a URL"""
        from modules.tech_detection import TechDetectionModule
        
        tech = TechDetectionModule(self.config)
        return await tech.scan(url)
    
    async def _scan_subdomains(self, subdomains: List[str], scan_config: Dict[str, Any]):
        """Scan discovered subdomains"""
        # Implementation for subdomain scanning
        for subdomain in subdomains[:10]:  # Limit for demo
            try:
                url = f"https://{subdomain}"
                # Quick tech detection
                tech_results = await self._detect_technologies(url)
                if tech_results:
                    self.results.setdefault('subdomain_technologies', {})[subdomain] = tech_results
            except Exception:
                continue
