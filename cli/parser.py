"""
Falcon CLI Parser
Handles command-line argument parsing and routing
"""

import argparse
import sys
from typing import List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from core.scanner import FalconScanner
from core.banner import show_banner
from core.config import FalconConfig
from ai_engine.manager import AIManager

console = Console()

class FalconCLI:
    def __init__(self):
        self.config = FalconConfig()
        self.scanner = FalconScanner(self.config)
        # Don't create separate AI manager, use the one from scanner
        self.ai_manager = self.scanner.ai_manager
        
    def create_parser(self) -> argparse.ArgumentParser:
        """Create the main argument parser"""
        parser = argparse.ArgumentParser(
            prog='falcon',
            description='🦅 Falcon AI-Enhanced Vulnerability Scanner',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  falcon scan --url https://target.com
  falcon scan --file targets.txt --ai-mode aggressive
  falcon recon --domain example.com --passive
  falcon tech --url https://app.com --detailed
  falcon ai-train --dataset bounty-data.json
  falcon autopilot --domain target.com --profile webapp
            """
        )
        
        # Global options
        parser.add_argument('--version', action='version', version='Falcon 1.0.0')
        parser.add_argument('--config', type=str, help='Custom config file path')
        parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
        parser.add_argument('--debug', action='store_true', help='Debug mode')
        parser.add_argument('--no-banner', action='store_true', help='Disable banner')
        parser.add_argument('--threads', '-t', type=int, default=20, help='Number of threads')
        parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds')
        
        # Create subparsers
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Scan command
        self._add_scan_parser(subparsers)
        
        # Reconnaissance command
        self._add_recon_parser(subparsers)
        
        # Technology detection command
        self._add_tech_parser(subparsers)
        
        # AI commands
        self._add_ai_parser(subparsers)
        
        # Autopilot command
        self._add_autopilot_parser(subparsers)
        
        # Utility commands
        self._add_utility_parsers(subparsers)
        
        return parser
    
    def _add_scan_parser(self, subparsers):
        """Add scan command parser"""
        scan_parser = subparsers.add_parser('scan', help='Perform vulnerability scan')
        
        # Target options
        target_group = scan_parser.add_mutually_exclusive_group(required=True)
        target_group.add_argument('--url', '-u', type=str, help='Target URL')
        target_group.add_argument('--file', '-f', type=str, help='File with target URLs')
        target_group.add_argument('--domain', '-d', type=str, help='Target domain')
        
        # Scanning options
        scan_parser.add_argument('--modules', '-m', type=str, 
                               default='tech,crawl,params,vulns',
                               help='Modules to run (comma-separated)')
        scan_parser.add_argument('--depth', type=int, default=2, 
                               help='Crawling depth')
        scan_parser.add_argument('--profile', '-p', type=str,
                               choices=['webapp', 'api', 'bug-bounty', 'pentest'],
                               help='Predefined scan profile')
        
        # AI options
        scan_parser.add_argument('--ai-mode', choices=['passive', 'smart', 'aggressive'],
                               default='smart', help='AI analysis mode')
        scan_parser.add_argument('--ai-explain', action='store_true',
                               help='Provide AI explanations for findings')
        scan_parser.add_argument('--ai-confidence', type=float, default=0.7,
                               help='AI confidence threshold (0.0-1.0)')
        
        # Output options
        scan_parser.add_argument('--export', type=str, help='Export formats (json,html,pdf)')
        scan_parser.add_argument('--output', '-o', type=str, help='Output directory')
        scan_parser.add_argument('--save-session', action='store_true',
                               help='Save scan session for resume')
        
        # Advanced options
        scan_parser.add_argument('--user-agent', type=str, help='Custom User-Agent')
        scan_parser.add_argument('--proxy', type=str, help='Proxy URL')
        scan_parser.add_argument('--headers', type=str, help='Custom headers (JSON)')
        scan_parser.add_argument('--rate-limit', type=int, default=10,
                               help='Requests per second limit')
    
    def _add_recon_parser(self, subparsers):
        """Add reconnaissance command parser"""
        recon_parser = subparsers.add_parser('recon', help='Reconnaissance and enumeration')
        
        recon_parser.add_argument('--domain', '-d', type=str, required=True,
                                help='Target domain')
        recon_parser.add_argument('--passive', action='store_true',
                                help='Passive reconnaissance only')
        recon_parser.add_argument('--active', action='store_true',
                                help='Active reconnaissance')
        recon_parser.add_argument('--subdomains', action='store_true',
                                help='Subdomain enumeration')
        recon_parser.add_argument('--ports', action='store_true',
                                help='Port scanning')
        recon_parser.add_argument('--wordlist', type=str,
                                help='Custom wordlist for enumeration')
        recon_parser.add_argument('--output', '-o', type=str,
                                help='Output file for results')
    
    def _add_tech_parser(self, subparsers):
        """Add technology detection parser"""
        tech_parser = subparsers.add_parser('tech', help='Technology detection and fingerprinting')
        
        target_group = tech_parser.add_mutually_exclusive_group(required=True)
        target_group.add_argument('--url', '-u', type=str, help='Target URL')
        target_group.add_argument('--file', '-f', type=str, help='File with URLs')
        target_group.add_argument('--subdomains-file', type=str, help='Subdomains file')
        
        tech_parser.add_argument('--detailed', action='store_true',
                               help='Detailed technology analysis')
        tech_parser.add_argument('--cve-check', action='store_true',
                               help='Check for known CVEs in detected technologies')
        tech_parser.add_argument('--export', type=str, help='Export format (json,csv)')
    
    def _add_ai_parser(self, subparsers):
        """Add AI-related command parsers"""
        ai_parser = subparsers.add_parser('ai-train', help='Train AI models')
        ai_parser.add_argument('--dataset', type=str, required=True,
                             help='Training dataset file')
        ai_parser.add_argument('--model-type', choices=['vuln-detection', 'payload-selection'],
                             default='vuln-detection', help='Model type to train')
        ai_parser.add_argument('--epochs', type=int, default=10, help='Training epochs')
        
        update_parser = subparsers.add_parser('ai-update', help='Update AI models and data')
        update_parser.add_argument('--force', action='store_true', help='Force update')
        update_parser.add_argument('--source', choices=['cve', 'bounty', 'all'],
                                 default='all', help='Update source')
    
    def _add_autopilot_parser(self, subparsers):
        """Add autopilot command parser"""
        autopilot_parser = subparsers.add_parser('autopilot', 
                                               help='Automated scanning with AI guidance')
        
        autopilot_parser.add_argument('--domain', '-d', type=str, required=True,
                                    help='Target domain')
        autopilot_parser.add_argument('--profile', choices=['webapp', 'api', 'mobile'],
                                    default='webapp', help='Application profile')
        autopilot_parser.add_argument('--intensity', choices=['low', 'medium', 'high'],
                                    default='medium', help='Scan intensity')
        autopilot_parser.add_argument('--time-limit', type=int, help='Time limit in minutes')
        autopilot_parser.add_argument('--ai-explain', action='store_true',
                                    help='Provide AI explanations')
        autopilot_parser.add_argument('--continuous', action='store_true',
                                    help='Continuous monitoring mode')
    
    def _add_utility_parsers(self, subparsers):
        """Add utility command parsers"""
        # Install dependencies
        install_parser = subparsers.add_parser('install-deps', 
                                             help='Install required dependencies')
        install_parser.add_argument('--tools', type=str, help='Specific tools to install')
        
        # Update command
        update_parser = subparsers.add_parser('update', help='Update Falcon and tools')
        update_parser.add_argument('--check-only', action='store_true', 
                                 help='Check for updates only')
        
        # Config command
        config_parser = subparsers.add_parser('config', help='Manage configuration')
        config_parser.add_argument('--show', action='store_true', help='Show current config')
        config_parser.add_argument('--reset', action='store_true', help='Reset to defaults')
        config_parser.add_argument('--set', type=str, help='Set config value (key=value)')
    
    async def run(self):
        """Main CLI execution method"""
        parser = self.create_parser()
        
        if len(sys.argv) == 1:
            if not self.config.get('cli.no_banner', False):
                show_banner()
            parser.print_help()
            return
        
        args = parser.parse_args()
        
        # Show banner unless disabled
        if not args.no_banner and not self.config.get('cli.no_banner', False):
            show_banner()
        
        # Configure logging and debug mode
        if args.debug:
            self.config.set('logging.level', 'DEBUG')
        elif args.verbose:
            self.config.set('logging.level', 'INFO')
        
        # Initialize scanner before routing commands
        await self.scanner.initialize()
        
        # Route to appropriate command handler
        try:
            await self._route_command(args)
        except KeyboardInterrupt:
            console.print("\n[red]⚠️  Scan interrupted by user[/red]")
        except Exception as e:
            console.print(f"[red]❌ Error: {e}[/red]")
            if args.debug:
                import traceback
                console.print(traceback.format_exc())
        finally:
            # Ensure proper cleanup
            if self.scanner.session:
                await self.scanner.session.close()
    
    async def _route_command(self, args):
        """Route commands to appropriate handlers"""
        command_map = {
            'scan': self._handle_scan,
            'recon': self._handle_recon,
            'tech': self._handle_tech,
            'ai-train': self._handle_ai_train,
            'ai-update': self._handle_ai_update,
            'autopilot': self._handle_autopilot,
            'install-deps': self._handle_install_deps,
            'update': self._handle_update,
            'config': self._handle_config
        }
        
        handler = command_map.get(args.command)
        if handler:
            await handler(args)
        else:
            console.print(f"[red]Unknown command: {args.command}[/red]")
    
    async def _handle_scan(self, args):
        """Handle scan command"""
        console.print("[cyan]🎯 Starting vulnerability scan...[/cyan]")
        
        # Configure scanner with CLI arguments
        scan_config = {
            'modules': args.modules.split(',') if args.modules else [],
            'depth': args.depth,
            'ai_mode': args.ai_mode,
            'ai_explain': args.ai_explain,
            'ai_confidence': args.ai_confidence,
            'threads': args.threads,
            'timeout': args.timeout,
            'profile': args.profile,
            'export': args.export.split(',') if args.export else [],
            'output': args.output,
            'save_session': args.save_session,
            'user_agent': args.user_agent,
            'proxy': args.proxy,
            'headers': args.headers,
            'rate_limit': args.rate_limit
        }
        
        # Determine target type and start scan
        if args.url:
            await self.scanner.scan_url(args.url, scan_config)
        elif args.file:
            await self.scanner.scan_file(args.file, scan_config)
        elif args.domain:
            await self.scanner.scan_domain(args.domain, scan_config)
    
    async def _handle_recon(self, args):
        """Handle reconnaissance command"""
        console.print("[cyan]🔍 Starting reconnaissance...[/cyan]")
        
        recon_config = {
            'domain': args.domain,
            'passive': args.passive,
            'active': args.active,
            'subdomains': args.subdomains,
            'ports': args.ports,
            'wordlist': args.wordlist,
            'output': args.output
        }
        
        from modules.recon import ReconModule
        recon = ReconModule(self.config)
        await recon.run(recon_config)
    
    async def _handle_tech(self, args):
        """Handle technology detection command"""
        console.print("[cyan]🔧 Detecting technologies...[/cyan]")
        
        tech_config = {
            'url': args.url,
            'file': args.file,
            'subdomains_file': args.subdomains_file,
            'detailed': args.detailed,
            'cve_check': args.cve_check,
            'export': args.export
        }
        
        from modules.tech_detection import TechDetectionModule
        tech = TechDetectionModule(self.config)
        await tech.run(tech_config)
    
    async def _handle_ai_train(self, args):
        """Handle AI training command"""
        console.print("[cyan]🧠 Training AI models...[/cyan]")
        
        await self.ai_manager.train_model(
            dataset_path=args.dataset,
            model_type=args.model_type,
            epochs=args.epochs
        )
    
    async def _handle_ai_update(self, args):
        """Handle AI update command"""
        console.print("[cyan]📡 Updating AI models and data...[/cyan]")
        
        await self.ai_manager.update_models(
            force=args.force,
            source=args.source
        )
    
    async def _handle_autopilot(self, args):
        """Handle autopilot command"""
        console.print("[cyan]🤖 Starting autopilot mode...[/cyan]")
        
        autopilot_config = {
            'domain': args.domain,
            'profile': args.profile,
            'intensity': args.intensity,
            'time_limit': args.time_limit,
            'ai_explain': args.ai_explain,
            'continuous': args.continuous
        }
        
        console.print("[cyan]🤖 Starting autopilot mode...[/cyan]")
        
        # Basic autopilot implementation - progressive scanning
        try:
            domain = args.domain
            
            # Phase 1: Reconnaissance
            console.print("[yellow]📡 Phase 1: Reconnaissance[/yellow]")
            await self._autopilot_recon(domain)
            
            # Phase 2: Technology Detection
            console.print("[yellow]🔍 Phase 2: Technology Detection[/yellow]")
            await self._autopilot_tech_detection(domain)
            
            # Phase 3: Vulnerability Scanning
            console.print("[yellow]🛡️  Phase 3: Vulnerability Scanning[/yellow]")
            await self._autopilot_vulnerability_scan(domain, args.intensity)
            
            console.print("[green]✅ Autopilot scan completed successfully![/green]")
            
        except Exception as e:
            console.print(f"[red]❌ Autopilot failed: {e}[/red]")
    
    async def _autopilot_recon(self, domain):
        """Autopilot reconnaissance phase"""
        from modules.recon import ReconModule
        recon = ReconModule(self.config)
        
        console.print(f"[cyan]🔎 Discovering subdomains for {domain}...[/cyan]")
        results = await recon.find_subdomains(domain, passive_only=True)
        
        if results:
            console.print(f"[green]✅ Found {len(results)} subdomains[/green]")
            for subdomain in results[:5]:  # Show first 5
                console.print(f"  • {subdomain}")
            if len(results) > 5:
                console.print(f"  ... and {len(results) - 5} more")
        else:
            console.print("[yellow]⚠️  No subdomains found[/yellow]")
    
    async def _autopilot_tech_detection(self, domain):
        """Autopilot technology detection phase"""
        from modules.tech_detection import TechDetectionModule
        tech_detector = TechDetectionModule(self.config)
        
        targets = [f"https://{domain}", f"http://{domain}"]
        
        for target in targets:
            try:
                console.print(f"[cyan]🔧 Analyzing technology stack for {target}...[/cyan]")
                results = await tech_detector.analyze_url(target)
                
                if results.get('technologies'):
                    console.print(f"[green]✅ Detected technologies on {target}[/green]")
                    for tech in results['technologies'][:3]:  # Show first 3
                        console.print(f"  • {tech.get('name', 'Unknown')} {tech.get('version', '')}")
                break  # Stop after first successful detection
            except Exception as e:
                console.print(f"[yellow]⚠️  Could not analyze {target}: {e}[/yellow]")
                continue
    
    async def _autopilot_vulnerability_scan(self, domain, intensity):
        """Autopilot vulnerability scanning phase"""
        from modules.vulnerability_scanner import VulnerabilityModule
        vuln_scanner = VulnerabilityModule(self.config)
        
        target_url = f"https://{domain}"
        
        # Determine test types based on intensity
        test_types = ['xss', 'sqli'] if intensity == 'low' else \
                    ['xss', 'sqli', 'csrf', 'open_redirect'] if intensity == 'medium' else \
                    ['xss', 'sqli', 'csrf', 'open_redirect', 'rce', 'ssrf', 'lfi']
        
        console.print(f"[cyan]🔍 Testing for vulnerabilities ({intensity} intensity)...[/cyan]")
        
        for test_type in test_types:
            try:
                console.print(f"[dim cyan]  Testing {test_type.upper()}...[/dim cyan]")
                results = await vuln_scanner.test_vulnerability(target_url, test_type)
                
                if results and results.get('vulnerable', False):
                    console.print(f"[red]🚨 {test_type.upper()} vulnerability found![/red]")
                else:
                    console.print(f"[green]✅ No {test_type.upper()} vulnerability detected[/green]")
                    
            except Exception as e:
                console.print(f"[yellow]⚠️  {test_type.upper()} test failed: {e}[/yellow]")
        
        # from core.autopilot import AutopilotMode
        # autopilot = AutopilotMode(self.config, self.scanner, self.ai_manager)
        # await autopilot.run(autopilot_config)
    
    async def _handle_install_deps(self, args):
        """Handle dependency installation"""
        console.print("[cyan]📦 Installing dependencies...[/cyan]")
        
        from core.installer import DependencyInstaller
        installer = DependencyInstaller()
        await installer.install(args.tools)
    
    async def _handle_update(self, args):
        """Handle update command"""
        console.print("[cyan]⬆️  Checking for updates...[/cyan]")
        
        from core.updater import FalconUpdater
        updater = FalconUpdater()
        
        if args.check_only:
            await updater.check_updates(check_only=True)
        else:
            await updater.check_updates(check_only=False)
    
    async def _handle_config(self, args):
        """Handle configuration command"""
        if args.show:
            self.config.show()
        elif args.reset:
            self.config.reset()
            console.print("[green]✅ Configuration reset to defaults[/green]")
        elif args.set:
            key, value = args.set.split('=', 1)
            self.config.set(key, value)
            console.print(f"[green]✅ Set {key} = {value}[/green]")
