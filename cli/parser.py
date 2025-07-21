"""
CLI Argument Parser
"""

import argparse
import sys
from pathlib import Path

def create_parser():
    """Create and configure the argument parser"""
    parser = argparse.ArgumentParser(
        prog='falcon',
        description='Falcon AI - Advanced AI-Enhanced Vulnerability Scanner',
        epilog='Example: falcon scan --url https://target.com --autopilot',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Global arguments
    parser.add_argument('--version', action='version', version='Falcon AI v1.0.0')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--config', help='Path to configuration file')
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--output', '-o', choices=['json', 'html', 'pdf', 'txt'], 
                             default='txt', help='Output format (default: txt)')
    output_group.add_argument('--output-file', help='Output file path')
    output_group.add_argument('--quiet', '-q', action='store_true', help='Suppress output')
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Perform vulnerability scan')
    scan_parser.add_argument('--url', '-u', required=True, help='Target URL to scan')
    scan_parser.add_argument('--modules', '-m', nargs='+', 
                           choices=['xss', 'sqli', 'ssrf', 'rce', 'csrf', 'idor', 'redirect', 'all'],
                           default=['all'], help='Vulnerability modules to run')
    scan_parser.add_argument('--autopilot', action='store_true', 
                           help='Enable AI autopilot mode')
    scan_parser.add_argument('--explain', action='store_true', 
                           help='Enable AI explanation mode')
    scan_parser.add_argument('--depth', type=int, default=3, 
                           help='Crawling depth (default: 3)')
    scan_parser.add_argument('--threads', type=int, default=10, 
                           help='Number of threads (default: 10)')
    scan_parser.add_argument('--delay', type=float, default=0, 
                           help='Delay between requests in seconds')
    scan_parser.add_argument('--timeout', type=int, default=30, 
                           help='Request timeout in seconds')
    scan_parser.add_argument('--user-agent', help='Custom User-Agent string')
    scan_parser.add_argument('--headers', nargs='+', 
                           help='Custom headers (format: "Header: Value")')
    scan_parser.add_argument('--cookies', help='Cookies string')
    scan_parser.add_argument('--proxy', help='Proxy URL (http://host:port)')
    
    # Fuzz command
    fuzz_parser = subparsers.add_parser('fuzz', help='Perform parameter fuzzing')
    fuzz_parser.add_argument('--url', '-u', required=True, help='Target URL')
    fuzz_parser.add_argument('--wordlist', '-w', help='Custom wordlist file')
    fuzz_parser.add_argument('--parameters', '-p', nargs='+', 
                           help='Specific parameters to fuzz')
    fuzz_parser.add_argument('--method', choices=['GET', 'POST', 'PUT', 'DELETE'], 
                           default='GET', help='HTTP method')
    fuzz_parser.add_argument('--data', help='POST data')
    fuzz_parser.add_argument('--encode', choices=['url', 'html', 'base64'], 
                           help='Payload encoding')
    
    # Tech detection command
    tech_parser = subparsers.add_parser('tech', help='Detect technology stack')
    tech_parser.add_argument('--url', '-u', required=True, help='Target URL')
    tech_parser.add_argument('--aggressive', action='store_true', 
                           help='Enable aggressive detection')
    tech_parser.add_argument('--fingerprint', action='store_true', 
                           help='Detailed fingerprinting')
    
    # Update command
    update_parser = subparsers.add_parser('update', help='Update components')
    update_parser.add_argument('--ai-data', action='store_true', 
                             help='Update AI training data')
    update_parser.add_argument('--payloads', action='store_true', 
                             help='Update payload databases')
    update_parser.add_argument('--tools', action='store_true', 
                             help='Update integrated tools')
    update_parser.add_argument('--all', action='store_true', 
                             help='Update everything')
    
    # AI training command
    ai_parser = subparsers.add_parser('ai-train', help='Train AI models')
    ai_parser.add_argument('--sources', nargs='+', 
                         choices=['bugbounty', 'cve', 'github', 'custom'],
                         default=['bugbounty', 'cve'], 
                         help='Training data sources')
    ai_parser.add_argument('--epochs', type=int, default=5, 
                         help='Training epochs')
    ai_parser.add_argument('--data-path', help='Path to custom training data')
    ai_parser.add_argument('--model-name', help='Custom model name')
    
    # Subdomain enumeration
    subdomain_parser = subparsers.add_parser('subdomains', help='Enumerate subdomains')
    subdomain_parser.add_argument('--domain', '-d', required=True, help='Target domain')
    subdomain_parser.add_argument('--passive', action='store_true', 
                                help='Passive enumeration only')
    subdomain_parser.add_argument('--active', action='store_true', 
                                help='Active enumeration')
    subdomain_parser.add_argument('--wordlist', help='Custom subdomain wordlist')
    
    # Crawl command
    crawl_parser = subparsers.add_parser('crawl', help='Crawl target for URLs')
    crawl_parser.add_argument('--url', '-u', required=True, help='Target URL')
    crawl_parser.add_argument('--depth', type=int, default=3, help='Crawl depth')
    crawl_parser.add_argument('--scope', help='Scope regex pattern')
    crawl_parser.add_argument('--include-js', action='store_true', 
                            help='Include JavaScript files')
    crawl_parser.add_argument('--forms', action='store_true', 
                            help='Extract forms')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate reports')
    report_parser.add_argument('--input', '-i', required=True, 
                             help='Input scan results file')
    report_parser.add_argument('--template', choices=['detailed', 'executive', 'technical'],
                             default='detailed', help='Report template')
    
    # Config command
    config_parser = subparsers.add_parser('config', help='Manage configuration')
    config_parser.add_argument('--show', action='store_true', 
                             help='Show current configuration')
    config_parser.add_argument('--set', nargs=2, metavar=('KEY', 'VALUE'),
                             help='Set configuration value')
    config_parser.add_argument('--reset', action='store_true', 
                             help='Reset to default configuration')
    
    # Profile command
    profile_parser = subparsers.add_parser('profile', help='Manage scan profiles')
    profile_parser.add_argument('--create', help='Create new profile')
    profile_parser.add_argument('--list', action='store_true', 
                              help='List available profiles')
    profile_parser.add_argument('--use', help='Use specific profile')
    profile_parser.add_argument('--delete', help='Delete profile')
    
    # If no subcommand is given, check for direct URL
    if len(sys.argv) >= 2 and sys.argv[1].startswith(('http://', 'https://')):
        # Parse as direct URL scan
        parser.add_argument('url', help='Target URL to scan')
        return parser
    
    return parser

def validate_args(args):
    """Validate command line arguments"""
    errors = []
    
    # Validate URL format
    if hasattr(args, 'url') and args.url:
        if not args.url.startswith(('http://', 'https://')):
            errors.append("URL must start with http:// or https://")
    
    # Validate file paths
    if hasattr(args, 'wordlist') and args.wordlist:
        if not Path(args.wordlist).exists():
            errors.append(f"Wordlist file not found: {args.wordlist}")
    
    if hasattr(args, 'config') and args.config:
        if not Path(args.config).exists():
            errors.append(f"Configuration file not found: {args.config}")
    
    # Validate numeric ranges
    if hasattr(args, 'threads') and args.threads:
        if args.threads < 1 or args.threads > 100:
            errors.append("Threads must be between 1 and 100")
    
    if hasattr(args, 'depth') and args.depth:
        if args.depth < 1 or args.depth > 10:
            errors.append("Depth must be between 1 and 10")
    
    if hasattr(args, 'timeout') and args.timeout:
        if args.timeout < 1 or args.timeout > 300:
            errors.append("Timeout must be between 1 and 300 seconds")
    
    return errors
