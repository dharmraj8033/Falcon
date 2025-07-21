"""
Reconnaissance Module
Handles subdomain enumeration, DNS enumeration, and passive reconnaissance
"""

import asyncio
import aiohttp
import dns.resolver
import subprocess
import json
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

class ReconModule:
    """Reconnaissance and enumeration module"""
    
    def __init__(self, config):
        self.config = config
        self.discovered_subdomains = set()
        self.alive_subdomains = set()
        
    async def run(self, config: Dict[str, Any]):
        """Run reconnaissance module"""
        
        domain = config.get('domain')
        if not domain:
            console.print("[red]❌ Domain is required for reconnaissance[/red]")
            return
        
        console.print(f"[cyan]🔍 Starting reconnaissance for: {domain}[/cyan]")
        
        results = {
            'domain': domain,
            'subdomains': [],
            'alive_subdomains': [],
            'dns_records': {},
            'technologies': {},
            'open_ports': {}
        }
        
        # Phase 1: Subdomain enumeration
        if config.get('subdomains', True):
            console.print("[cyan]📡 Enumerating subdomains...[/cyan]")
            subdomains = await self.enumerate_subdomains(domain)
            results['subdomains'] = list(subdomains)
            console.print(f"[green]✅ Found {len(subdomains)} subdomains[/green]")
        
        # Phase 2: Check alive subdomains
        if results['subdomains']:
            console.print("[cyan]🏃 Checking alive subdomains...[/cyan]")
            alive = await self._check_alive_subdomains(results['subdomains'])
            results['alive_subdomains'] = list(alive)
            console.print(f"[green]✅ {len(alive)} subdomains are alive[/green]")
        
        # Phase 3: DNS enumeration
        console.print("[cyan]🌐 Performing DNS enumeration...[/cyan]")
        dns_records = await self._enumerate_dns(domain)
        results['dns_records'] = dns_records
        
        # Phase 4: Port scanning (if active mode)
        if config.get('active') and config.get('ports'):
            console.print("[cyan]🔌 Scanning common ports...[/cyan]")
            ports = await self._scan_ports(domain, results['alive_subdomains'])
            results['open_ports'] = ports
        
        # Save results if output specified
        if config.get('output'):
            await self._save_results(results, config['output'])
        
        return results
    
    async def enumerate_subdomains(self, domain: str) -> set:
        """Enumerate subdomains using multiple techniques"""
        
        subdomains = set()
        
        # Passive sources
        passive_sources = [
            self._subfinder_passive,
            self._crtsh_subdomains,
            self._virustotal_subdomains,
            self._threatcrowd_subdomains,
            self._dnsdumpster_subdomains
        ]
        
        for source in passive_sources:
            try:
                found = await source(domain)
                subdomains.update(found)
            except Exception as e:
                console.print(f"[yellow]⚠️  {source.__name__} failed: {e}[/yellow]")
        
        # DNS brute force (if wordlist provided)
        wordlist = self.config.get('modules.subfinder.wordlist')
        if wordlist:
            brute_force_results = await self._dns_bruteforce(domain, wordlist)
            subdomains.update(brute_force_results)
        
        # Remove invalid subdomains
        valid_subdomains = set()
        for subdomain in subdomains:
            if self._is_valid_subdomain(subdomain, domain):
                valid_subdomains.add(subdomain)
        
        return valid_subdomains
    
    async def _subfinder_passive(self, domain: str) -> List[str]:
        """Use Subfinder for passive subdomain enumeration"""
        
        try:
            # Check if subfinder is installed
            result = subprocess.run(['subfinder', '-version'], capture_output=True, text=True)
            if result.returncode != 0:
                console.print("[yellow]⚠️  Subfinder not installed, skipping[/yellow]")
                return []
            
            # Run subfinder
            cmd = ['subfinder', '-d', domain, '-silent', '-o', '-']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                console.print(f"[info]Subfinder found {len(subdomains)} subdomains[/info]")
                return subdomains
            
        except subprocess.TimeoutExpired:
            console.print("[yellow]⚠️  Subfinder timeout[/yellow]")
        except FileNotFoundError:
            console.print("[yellow]⚠️  Subfinder not found[/yellow]")
        except Exception as e:
            console.print(f"[yellow]⚠️  Subfinder error: {e}[/yellow]")
        
        return []
    
    async def _crtsh_subdomains(self, domain: str) -> List[str]:
        """Query crt.sh for certificate transparency logs"""
        
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        subdomains = set()
                        for entry in data:
                            name_value = entry.get('name_value', '')
                            # Handle multiple domains in one entry
                            for subdomain in name_value.split('\n'):
                                subdomain = subdomain.strip().lower()
                                if subdomain and subdomain.endswith(f'.{domain}'):
                                    # Remove wildcard prefix
                                    if subdomain.startswith('*.'):
                                        subdomain = subdomain[2:]
                                    subdomains.add(subdomain)
                        
                        console.print(f"[info]crt.sh found {len(subdomains)} subdomains[/info]")
                        return list(subdomains)
        
        except Exception as e:
            console.print(f"[yellow]⚠️  crt.sh query failed: {e}[/yellow]")
        
        return []
    
    async def _virustotal_subdomains(self, domain: str) -> List[str]:
        """Query VirusTotal for subdomains"""
        
        # Note: This would require a VirusTotal API key
        # For demo purposes, we'll return empty list
        console.print("[info]VirusTotal integration (requires API key)[/info]")
        return []
    
    async def _threatcrowd_subdomains(self, domain: str) -> List[str]:
        """Query ThreatCrowd for subdomains"""
        
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        subdomains = data.get('subdomains', [])
                        console.print(f"[info]ThreatCrowd found {len(subdomains)} subdomains[/info]")
                        return subdomains
        
        except Exception as e:
            console.print(f"[yellow]⚠️  ThreatCrowd query failed: {e}[/yellow]")
        
        return []
    
    async def _dnsdumpster_subdomains(self, domain: str) -> List[str]:
        """Scrape DNSDumpster for subdomains"""
        
        try:
            # DNSDumpster requires session handling and CSRF tokens
            # This is a simplified implementation
            url = "https://dnsdumpster.com/"
            
            async with aiohttp.ClientSession() as session:
                # Get CSRF token
                async with session.get(url) as response:
                    html = await response.text()
                    
                    # Extract CSRF token (simplified)
                    import re
                    csrf_match = re.search(r'csrfmiddlewaretoken.*?value="([^"]+)"', html)
                    if csrf_match:
                        csrf_token = csrf_match.group(1)
                        
                        # Submit form
                        data = {
                            'csrfmiddlewaretoken': csrf_token,
                            'targetip': domain
                        }
                        
                        async with session.post(url, data=data) as post_response:
                            if post_response.status == 200:
                                result_html = await post_response.text()
                                
                                # Parse subdomains from HTML (simplified)
                                subdomain_pattern = r'([a-zA-Z0-9-]+\.' + re.escape(domain) + r')'
                                subdomains = re.findall(subdomain_pattern, result_html)
                                
                                unique_subdomains = list(set(subdomains))
                                console.print(f"[info]DNSDumpster found {len(unique_subdomains)} subdomains[/info]")
                                return unique_subdomains
        
        except Exception as e:
            console.print(f"[yellow]⚠️  DNSDumpster scraping failed: {e}[/yellow]")
        
        return []
    
    async def _dns_bruteforce(self, domain: str, wordlist_path: str) -> List[str]:
        """Perform DNS brute force enumeration"""
        
        subdomains = []
        
        try:
            with open(wordlist_path, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            
            console.print(f"[info]Starting DNS brute force with {len(wordlist)} words[/info]")
            
            # Limit concurrent requests
            semaphore = asyncio.Semaphore(50)
            tasks = []
            
            for word in wordlist[:1000]:  # Limit for demo
                subdomain = f"{word}.{domain}"
                tasks.append(self._check_dns_record(semaphore, subdomain))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, str):  # Valid subdomain
                    subdomains.append(result)
            
            console.print(f"[info]DNS brute force found {len(subdomains)} subdomains[/info]")
        
        except Exception as e:
            console.print(f"[yellow]⚠️  DNS brute force failed: {e}[/yellow]")
        
        return subdomains
    
    async def _check_dns_record(self, semaphore: asyncio.Semaphore, subdomain: str) -> Optional[str]:
        """Check if subdomain has DNS record"""
        
        async with semaphore:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2
                resolver.lifetime = 5
                
                await asyncio.sleep(0.1)  # Rate limiting
                
                # Try A record
                answers = resolver.resolve(subdomain, 'A')
                if answers:
                    return subdomain
            
            except Exception:
                pass
        
        return None
    
    def _is_valid_subdomain(self, subdomain: str, domain: str) -> bool:
        """Validate subdomain format and domain match"""
        
        if not subdomain or not subdomain.endswith(f'.{domain}'):
            return False
        
        # Check for valid characters
        import re
        if not re.match(r'^[a-zA-Z0-9.-]+$', subdomain):
            return False
        
        # Exclude wildcard entries
        if subdomain.startswith('*.'):
            return False
        
        return True
    
    async def _check_alive_subdomains(self, subdomains: List[str]) -> set:
        """Check which subdomains are alive (respond to HTTP/HTTPS)"""
        
        alive = set()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            task = progress.add_task("Checking subdomains...", total=len(subdomains))
            
            # Limit concurrent requests
            semaphore = asyncio.Semaphore(20)
            tasks = []
            
            for subdomain in subdomains:
                tasks.append(self._check_subdomain_alive(semaphore, subdomain))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, str):  # Alive subdomain
                    alive.add(result)
                progress.advance(task)
        
        return alive
    
    async def _check_subdomain_alive(self, semaphore: asyncio.Semaphore, subdomain: str) -> Optional[str]:
        """Check if subdomain is alive"""
        
        async with semaphore:
            for scheme in ['https', 'http']:
                try:
                    url = f"{scheme}://{subdomain}"
                    
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            url, 
                            timeout=aiohttp.ClientTimeout(total=10),
                            allow_redirects=True
                        ) as response:
                            if response.status < 400:
                                return subdomain
                
                except Exception:
                    continue
        
        return None
    
    async def _enumerate_dns(self, domain: str) -> Dict[str, List[str]]:
        """Enumerate DNS records for domain"""
        
        dns_records = {}
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA']
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        
        for record_type in record_types:
            try:
                answers = resolver.resolve(domain, record_type)
                dns_records[record_type] = [str(rdata) for rdata in answers]
            except Exception:
                dns_records[record_type] = []
        
        return dns_records
    
    async def _scan_ports(self, domain: str, subdomains: List[str]) -> Dict[str, List[int]]:
        """Scan common ports on domain and subdomains"""
        
        open_ports = {}
        common_ports = [80, 443, 8080, 8443, 3000, 8000, 9000]
        
        targets = [domain] + list(subdomains)[:5]  # Limit for demo
        
        for target in targets:
            target_ports = []
            
            for port in common_ports:
                if await self._check_port(target, port):
                    target_ports.append(port)
            
            if target_ports:
                open_ports[target] = target_ports
        
        return open_ports
    
    async def _check_port(self, host: str, port: int) -> bool:
        """Check if port is open"""
        
        try:
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=3)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False
    
    async def _save_results(self, results: Dict[str, Any], output_path: str):
        """Save reconnaissance results to file"""
        
        try:
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            console.print(f"[green]✅ Results saved to {output_path}[/green]")
        
        except Exception as e:
            console.print(f"[red]❌ Failed to save results: {e}[/red]")
