"""
Subdomain Discovery Module
"""

import asyncio
import subprocess
import json
import socket
from typing import List, Set
from urllib.parse import urlparse
import re

from ..core.http_client import HTTPClient
from ..core.logger import setup_logger

class SubdomainFinder:
    """Subdomain enumeration using multiple techniques"""
    
    def __init__(self):
        self.logger = setup_logger('subdomain-finder')
        self.http_client = HTTPClient()
        self.found_subdomains = set()
        
        # Common subdomain wordlist
        self.wordlist = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
            'blog', 'shop', 'app', 'mobile', 'secure', 'vpn', 'ssh', 'git',
            'jenkins', 'jira', 'confluence', 'wiki', 'docs', 'help', 'support',
            'portal', 'dashboard', 'panel', 'cpanel', 'webmail', 'mx', 'ns1',
            'ns2', 'dns', 'cdn', 'media', 'static', 'images', 'assets', 'files',
            'download', 'upload', 'backup', 'old', 'new', 'beta', 'alpha',
            'demo', 'sandbox', 'internal', 'intranet', 'extranet', 'remote'
        ]
    
    async def find_subdomains(self, domain: str) -> List[str]:
        """Main subdomain discovery function"""
        self.logger.info(f"Starting subdomain enumeration for {domain}")
        
        # Run multiple discovery methods
        tasks = [
            self._passive_dns_discovery(domain),
            self._bruteforce_discovery(domain),
            self._search_engine_discovery(domain),
            self._certificate_transparency_discovery(domain)
        ]
        
        # Execute all methods concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Combine all results
        all_subdomains = set()
        for result in results:
            if isinstance(result, list):
                all_subdomains.update(result)
        
        # Validate subdomains
        valid_subdomains = await self._validate_subdomains(list(all_subdomains))
        
        self.logger.info(f"Found {len(valid_subdomains)} valid subdomains")
        return sorted(list(valid_subdomains))
    
    async def _passive_dns_discovery(self, domain: str) -> List[str]:
        """Passive DNS discovery using public APIs"""
        subdomains = set()
        
        try:
            # Use crt.sh certificate transparency logs
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = await self.http_client.get(url)
            
            if response['status_code'] == 200:
                try:
                    data = json.loads(response['text'])
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        if name_value:
                            # Handle multiple domains in name_value
                            for subdomain in name_value.split('\n'):
                                subdomain = subdomain.strip()
                                if subdomain.endswith(f'.{domain}'):
                                    subdomains.add(subdomain)
                except json.JSONDecodeError:
                    pass
        
        except Exception as e:
            self.logger.error(f"Passive DNS discovery failed: {e}")
        
        return list(subdomains)
    
    async def _bruteforce_discovery(self, domain: str) -> List[str]:
        """Brute force subdomain discovery"""
        subdomains = set()
        
        # Create tasks for concurrent DNS resolution
        tasks = []
        for subdomain in self.wordlist:
            full_domain = f"{subdomain}.{domain}"
            tasks.append(self._resolve_subdomain(full_domain))
        
        # Resolve all subdomains concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(results):
            if result and not isinstance(result, Exception):
                subdomains.add(f"{self.wordlist[i]}.{domain}")
        
        return list(subdomains)
    
    async def _resolve_subdomain(self, subdomain: str) -> bool:
        """Resolve a single subdomain"""
        try:
            loop = asyncio.get_event_loop()
            # Use asyncio's DNS resolution
            result = await loop.getaddrinfo(subdomain, None)
            return bool(result)
        except Exception:
            return False
    
    async def _search_engine_discovery(self, domain: str) -> List[str]:
        """Search engine based subdomain discovery"""
        subdomains = set()
        
        # Google dorking for subdomains
        search_queries = [
            f"site:*.{domain}",
            f"site:{domain} inurl:subdomain",
            f"site:{domain} filetype:xml",
        ]
        
        for query in search_queries:
            try:
                # Note: In production, you'd use proper search APIs
                # This is a simplified example
                url = f"https://www.google.com/search?q={query}"
                response = await self.http_client.get(url, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                
                if response['status_code'] == 200:
                    # Extract subdomains from search results
                    subdomain_pattern = rf'\b\w+\.{re.escape(domain)}\b'
                    matches = re.findall(subdomain_pattern, response['text'])
                    subdomains.update(matches)
                
                # Rate limiting
                await asyncio.sleep(1)
                
            except Exception as e:
                self.logger.error(f"Search engine discovery failed: {e}")
        
        return list(subdomains)
    
    async def _certificate_transparency_discovery(self, domain: str) -> List[str]:
        """Certificate transparency log discovery"""
        subdomains = set()
        
        try:
            # Use censys.io API (free tier)
            # Note: In production, you'd need API keys
            url = f"https://search.censys.io/api/v2/certificates/search"
            params = {
                'q': f'names: *.{domain}',
                'per_page': 100
            }
            
            response = await self.http_client.get(url, params=params)
            
            if response['status_code'] == 200:
                try:
                    data = json.loads(response['text'])
                    hits = data.get('result', {}).get('hits', [])
                    
                    for hit in hits:
                        names = hit.get('names', [])
                        for name in names:
                            if name.endswith(f'.{domain}'):
                                subdomains.add(name)
                                
                except json.JSONDecodeError:
                    pass
        
        except Exception as e:
            self.logger.error(f"Certificate transparency discovery failed: {e}")
        
        return list(subdomains)
    
    async def _validate_subdomains(self, subdomains: List[str]) -> List[str]:
        """Validate that subdomains are actually accessible"""
        valid_subdomains = []
        
        # Create tasks for concurrent validation
        tasks = []
        for subdomain in subdomains:
            tasks.append(self._validate_single_subdomain(subdomain))
        
        # Validate all subdomains concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(results):
            if result and not isinstance(result, Exception):
                valid_subdomains.append(subdomains[i])
        
        return valid_subdomains
    
    async def _validate_single_subdomain(self, subdomain: str) -> bool:
        """Validate a single subdomain by making an HTTP request"""
        try:
            # Try both HTTP and HTTPS
            for protocol in ['https', 'http']:
                url = f"{protocol}://{subdomain}"
                response = await self.http_client.head(url)
                
                # Consider it valid if we get any response (even errors)
                if response['status_code'] > 0:
                    return True
            
            return False
            
        except Exception:
            return False
    
    async def run_subfinder(self, domain: str) -> List[str]:
        """Run external subfinder tool if available"""
        try:
            # Check if subfinder is installed
            result = subprocess.run(['which', 'subfinder'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                # Run subfinder
                cmd = ['subfinder', '-d', domain, '-silent']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0:
                    subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                    self.logger.info(f"Subfinder found {len(subdomains)} subdomains")
                    return subdomains
        
        except Exception as e:
            self.logger.error(f"Subfinder execution failed: {e}")
        
        return []
    
    async def run_assetfinder(self, domain: str) -> List[str]:
        """Run external assetfinder tool if available"""
        try:
            # Check if assetfinder is installed
            result = subprocess.run(['which', 'assetfinder'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                # Run assetfinder
                cmd = ['assetfinder', '--subs-only', domain]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0:
                    subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                    self.logger.info(f"Assetfinder found {len(subdomains)} subdomains")
                    return subdomains
        
        except Exception as e:
            self.logger.error(f"Assetfinder execution failed: {e}")
        
        return []
