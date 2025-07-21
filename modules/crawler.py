"""
Web Crawler Module
Intelligent web crawling with AI-guided discovery
"""

import asyncio
import aiohttp
import re
from typing import Dict, List, Any, Set, Optional
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

class CrawlerModule:
    """Intelligent web crawler for URL discovery"""
    
    def __init__(self, config):
        self.config = config
        self.visited_urls = set()
        self.discovered_urls = set()
        self.forms = []
        self.endpoints = []
        self.session = None
        
    async def scan(self, base_url: str, max_depth: int = 3) -> List[str]:
        """Main crawling method"""
        
        console.print(f"[cyan]🕷️  Starting web crawl from: {base_url}[/cyan]")
        
        self.base_domain = urlparse(base_url).netloc
        self.discovered_urls.add(base_url)
        
        connector = aiohttp.TCPConnector(limit=20, limit_per_host=10)
        timeout = aiohttp.ClientTimeout(total=30)
        
        headers = {
            'User-Agent': self.config.get('general.user_agent', 'Falcon-Crawler/1.0')
        }
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers
        ) as session:
            
            self.session = session
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                
                task = progress.add_task("Crawling...", total=None)
                
                await self._crawl_recursive(base_url, 0, max_depth, progress, task)
                
                progress.update(task, description=f"✅ Crawled {len(self.visited_urls)} pages, found {len(self.discovered_urls)} URLs")
        
        console.print(f"[green]✅ Crawling completed! Discovered {len(self.discovered_urls)} URLs[/green]")
        
        return list(self.discovered_urls)
    
    async def _crawl_recursive(self, url: str, current_depth: int, max_depth: int, 
                             progress: Progress, task_id) -> None:
        """Recursively crawl pages"""
        
        if current_depth > max_depth:
            return
        
        if url in self.visited_urls:
            return
        
        # Skip non-HTTP URLs
        if not url.startswith(('http://', 'https://')):
            return
        
        # Skip binary files
        if self._is_binary_url(url):
            return
        
        self.visited_urls.add(url)
        
        try:
            progress.update(task_id, description=f"Crawling depth {current_depth}: {url[:60]}...")
            
            async with self.session.get(url, allow_redirects=True) as response:
                if response.status == 200 and 'text/html' in response.headers.get('content-type', ''):
                    content = await response.text()
                    
                    # Parse the page
                    links, forms, endpoints = await self._parse_page(content, url)
                    
                    # Add discovered URLs
                    self.discovered_urls.update(links)
                    self.forms.extend(forms)
                    self.endpoints.extend(endpoints)
                    
                    # Continue crawling new links
                    for link in links:
                        if link not in self.visited_urls and self._should_crawl_url(link):
                            await self._crawl_recursive(link, current_depth + 1, max_depth, progress, task_id)
                            
                            # Rate limiting
                            await asyncio.sleep(0.1)
        
        except Exception as e:
            console.print(f"[yellow]⚠️  Failed to crawl {url}: {e}[/yellow]")
    
    async def _parse_page(self, content: str, base_url: str) -> tuple:
        """Parse HTML page for links, forms, and endpoints"""
        
        soup = BeautifulSoup(content, 'html.parser')
        links = set()
        forms = []
        endpoints = set()
        
        # Extract links
        for tag in soup.find_all(['a', 'link']):
            href = tag.get('href')
            if href:
                absolute_url = urljoin(base_url, href)
                if self._is_valid_url(absolute_url):
                    links.add(absolute_url)
        
        # Extract script sources
        for script in soup.find_all('script', src=True):
            src = script.get('src')
            if src:
                absolute_url = urljoin(base_url, src)
                if self._is_valid_url(absolute_url):
                    links.add(absolute_url)
        
        # Extract image sources
        for img in soup.find_all('img', src=True):
            src = img.get('src')
            if src:
                absolute_url = urljoin(base_url, src)
                if self._is_valid_url(absolute_url):
                    links.add(absolute_url)
        
        # Extract forms
        for form in soup.find_all('form'):
            form_data = self._parse_form(form, base_url)
            if form_data:
                forms.append(form_data)
        
        # Extract API endpoints from JavaScript
        js_endpoints = self._extract_js_endpoints(content, base_url)
        endpoints.update(js_endpoints)
        
        # Extract potential endpoints from page content
        content_endpoints = self._extract_content_endpoints(content, base_url)
        endpoints.update(content_endpoints)
        
        return links, forms, list(endpoints)
    
    def _parse_form(self, form_tag, base_url: str) -> Optional[Dict[str, Any]]:
        """Parse form element"""
        
        action = form_tag.get('action', '')
        method = form_tag.get('method', 'GET').upper()
        
        # Get absolute action URL
        if action:
            action_url = urljoin(base_url, action)
        else:
            action_url = base_url
        
        # Extract form inputs
        inputs = []
        for input_tag in form_tag.find_all(['input', 'select', 'textarea']):
            input_data = {
                'name': input_tag.get('name'),
                'type': input_tag.get('type', 'text'),
                'value': input_tag.get('value', ''),
                'required': input_tag.has_attr('required')
            }
            
            if input_data['name']:
                inputs.append(input_data)
        
        return {
            'url': action_url,
            'method': method,
            'inputs': inputs,
            'base_url': base_url
        }
    
    def _extract_js_endpoints(self, content: str, base_url: str) -> Set[str]:
        """Extract API endpoints from JavaScript code"""
        
        endpoints = set()
        
        # Common API endpoint patterns
        patterns = [
            r'["\']([/\w\-\.]+/api/[/\w\-\.]*)["\']',
            r'["\']([/\w\-\.]+/v\d+/[/\w\-\.]*)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[get|post|put|delete]+\(["\']([^"\']+)["\']',
            r'jQuery\.[get|post]+\(["\']([^"\']+)["\']',
            r'\$\.[get|post]+\(["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    endpoint = match[0]
                else:
                    endpoint = match
                
                # Convert to absolute URL
                if endpoint.startswith('/'):
                    absolute_url = urljoin(base_url, endpoint)
                    if self._is_valid_url(absolute_url):
                        endpoints.add(absolute_url)
        
        return endpoints
    
    def _extract_content_endpoints(self, content: str, base_url: str) -> Set[str]:
        """Extract potential endpoints from page content"""
        
        endpoints = set()
        
        # Look for URL patterns in content
        url_patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
            r'url:["\']([^"\']+)["\']',
            r'endpoint:["\']([^"\']+)["\']'
        ]
        
        for pattern in url_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match.startswith(('/', 'http')):
                    absolute_url = urljoin(base_url, match)
                    if self._is_valid_url(absolute_url) and '?' not in match:  # Avoid URLs with parameters for now
                        endpoints.add(absolute_url)
        
        return endpoints
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if URL is valid for crawling"""
        
        try:
            parsed = urlparse(url)
            
            # Must be HTTP/HTTPS
            if parsed.scheme not in ['http', 'https']:
                return False
            
            # Must be same domain (unless configured otherwise)
            if parsed.netloc != self.base_domain:
                return False
            
            # Skip fragments
            if parsed.fragment:
                return False
            
            # Skip common non-crawlable paths
            skip_paths = [
                '/logout', '/login', '/signin', '/signout',
                '/download', '/uploads', '/assets', '/static',
                '/images', '/css', '/js', '/fonts'
            ]
            
            for skip_path in skip_paths:
                if skip_path in parsed.path.lower():
                    return False
            
            return True
        
        except Exception:
            return False
    
    def _should_crawl_url(self, url: str) -> bool:
        """Determine if URL should be crawled"""
        
        # Check against crawling limits
        if len(self.visited_urls) >= self.config.get('modules.crawling.max_pages', 1000):
            return False
        
        # Skip if already visited
        if url in self.visited_urls:
            return False
        
        # Additional filtering logic can be added here
        return self._is_valid_url(url)
    
    def _is_binary_url(self, url: str) -> bool:
        """Check if URL points to binary content"""
        
        binary_extensions = [
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.rar', '.tar', '.gz', '.7z',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv',
            '.exe', '.dmg', '.pkg', '.deb', '.rpm'
        ]
        
        url_lower = url.lower()
        return any(url_lower.endswith(ext) for ext in binary_extensions)
    
    def get_forms(self) -> List[Dict[str, Any]]:
        """Get discovered forms"""
        return self.forms
    
    def get_endpoints(self) -> List[str]:
        """Get discovered endpoints"""
        return self.endpoints
    
    def get_statistics(self) -> Dict[str, int]:
        """Get crawling statistics"""
        return {
            'pages_crawled': len(self.visited_urls),
            'urls_discovered': len(self.discovered_urls),
            'forms_found': len(self.forms),
            'endpoints_found': len(self.endpoints)
        }
