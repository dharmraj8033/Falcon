"""
Web Crawler Module
"""

import asyncio
import re
from urllib.parse import urljoin, urlparse, unquote
from typing import List, Set, Dict, Any
from collections import deque
import hashlib

from ..core.http_client import HTTPClient
from ..core.logger import setup_logger

class WebCrawler:
    """Fast web crawler for URL and form discovery"""
    
    def __init__(self):
        self.logger = setup_logger('crawler')
        self.http_client = HTTPClient()
        self.visited_urls = set()
        self.discovered_urls = set()
        self.forms = []
        self.max_depth = 3
        self.max_urls = 1000
        
    async def crawl(self, start_url: str, depth: int = 3, 
                   scope_regex: str = None, include_js: bool = True) -> List[str]:
        """Main crawling function"""
        self.logger.info(f"Starting crawl from {start_url} with depth {depth}")
        
        self.max_depth = depth
        self.visited_urls.clear()
        self.discovered_urls.clear()
        
        # Initialize scope
        parsed_start = urlparse(start_url)
        base_domain = parsed_start.netloc
        
        # BFS crawling
        queue = deque([(start_url, 0)])  # (url, current_depth)
        
        while queue and len(self.discovered_urls) < self.max_urls:
            current_url, current_depth = queue.popleft()
            
            if current_depth >= self.max_depth:
                continue
            
            if current_url in self.visited_urls:
                continue
            
            # Check scope
            if not self._is_in_scope(current_url, base_domain, scope_regex):
                continue
            
            self.visited_urls.add(current_url)
            self.discovered_urls.add(current_url)
            
            # Crawl the page
            new_urls = await self._crawl_page(current_url, include_js)
            
            # Add new URLs to queue
            for new_url in new_urls:
                if new_url not in self.visited_urls:
                    queue.append((new_url, current_depth + 1))
            
            # Rate limiting
            await asyncio.sleep(0.1)
        
        result = sorted(list(self.discovered_urls))
        self.logger.info(f"Crawled {len(self.visited_urls)} pages, found {len(result)} URLs")
        return result
    
    async def _crawl_page(self, url: str, include_js: bool = True) -> Set[str]:
        """Crawl a single page and extract URLs"""
        new_urls = set()
        
        try:
            response = await self.http_client.get(url)
            
            if response['status_code'] != 200:
                return new_urls
            
            content = response['text']
            
            # Extract URLs from various sources
            new_urls.update(self._extract_href_urls(content, url))
            new_urls.update(self._extract_action_urls(content, url))
            new_urls.update(self._extract_src_urls(content, url))
            
            if include_js:
                new_urls.update(self._extract_javascript_urls(content, url))
            
            # Extract forms
            page_forms = self._extract_forms(content, url)
            self.forms.extend(page_forms)
            
        except Exception as e:
            self.logger.error(f"Error crawling {url}: {e}")
        
        return new_urls
    
    def _extract_href_urls(self, content: str, base_url: str) -> Set[str]:
        """Extract URLs from href attributes"""
        urls = set()
        
        # Match href attributes
        href_pattern = r'href\s*=\s*["\']([^"\']+)["\']'
        matches = re.findall(href_pattern, content, re.IGNORECASE)
        
        for match in matches:
            url = self._normalize_url(match, base_url)
            if url:
                urls.add(url)
        
        return urls
    
    def _extract_action_urls(self, content: str, base_url: str) -> Set[str]:
        """Extract URLs from form action attributes"""
        urls = set()
        
        action_pattern = r'action\s*=\s*["\']([^"\']+)["\']'
        matches = re.findall(action_pattern, content, re.IGNORECASE)
        
        for match in matches:
            url = self._normalize_url(match, base_url)
            if url:
                urls.add(url)
        
        return urls
    
    def _extract_src_urls(self, content: str, base_url: str) -> Set[str]:
        """Extract URLs from src attributes"""
        urls = set()
        
        src_pattern = r'src\s*=\s*["\']([^"\']+)["\']'
        matches = re.findall(src_pattern, content, re.IGNORECASE)
        
        for match in matches:
            url = self._normalize_url(match, base_url)
            if url and not self._is_static_resource(url):
                urls.add(url)
        
        return urls
    
    def _extract_javascript_urls(self, content: str, base_url: str) -> Set[str]:
        """Extract URLs from JavaScript code"""
        urls = set()
        
        # Common JavaScript URL patterns
        js_patterns = [
            r'["\']([^"\']*(?:https?://|/)[^"\']*)["\']',  # General URLs
            r'location\.href\s*=\s*["\']([^"\']+)["\']',   # Location redirects
            r'window\.open\s*\(\s*["\']([^"\']+)["\']',    # Window open
            r'fetch\s*\(\s*["\']([^"\']+)["\']',           # Fetch API
            r'ajax\s*\(\s*["\']([^"\']+)["\']',            # AJAX calls
            r'\.load\s*\(\s*["\']([^"\']+)["\']',          # jQuery load
            r'\.get\s*\(\s*["\']([^"\']+)["\']',           # HTTP GET
            r'\.post\s*\(\s*["\']([^"\']+)["\']',          # HTTP POST
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                url = self._normalize_url(match, base_url)
                if url and not self._is_static_resource(url):
                    urls.add(url)
        
        return urls
    
    def _extract_forms(self, content: str, base_url: str) -> List[Dict[str, Any]]:
        """Extract form information"""
        forms = []
        
        # Find all form tags
        form_pattern = r'<form([^>]*)>(.*?)</form>'
        form_matches = re.findall(form_pattern, content, re.DOTALL | re.IGNORECASE)
        
        for form_attrs, form_content in form_matches:
            form_info = {
                'url': base_url,
                'action': self._extract_form_action(form_attrs, base_url),
                'method': self._extract_form_method(form_attrs),
                'inputs': self._extract_form_inputs(form_content),
                'enctype': self._extract_form_enctype(form_attrs)
            }
            forms.append(form_info)
        
        return forms
    
    def _extract_form_action(self, form_attrs: str, base_url: str) -> str:
        """Extract form action URL"""
        action_match = re.search(r'action\s*=\s*["\']([^"\']+)["\']', form_attrs, re.IGNORECASE)
        if action_match:
            action = action_match.group(1)
            return self._normalize_url(action, base_url) or base_url
        return base_url
    
    def _extract_form_method(self, form_attrs: str) -> str:
        """Extract form method"""
        method_match = re.search(r'method\s*=\s*["\']([^"\']+)["\']', form_attrs, re.IGNORECASE)
        return method_match.group(1).upper() if method_match else 'GET'
    
    def _extract_form_enctype(self, form_attrs: str) -> str:
        """Extract form encoding type"""
        enctype_match = re.search(r'enctype\s*=\s*["\']([^"\']+)["\']', form_attrs, re.IGNORECASE)
        return enctype_match.group(1) if enctype_match else 'application/x-www-form-urlencoded'
    
    def _extract_form_inputs(self, form_content: str) -> List[Dict[str, str]]:
        """Extract form input fields"""
        inputs = []
        
        # Extract input tags
        input_pattern = r'<input([^>]*)>'
        input_matches = re.findall(input_pattern, form_content, re.IGNORECASE)
        
        for input_attrs in input_matches:
            input_info = {
                'type': self._extract_attribute(input_attrs, 'type') or 'text',
                'name': self._extract_attribute(input_attrs, 'name'),
                'value': self._extract_attribute(input_attrs, 'value'),
                'placeholder': self._extract_attribute(input_attrs, 'placeholder')
            }
            if input_info['name']:  # Only add inputs with names
                inputs.append(input_info)
        
        # Extract textarea tags
        textarea_pattern = r'<textarea([^>]*)>'
        textarea_matches = re.findall(textarea_pattern, form_content, re.IGNORECASE)
        
        for textarea_attrs in textarea_matches:
            textarea_info = {
                'type': 'textarea',
                'name': self._extract_attribute(textarea_attrs, 'name'),
                'value': '',
                'placeholder': self._extract_attribute(textarea_attrs, 'placeholder')
            }
            if textarea_info['name']:
                inputs.append(textarea_info)
        
        # Extract select tags
        select_pattern = r'<select([^>]*)>'
        select_matches = re.findall(select_pattern, form_content, re.IGNORECASE)
        
        for select_attrs in select_matches:
            select_info = {
                'type': 'select',
                'name': self._extract_attribute(select_attrs, 'name'),
                'value': '',
                'placeholder': ''
            }
            if select_info['name']:
                inputs.append(select_info)
        
        return inputs
    
    def _extract_attribute(self, attrs: str, attr_name: str) -> str:
        """Extract specific attribute value"""
        pattern = rf'{attr_name}\s*=\s*["\']([^"\']*)["\']'
        match = re.search(pattern, attrs, re.IGNORECASE)
        return match.group(1) if match else ''
    
    def _normalize_url(self, url: str, base_url: str) -> str:
        """Normalize and validate URL"""
        if not url:
            return None
        
        # Skip javascript:, mailto:, tel:, etc.
        if any(url.lower().startswith(proto) for proto in 
               ['javascript:', 'mailto:', 'tel:', 'sms:', 'data:']):
            return None
        
        # Skip anchors
        if url.startswith('#'):
            return None
        
        # Decode URL
        url = unquote(url)
        
        # Join with base URL
        try:
            full_url = urljoin(base_url, url)
            
            # Validate URL structure
            parsed = urlparse(full_url)
            if not parsed.scheme or not parsed.netloc:
                return None
            
            # Remove fragment
            if parsed.fragment:
                full_url = full_url.split('#')[0]
            
            return full_url
            
        except Exception:
            return None
    
    def _is_in_scope(self, url: str, base_domain: str, scope_regex: str = None) -> bool:
        """Check if URL is in crawling scope"""
        try:
            parsed = urlparse(url)
            
            # Must be same domain (or subdomain)
            if not parsed.netloc.endswith(base_domain):
                return False
            
            # Custom scope regex
            if scope_regex:
                if not re.search(scope_regex, url):
                    return False
            
            return True
            
        except Exception:
            return False
    
    def _is_static_resource(self, url: str) -> bool:
        """Check if URL points to static resource"""
        static_extensions = [
            '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
            '.ico', '.pdf', '.doc', '.docx', '.zip', '.rar', '.tar', '.gz',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.swf', '.woff',
            '.woff2', '.ttf', '.eot', '.otf'
        ]
        
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        return any(path.endswith(ext) for ext in static_extensions)
    
    async def extract_forms(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Extract forms from a list of URLs"""
        all_forms = []
        
        # Process URLs in batches
        batch_size = 10
        for i in range(0, len(urls), batch_size):
            batch = urls[i:i + batch_size]
            
            # Create concurrent tasks
            tasks = []
            for url in batch:
                tasks.append(self._extract_forms_from_url(url))
            
            # Execute batch
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Collect results
            for result in results:
                if isinstance(result, list):
                    all_forms.extend(result)
        
        # Remove duplicates based on form signature
        unique_forms = []
        seen_signatures = set()
        
        for form in all_forms:
            signature = self._get_form_signature(form)
            if signature not in seen_signatures:
                unique_forms.append(form)
                seen_signatures.add(signature)
        
        self.logger.info(f"Extracted {len(unique_forms)} unique forms")
        return unique_forms
    
    async def _extract_forms_from_url(self, url: str) -> List[Dict[str, Any]]:
        """Extract forms from a single URL"""
        try:
            response = await self.http_client.get(url)
            if response['status_code'] == 200:
                return self._extract_forms(response['text'], url)
        except Exception as e:
            self.logger.error(f"Error extracting forms from {url}: {e}")
        
        return []
    
    def _get_form_signature(self, form: Dict[str, Any]) -> str:
        """Generate unique signature for form"""
        action = form.get('action', '')
        method = form.get('method', '')
        input_names = sorted([inp.get('name', '') for inp in form.get('inputs', [])])
        
        signature_data = f"{action}:{method}:{':'.join(input_names)}"
        return hashlib.md5(signature_data.encode()).hexdigest()
    
    async def deep_crawl(self, start_url: str, max_pages: int = 100) -> Dict[str, Any]:
        """Perform deep crawling with comprehensive analysis"""
        self.logger.info(f"Starting deep crawl of {start_url}")
        
        # Regular crawl
        urls = await self.crawl(start_url, depth=5, include_js=True)
        
        # Extract forms
        forms = await self.extract_forms(urls)
        
        # Analyze JavaScript files
        js_urls = [url for url in urls if url.endswith('.js')]
        js_analysis = await self._analyze_javascript_files(js_urls)
        
        # Look for interesting endpoints
        interesting_endpoints = self._find_interesting_endpoints(urls)
        
        # Extract API endpoints
        api_endpoints = self._extract_api_endpoints(urls)
        
        return {
            'urls': urls,
            'forms': forms,
            'javascript_analysis': js_analysis,
            'interesting_endpoints': interesting_endpoints,
            'api_endpoints': api_endpoints,
            'total_pages_crawled': len(self.visited_urls)
        }
    
    async def _analyze_javascript_files(self, js_urls: List[str]) -> Dict[str, Any]:
        """Analyze JavaScript files for interesting content"""
        analysis = {
            'endpoints': [],
            'api_keys': [],
            'secrets': [],
            'comments': []
        }
        
        for js_url in js_urls[:20]:  # Limit analysis
            try:
                response = await self.http_client.get(js_url)
                if response['status_code'] == 200:
                    js_content = response['text']
                    
                    # Extract potential endpoints
                    endpoints = re.findall(r'["\'][^"\']*(?:/api/|/v\d+/)[^"\']*["\']', js_content)
                    analysis['endpoints'].extend(endpoints)
                    
                    # Look for API keys and secrets
                    api_key_patterns = [
                        r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                        r'secret["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                        r'token["\']?\s*[:=]\s*["\']([^"\']+)["\']'
                    ]
                    
                    for pattern in api_key_patterns:
                        matches = re.findall(pattern, js_content, re.IGNORECASE)
                        analysis['secrets'].extend(matches)
                    
                    # Extract comments
                    comment_patterns = [
                        r'//\s*(.+)',
                        r'/\*\s*(.*?)\s*\*/'
                    ]
                    
                    for pattern in comment_patterns:
                        matches = re.findall(pattern, js_content)
                        analysis['comments'].extend(matches)
                        
            except Exception as e:
                self.logger.error(f"Error analyzing JavaScript file {js_url}: {e}")
        
        return analysis
    
    def _find_interesting_endpoints(self, urls: List[str]) -> List[str]:
        """Find potentially interesting endpoints"""
        interesting_keywords = [
            'admin', 'api', 'debug', 'test', 'dev', 'staging', 'backup',
            'config', 'settings', 'dashboard', 'panel', 'management',
            'upload', 'download', 'file', 'document', 'report', 'export',
            'login', 'logout', 'auth', 'register', 'password', 'reset',
            'user', 'profile', 'account', 'member', 'customer', 'client'
        ]
        
        interesting_urls = []
        for url in urls:
            url_lower = url.lower()
            if any(keyword in url_lower for keyword in interesting_keywords):
                interesting_urls.append(url)
        
        return interesting_urls
    
    def _extract_api_endpoints(self, urls: List[str]) -> List[str]:
        """Extract potential API endpoints"""
        api_patterns = [
            r'/api/',
            r'/v\d+/',
            r'/rest/',
            r'/graphql',
            r'/webhook',
            r'\.json',
            r'\.xml'
        ]
        
        api_urls = []
        for url in urls:
            if any(re.search(pattern, url, re.IGNORECASE) for pattern in api_patterns):
                api_urls.append(url)
        
        return api_urls
