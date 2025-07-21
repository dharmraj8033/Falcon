"""
Parameter Discovery Module
"""

import re
import asyncio
from urllib.parse import urlparse, parse_qs, urljoin
from typing import List, Set, Dict, Any
import json

from ..core.http_client import HTTPClient
from ..core.logger import setup_logger

class ParameterFinder:
    """Discover hidden parameters using various techniques"""
    
    def __init__(self):
        self.logger = setup_logger('param-finder')
        self.http_client = HTTPClient()
        
        # Common parameter wordlist
        self.parameter_wordlist = [
            # Common parameters
            'id', 'user', 'name', 'email', 'password', 'pass', 'pwd', 'token',
            'key', 'api_key', 'access_token', 'session', 'sid', 'csrf', 'nonce',
            'username', 'login', 'admin', 'debug', 'test', 'dev', 'action',
            'cmd', 'command', 'exec', 'system', 'eval', 'code', 'file', 'path',
            'url', 'link', 'redirect', 'return', 'callback', 'jsonp', 'format',
            'type', 'method', 'mode', 'sort', 'order', 'limit', 'offset',
            'page', 'pagesize', 'count', 'max', 'min', 'filter', 'search',
            'query', 'q', 'keyword', 'term', 'category', 'tag', 'status',
            
            # API parameters
            'api', 'version', 'v', 'endpoint', 'resource', 'service', 'data',
            'payload', 'body', 'content', 'message', 'response', 'output',
            'input', 'request', 'params', 'args', 'options', 'config',
            
            # File operations
            'filename', 'filepath', 'directory', 'folder', 'upload', 'download',
            'attachment', 'document', 'image', 'photo', 'video', 'audio',
            'include', 'require', 'load', 'import', 'export', 'backup',
            
            # Database parameters
            'table', 'column', 'field', 'value', 'where', 'select', 'insert',
            'update', 'delete', 'drop', 'create', 'alter', 'index', 'join',
            
            # Authentication/Authorization
            'auth', 'authenticate', 'authorize', 'permission', 'role', 'group',
            'privilege', 'access', 'grant', 'deny', 'allow', 'block', 'ban',
            
            # Time/Date parameters
            'date', 'time', 'timestamp', 'created', 'modified', 'updated',
            'start', 'end', 'from', 'to', 'since', 'until', 'ago', 'future',
            
            # Miscellaneous
            'lang', 'language', 'locale', 'country', 'region', 'timezone',
            'encoding', 'charset', 'mime', 'content-type', 'accept', 'host',
            'domain', 'subdomain', 'port', 'protocol', 'scheme', 'hash',
            'checksum', 'signature', 'verify', 'validate', 'confirm'
        ]
    
    async def find_parameters(self, target_url: str, urls: List[str] = None) -> List[str]:
        """Main parameter discovery function"""
        self.logger.info(f"Starting parameter discovery for {target_url}")
        
        found_parameters = set()
        
        # Method 1: Extract from existing URLs
        if urls:
            url_params = self._extract_from_urls(urls)
            found_parameters.update(url_params)
        
        # Method 2: Extract from HTML forms and JavaScript
        html_params = await self._extract_from_html(target_url)
        found_parameters.update(html_params)
        
        # Method 3: Brute force common parameters
        bruteforce_params = await self._bruteforce_parameters(target_url)
        found_parameters.update(bruteforce_params)
        
        # Method 4: Extract from JavaScript files
        js_params = await self._extract_from_javascript(target_url)
        found_parameters.update(js_params)
        
        # Method 5: Use external tools if available
        external_params = await self._run_external_tools(target_url)
        found_parameters.update(external_params)
        
        result = sorted(list(found_parameters))
        self.logger.info(f"Found {len(result)} unique parameters")
        return result
    
    def _extract_from_urls(self, urls: List[str]) -> Set[str]:
        """Extract parameters from existing URLs"""
        parameters = set()
        
        for url in urls:
            parsed = urlparse(url)
            if parsed.query:
                query_params = parse_qs(parsed.query)
                parameters.update(query_params.keys())
        
        return parameters
    
    async def _extract_from_html(self, target_url: str) -> Set[str]:
        """Extract parameters from HTML forms and content"""
        parameters = set()
        
        try:
            response = await self.http_client.get(target_url)
            if response['status_code'] != 200:
                return parameters
            
            html_content = response['text']
            
            # Extract form input names
            input_pattern = r'<input[^>]+name\s*=\s*["\']([^"\']+)["\']'
            input_matches = re.findall(input_pattern, html_content, re.IGNORECASE)
            parameters.update(input_matches)
            
            # Extract select names
            select_pattern = r'<select[^>]+name\s*=\s*["\']([^"\']+)["\']'
            select_matches = re.findall(select_pattern, html_content, re.IGNORECASE)
            parameters.update(select_matches)
            
            # Extract textarea names
            textarea_pattern = r'<textarea[^>]+name\s*=\s*["\']([^"\']+)["\']'
            textarea_matches = re.findall(textarea_pattern, html_content, re.IGNORECASE)
            parameters.update(textarea_matches)
            
            # Extract from URLs in href and action attributes
            url_pattern = r'(?:href|action)\s*=\s*["\']([^"\']*\?[^"\']*)["\']'
            url_matches = re.findall(url_pattern, html_content, re.IGNORECASE)
            for url_match in url_matches:
                parsed = urlparse(url_match)
                if parsed.query:
                    query_params = parse_qs(parsed.query)
                    parameters.update(query_params.keys())
            
            # Extract potential parameters from JavaScript variables
            js_var_pattern = r'var\s+(\w+)\s*=|let\s+(\w+)\s*=|const\s+(\w+)\s*='
            js_matches = re.findall(js_var_pattern, html_content)
            for match_tuple in js_matches:
                for match in match_tuple:
                    if match and len(match) > 2:  # Filter out very short names
                        parameters.add(match)
        
        except Exception as e:
            self.logger.error(f"Error extracting from HTML: {e}")
        
        return parameters
    
    async def _bruteforce_parameters(self, target_url: str) -> Set[str]:
        """Brute force common parameters"""
        self.logger.info("Brute forcing common parameters...")
        found_parameters = set()
        
        # Get baseline response
        baseline_response = await self.http_client.get(target_url)
        if baseline_response['status_code'] == 0:
            return found_parameters
        
        baseline_length = len(baseline_response['text'])
        baseline_status = baseline_response['status_code']
        
        # Test parameters in batches for efficiency
        batch_size = 5
        for i in range(0, len(self.parameter_wordlist), batch_size):
            batch = self.parameter_wordlist[i:i + batch_size]
            
            # Create concurrent tasks for this batch
            tasks = []
            for param in batch:
                task = self._test_parameter(target_url, param, baseline_length, baseline_status)
                tasks.append(task)
            
            # Execute batch
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for j, result in enumerate(results):
                if result and not isinstance(result, Exception):
                    found_parameters.add(batch[j])
            
            # Rate limiting
            await asyncio.sleep(0.1)
        
        return found_parameters
    
    async def _test_parameter(self, url: str, parameter: str, 
                            baseline_length: int, baseline_status: int) -> bool:
        """Test a single parameter"""
        try:
            # Test with different values
            test_values = ['1', 'test', 'true', 'false', '0', '']
            
            for value in test_values:
                separator = '&' if '?' in url else '?'
                test_url = f"{url}{separator}{parameter}={value}"
                
                response = await self.http_client.get(test_url)
                
                # Check for differences that indicate parameter existence
                if (response['status_code'] != baseline_status or
                    abs(len(response['text']) - baseline_length) > 50 or
                    'error' in response['text'].lower() or
                    'invalid' in response['text'].lower() or
                    'missing' in response['text'].lower()):
                    return True
            
            return False
            
        except Exception:
            return False
    
    async def _extract_from_javascript(self, target_url: str) -> Set[str]:
        """Extract parameters from JavaScript files"""
        parameters = set()
        
        try:
            # Get main page to find JavaScript files
            response = await self.http_client.get(target_url)
            if response['status_code'] != 200:
                return parameters
            
            # Find JavaScript file URLs
            js_pattern = r'<script[^>]+src\s*=\s*["\']([^"\']+\.js[^"\']*)["\']'
            js_files = re.findall(js_pattern, response['text'], re.IGNORECASE)
            
            # Also check inline JavaScript
            inline_js_pattern = r'<script[^>]*>(.*?)</script>'
            inline_js = re.findall(inline_js_pattern, response['text'], re.DOTALL | re.IGNORECASE)
            
            # Process external JavaScript files
            for js_file in js_files[:10]:  # Limit to first 10 files
                js_url = urljoin(target_url, js_file)
                js_params = await self._analyze_javascript_content(js_url)
                parameters.update(js_params)
            
            # Process inline JavaScript
            for js_content in inline_js:
                js_params = self._extract_params_from_js_code(js_content)
                parameters.update(js_params)
        
        except Exception as e:
            self.logger.error(f"Error extracting from JavaScript: {e}")
        
        return parameters
    
    async def _analyze_javascript_content(self, js_url: str) -> Set[str]:
        """Analyze JavaScript file content for parameters"""
        parameters = set()
        
        try:
            response = await self.http_client.get(js_url)
            if response['status_code'] == 200:
                parameters = self._extract_params_from_js_code(response['text'])
        except Exception as e:
            self.logger.error(f"Error analyzing JavaScript file {js_url}: {e}")
        
        return parameters
    
    def _extract_params_from_js_code(self, js_code: str) -> Set[str]:
        """Extract parameter names from JavaScript code"""
        parameters = set()
        
        # Extract from object properties
        property_patterns = [
            r'["\'](\w+)["\']\s*:',  # Object properties
            r'\.(\w+)\s*=',          # Property assignments
            r'\[["\']([\w-]+)["\']\]', # Bracket notation
            r'data-(\w+)',           # Data attributes
            r'name\s*:\s*["\'](\w+)["\']', # Name properties
            r'key\s*:\s*["\'](\w+)["\']',  # Key properties
        ]
        
        for pattern in property_patterns:
            matches = re.findall(pattern, js_code)
            parameters.update(matches)
        
        # Extract from URL patterns
        url_patterns = [
            r'["\'][^"\']*\?[^"\']*[&?](\w+)=',  # URL parameters
            r'fetch\s*\(\s*["\'][^"\']*[&?](\w+)=', # Fetch API calls
            r'ajax\s*\(\s*["\'][^"\']*[&?](\w+)=',  # AJAX calls
        ]
        
        for pattern in url_patterns:
            matches = re.findall(pattern, js_code)
            parameters.update(matches)
        
        return parameters
    
    async def _run_external_tools(self, target_url: str) -> Set[str]:
        """Run external parameter discovery tools"""
        parameters = set()
        
        # Try to run Arjun if available
        arjun_params = await self._run_arjun(target_url)
        parameters.update(arjun_params)
        
        return parameters
    
    async def _run_arjun(self, target_url: str) -> Set[str]:
        """Run Arjun parameter discovery tool"""
        try:
            import subprocess
            
            # Check if arjun is installed
            result = subprocess.run(['which', 'arjun'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                # Run arjun
                cmd = ['arjun', '-u', target_url, '--get', '--quiet']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0:
                    # Parse arjun output
                    parameters = set()
                    for line in result.stdout.split('\n'):
                        if 'Parameter:' in line:
                            param = line.split('Parameter:')[1].strip()
                            parameters.add(param)
                    
                    self.logger.info(f"Arjun found {len(parameters)} parameters")
                    return parameters
        
        except Exception as e:
            self.logger.error(f"Arjun execution failed: {e}")
        
        return set()
    
    async def find_hidden_parameters(self, target_url: str, known_params: List[str]) -> List[str]:
        """Find hidden parameters using differential analysis"""
        self.logger.info("Searching for hidden parameters...")
        
        hidden_parameters = []
        
        # Get baseline response
        baseline = await self.http_client.get(target_url)
        if baseline['status_code'] == 0:
            return hidden_parameters
        
        # Test each parameter from wordlist
        for param in self.parameter_wordlist:
            if param not in known_params:  # Only test unknown parameters
                
                # Test with various payloads
                test_payloads = [
                    '1', 'test', 'admin', 'true', 'false', '0', '',
                    '../../../etc/passwd',  # LFI test
                    'http://localhost',     # SSRF test
                    '<script>alert(1)</script>'  # XSS test
                ]
                
                for payload in test_payloads:
                    separator = '&' if '?' in target_url else '?'
                    test_url = f"{target_url}{separator}{param}={payload}"
                    
                    response = await self.http_client.get(test_url)
                    
                    # Check for significant differences
                    if self._is_significant_difference(baseline, response):
                        hidden_parameters.append(param)
                        self.logger.info(f"Found hidden parameter: {param}")
                        break  # Found this parameter, move to next
                    
                    # Rate limiting
                    await asyncio.sleep(0.05)
        
        return hidden_parameters
    
    def _is_significant_difference(self, baseline: Dict[str, Any], 
                                 response: Dict[str, Any]) -> bool:
        """Check if response is significantly different from baseline"""
        
        # Status code difference
        if baseline['status_code'] != response['status_code']:
            return True
        
        # Content length difference
        baseline_length = len(baseline['text'])
        response_length = len(response['text'])
        
        if abs(baseline_length - response_length) > 100:  # Significant size difference
            return True
        
        # Error message indicators
        error_indicators = [
            'error', 'invalid', 'missing', 'required', 'forbidden',
            'not found', 'denied', 'unauthorized', 'exception'
        ]
        
        for indicator in error_indicators:
            if (indicator in response['text'].lower() and 
                indicator not in baseline['text'].lower()):
                return True
        
        return False
