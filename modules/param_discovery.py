"""
Parameter Discovery Module
Discovers hidden parameters in web applications
"""

import asyncio
import aiohttp
import itertools
from typing import Dict, List, Any, Set
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

class ParamDiscoveryModule:
    """Parameter discovery and fuzzing module"""
    
    def __init__(self, config):
        self.config = config
        self.wordlists = {
            'common': [
                'id', 'user', 'admin', 'test', 'debug', 'action', 'cmd', 'exec',
                'file', 'path', 'dir', 'page', 'url', 'link', 'src', 'data',
                'key', 'value', 'name', 'type', 'mode', 'format', 'output',
                'callback', 'redirect', 'return', 'next', 'back', 'ref',
                'search', 'query', 'q', 'keyword', 'term', 'filter',
                'sort', 'order', 'limit', 'offset', 'count', 'max', 'min',
                'start', 'end', 'from', 'to', 'date', 'time', 'timestamp',
                'token', 'session', 'auth', 'login', 'password', 'pass',
                'username', 'email', 'mail', 'phone', 'mobile', 'address'
            ],
            'api': [
                'api_key', 'apikey', 'access_token', 'auth_token', 'bearer',
                'client_id', 'client_secret', 'scope', 'grant_type',
                'response_type', 'state', 'nonce', 'code_challenge',
                'version', 'v', 'format', 'pretty', 'include', 'exclude',
                'fields', 'expand', 'embed', 'with', 'without', 'only'
            ],
            'security': [
                'csrf_token', 'csrf', 'authenticity_token', '_token',
                'anti_csrf', 'xsrf_token', 'form_token', 'request_token',
                'verify', 'validation', 'check', 'confirm', 'approve'
            ]
        }
        
        self.load_custom_wordlist()
    
    def load_custom_wordlist(self):
        """Load custom wordlist if specified"""
        
        wordlist_path = self.config.get('modules.param_discovery.wordlist')
        if wordlist_path:
            try:
                with open(wordlist_path, 'r') as f:
                    custom_words = [line.strip() for line in f if line.strip()]
                    self.wordlists['custom'] = custom_words
                    console.print(f"[info]Loaded {len(custom_words)} words from custom wordlist[/info]")
            except Exception as e:
                console.print(f"[yellow]⚠️  Failed to load custom wordlist: {e}[/yellow]")
    
    async def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Main parameter discovery method"""
        
        console.print(f"[cyan]🔧 Starting parameter discovery on {len(urls)} URLs[/cyan]")
        
        discovered_params = []
        
        connector = aiohttp.TCPConnector(limit=20, limit_per_host=10)
        timeout = aiohttp.ClientTimeout(total=15)
        
        headers = {
            'User-Agent': self.config.get('general.user_agent', 'Falcon-ParamDiscovery/1.0')
        }
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers
        ) as session:
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                console=console
            ) as progress:
                
                task = progress.add_task("Discovering parameters...", total=len(urls))
                
                for url in urls:
                    try:
                        url_params = await self._discover_url_params(session, url)
                        if url_params:
                            discovered_params.append({
                                'url': url,
                                'parameters': url_params,
                                'method': 'GET'
                            })
                        
                        # Also test POST parameters
                        post_params = await self._discover_post_params(session, url)
                        if post_params:
                            discovered_params.append({
                                'url': url,
                                'parameters': post_params,
                                'method': 'POST'
                            })
                    
                    except Exception as e:
                        console.print(f"[yellow]⚠️  Failed to scan {url}: {e}[/yellow]")
                    
                    progress.advance(task)
        
        console.print(f"[green]✅ Parameter discovery completed! Found {sum(len(p['parameters']) for p in discovered_params)} parameters[/green]")
        
        return discovered_params
    
    async def _discover_url_params(self, session: aiohttp.ClientSession, url: str) -> List[Dict[str, Any]]:
        """Discover GET parameters for a URL"""
        
        discovered = []
        
        # Get baseline response
        baseline = await self._get_baseline_response(session, url)
        if not baseline:
            return discovered
        
        # Test parameter discovery methods
        methods = [
            self._test_common_params,
            self._test_error_based_discovery,
            self._test_reflection_based_discovery
        ]
        
        all_wordlists = []
        for wordlist_name, words in self.wordlists.items():
            all_wordlists.extend(words)
        
        # Remove duplicates and limit size
        unique_words = list(set(all_wordlists))[:500]  # Limit for performance
        
        for method in methods:
            try:
                found_params = await method(session, url, baseline, unique_words)
                discovered.extend(found_params)
            except Exception as e:
                console.print(f"[yellow]⚠️  Discovery method failed: {e}[/yellow]")
        
        # Remove duplicates
        unique_params = []
        seen_params = set()
        
        for param in discovered:
            param_name = param['name']
            if param_name not in seen_params:
                seen_params.add(param_name)
                unique_params.append(param)
        
        return unique_params
    
    async def _discover_post_params(self, session: aiohttp.ClientSession, url: str) -> List[Dict[str, Any]]:
        """Discover POST parameters for a URL"""
        
        discovered = []
        
        # Get baseline POST response
        try:
            async with session.post(url) as response:
                baseline_status = response.status
                baseline_length = len(await response.text())
        except Exception:
            return discovered
        
        # Test common POST parameters
        common_post_params = [
            'data', 'content', 'message', 'text', 'body', 'input',
            'username', 'password', 'email', 'name', 'title',
            'description', 'comment', 'feedback', 'subject'
        ]
        
        for param_name in common_post_params[:20]:  # Limit for performance
            try:
                test_data = {param_name: 'test_value'}
                
                async with session.post(url, data=test_data) as response:
                    status = response.status
                    length = len(await response.text())
                    
                    # Check for differences indicating parameter acceptance
                    if status != baseline_status or abs(length - baseline_length) > 10:
                        discovered.append({
                            'name': param_name,
                            'type': 'POST',
                            'evidence': f'Status: {status} (baseline: {baseline_status}), Length diff: {abs(length - baseline_length)}',
                            'confidence': 0.7
                        })
            
            except Exception:
                continue
        
        return discovered
    
    async def _get_baseline_response(self, session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
        """Get baseline response for comparison"""
        
        try:
            async with session.get(url) as response:
                content = await response.text()
                return {
                    'status': response.status,
                    'length': len(content),
                    'content': content,
                    'headers': dict(response.headers)
                }
        except Exception:
            return None
    
    async def _test_common_params(self, session: aiohttp.ClientSession, url: str, 
                                baseline: Dict[str, Any], wordlist: List[str]) -> List[Dict[str, Any]]:
        """Test common parameter names"""
        
        discovered = []
        
        # Test parameters in batches
        batch_size = 10
        for i in range(0, min(len(wordlist), 100), batch_size):  # Limit total tests
            batch = wordlist[i:i + batch_size]
            
            tasks = []
            for param_name in batch:
                tasks.append(self._test_single_param(session, url, param_name, baseline))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for param_name, result in zip(batch, results):
                if isinstance(result, dict) and result.get('found'):
                    discovered.append({
                        'name': param_name,
                        'type': 'GET',
                        'evidence': result.get('evidence', ''),
                        'confidence': result.get('confidence', 0.5)
                    })
            
            # Rate limiting
            await asyncio.sleep(0.1)
        
        return discovered
    
    async def _test_single_param(self, session: aiohttp.ClientSession, url: str, 
                               param_name: str, baseline: Dict[str, Any]) -> Dict[str, Any]:
        """Test a single parameter"""
        
        try:
            # Build test URL
            test_url = f"{url}{'&' if '?' in url else '?'}{param_name}=test_value"
            
            async with session.get(test_url) as response:
                content = await response.text()
                status = response.status
                length = len(content)
                
                # Compare with baseline
                status_diff = status != baseline['status']
                length_diff = abs(length - baseline['length'])
                content_diff = content != baseline['content']
                
                # Check for parameter reflection
                param_reflected = param_name in content or 'test_value' in content
                
                # Calculate confidence
                confidence = 0.0
                evidence_parts = []
                
                if status_diff:
                    confidence += 0.3
                    evidence_parts.append(f"Status changed: {status}")
                
                if length_diff > 10:
                    confidence += 0.2
                    evidence_parts.append(f"Length diff: {length_diff}")
                
                if param_reflected:
                    confidence += 0.4
                    evidence_parts.append("Parameter reflected")
                
                if content_diff and length_diff > 5:
                    confidence += 0.1
                    evidence_parts.append("Content changed")
                
                if confidence > 0.3:  # Threshold for detection
                    return {
                        'found': True,
                        'confidence': min(confidence, 1.0),
                        'evidence': '; '.join(evidence_parts)
                    }
        
        except Exception:
            pass
        
        return {'found': False}
    
    async def _test_error_based_discovery(self, session: aiohttp.ClientSession, url: str, 
                                        baseline: Dict[str, Any], wordlist: List[str]) -> List[Dict[str, Any]]:
        """Test parameters using error-based discovery"""
        
        discovered = []
        
        # Error-inducing values
        error_values = [
            "';", '";', '\\', '/', '..', '???', 'null', 'undefined',
            '<script>', '${7*7}', '{{7*7}}', '<%=7*7%>',
            'admin', 'root', '0', '-1', '9999999', 'true', 'false'
        ]
        
        # Test subset of wordlist with error values
        test_params = wordlist[:50]  # Limit for performance
        
        for param_name in test_params:
            for error_value in error_values[:3]:  # Limit error values per param
                try:
                    test_url = f"{url}{'&' if '?' in url else '?'}{param_name}={error_value}"
                    
                    async with session.get(test_url) as response:
                        content = await response.text()
                        status = response.status
                        
                        # Look for error indicators
                        error_indicators = [
                            'error', 'exception', 'warning', 'notice',
                            'mysql', 'postgresql', 'oracle', 'sql',
                            'stack trace', 'line number', 'file not found',
                            'permission denied', 'access denied'
                        ]
                        
                        content_lower = content.lower()
                        error_found = any(indicator in content_lower for indicator in error_indicators)
                        
                        if error_found or status in [400, 500, 502, 503]:
                            discovered.append({
                                'name': param_name,
                                'type': 'GET',
                                'evidence': f'Error response with value "{error_value}"',
                                'confidence': 0.8
                            })
                            break  # Move to next parameter after finding error
                
                except Exception:
                    continue
                
                # Rate limiting
                await asyncio.sleep(0.05)
        
        return discovered
    
    async def _test_reflection_based_discovery(self, session: aiohttp.ClientSession, url: str, 
                                             baseline: Dict[str, Any], wordlist: List[str]) -> List[Dict[str, Any]]:
        """Test parameters using reflection-based discovery"""
        
        discovered = []
        
        # Use unique reflection values
        reflection_values = [
            'falcon_test_12345',
            'unique_value_67890',
            'reflection_test_xyz'
        ]
        
        # Test subset of wordlist
        test_params = wordlist[:30]  # Limit for performance
        
        for param_name in test_params:
            for reflection_value in reflection_values:
                try:
                    test_url = f"{url}{'&' if '?' in url else '?'}{param_name}={reflection_value}"
                    
                    async with session.get(test_url) as response:
                        content = await response.text()
                        
                        # Check if value is reflected in response
                        if reflection_value in content:
                            discovered.append({
                                'name': param_name,
                                'type': 'GET',
                                'evidence': f'Value "{reflection_value}" reflected in response',
                                'confidence': 0.9
                            })
                            break  # Move to next parameter
                
                except Exception:
                    continue
                
                # Rate limiting
                await asyncio.sleep(0.05)
        
        return discovered
    
    async def analyze_existing_params(self, url: str) -> List[Dict[str, Any]]:
        """Analyze existing parameters in URL"""
        
        parsed_url = urlparse(url)
        if not parsed_url.query:
            return []
        
        params = parse_qs(parsed_url.query)
        analyzed_params = []
        
        for param_name, param_values in params.items():
            param_info = {
                'name': param_name,
                'values': param_values,
                'type': 'existing',
                'analysis': self._analyze_param_pattern(param_name, param_values)
            }
            analyzed_params.append(param_info)
        
        return analyzed_params
    
    def _analyze_param_pattern(self, param_name: str, param_values: List[str]) -> Dict[str, Any]:
        """Analyze parameter name and values for patterns"""
        
        analysis = {
            'likely_purpose': 'unknown',
            'security_risk': 'low',
            'data_type': 'string'
        }
        
        param_lower = param_name.lower()
        
        # Analyze parameter name
        if any(keyword in param_lower for keyword in ['id', 'key', 'token']):
            analysis['likely_purpose'] = 'identifier'
            analysis['security_risk'] = 'medium'
        
        elif any(keyword in param_lower for keyword in ['file', 'path', 'dir', 'url']):
            analysis['likely_purpose'] = 'file_path'
            analysis['security_risk'] = 'high'
        
        elif any(keyword in param_lower for keyword in ['cmd', 'exec', 'command']):
            analysis['likely_purpose'] = 'command'
            analysis['security_risk'] = 'critical'
        
        elif any(keyword in param_lower for keyword in ['admin', 'debug', 'test']):
            analysis['likely_purpose'] = 'debugging'
            analysis['security_risk'] = 'medium'
        
        elif any(keyword in param_lower for keyword in ['redirect', 'return', 'callback']):
            analysis['likely_purpose'] = 'redirect'
            analysis['security_risk'] = 'medium'
        
        # Analyze parameter values
        if param_values:
            value = param_values[0]
            
            if value.isdigit():
                analysis['data_type'] = 'integer'
            elif value.lower() in ['true', 'false']:
                analysis['data_type'] = 'boolean'
            elif value.startswith(('http://', 'https://', 'ftp://')):
                analysis['data_type'] = 'url'
                analysis['security_risk'] = 'medium'
            elif '/' in value or '\\' in value:
                analysis['data_type'] = 'path'
                analysis['security_risk'] = 'high'
        
        return analysis
