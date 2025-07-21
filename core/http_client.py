"""
HTTP Client for web requests
"""

import asyncio
import ssl
import time
from urllib.parse import urljoin, urlparse
from typing import Dict, Any, Optional, List
import json

# Try to import aiohttp, fallback to urllib if not available
try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    import urllib.request
    import urllib.parse
    import urllib.error
    AIOHTTP_AVAILABLE = False

class HTTPClient:
    """Async HTTP client with security testing features"""
    
    def __init__(self, 
                 timeout: int = 30,
                 max_concurrent: int = 10,
                 user_agent: str = None,
                 proxy: str = None):
        
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_concurrent = max_concurrent
        self.user_agent = user_agent or "Falcon-AI/1.0 (Security Scanner)"
        self.proxy = proxy
        self.session = None
        self.semaphore = asyncio.Semaphore(max_concurrent)
        
        # SSL context that allows self-signed certificates
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
        # Request statistics
        self.stats = {
            'requests_made': 0,
            'total_time': 0,
            'errors': 0,
            'timeouts': 0
        }
    
    async def __aenter__(self):
        await self.start_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    async def start_session(self):
        """Start the HTTP session"""
        if self.session is None:
            connector = aiohttp.TCPConnector(
                ssl=self.ssl_context,
                limit=100,
                limit_per_host=self.max_concurrent
            )
            
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=self.timeout,
                headers={'User-Agent': self.user_agent}
            )
    
    async def close(self):
        """Close the HTTP session"""
        if self.session:
            await self.session.close()
            self.session = None
    
    async def request(self, 
                     method: str, 
                     url: str,
                     headers: Dict[str, str] = None,
                     data: Any = None,
                     params: Dict[str, str] = None,
                     cookies: Dict[str, str] = None,
                     follow_redirects: bool = True,
                     **kwargs) -> Dict[str, Any]:
        """Make an HTTP request"""
        
        async with self.semaphore:
            if not self.session:
                await self.start_session()
            
            start_time = time.time()
            
            try:
                # Prepare request
                request_kwargs = {
                    'headers': headers or {},
                    'params': params,
                    'cookies': cookies,
                    'allow_redirects': follow_redirects,
                    'ssl': self.ssl_context
                }
                
                if self.proxy:
                    request_kwargs['proxy'] = self.proxy
                
                # Handle different data types
                if data is not None:
                    if isinstance(data, dict):
                        if headers and 'content-type' in [h.lower() for h in headers]:
                            content_type = next(v for k, v in headers.items() if k.lower() == 'content-type')
                            if 'application/json' in content_type:
                                request_kwargs['json'] = data
                            else:
                                request_kwargs['data'] = data
                        else:
                            request_kwargs['data'] = data
                    else:
                        request_kwargs['data'] = data
                
                # Make request
                async with self.session.request(method, url, **request_kwargs) as response:
                    response_time = time.time() - start_time
                    
                    # Read response
                    try:
                        text = await response.text()
                    except UnicodeDecodeError:
                        text = await response.read()
                        text = str(text)
                    
                    # Prepare response data
                    response_data = {
                        'status_code': response.status,
                        'headers': dict(response.headers),
                        'text': text,
                        'url': str(response.url),
                        'response_time': response_time,
                        'method': method.upper(),
                        'request_headers': headers or {},
                        'request_data': data
                    }
                    
                    # Update statistics
                    self.stats['requests_made'] += 1
                    self.stats['total_time'] += response_time
                    
                    return response_data
                    
            except asyncio.TimeoutError:
                self.stats['timeouts'] += 1
                return {
                    'status_code': 0,
                    'headers': {},
                    'text': '',
                    'url': url,
                    'response_time': time.time() - start_time,
                    'method': method.upper(),
                    'error': 'Timeout',
                    'request_headers': headers or {},
                    'request_data': data
                }
                
            except Exception as e:
                self.stats['errors'] += 1
                return {
                    'status_code': 0,
                    'headers': {},
                    'text': '',
                    'url': url,
                    'response_time': time.time() - start_time,
                    'method': method.upper(),
                    'error': str(e),
                    'request_headers': headers or {},
                    'request_data': data
                }
    
    async def get(self, url: str, **kwargs) -> Dict[str, Any]:
        """Make a GET request"""
        return await self.request('GET', url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> Dict[str, Any]:
        """Make a POST request"""
        return await self.request('POST', url, **kwargs)
    
    async def put(self, url: str, **kwargs) -> Dict[str, Any]:
        """Make a PUT request"""
        return await self.request('PUT', url, **kwargs)
    
    async def delete(self, url: str, **kwargs) -> Dict[str, Any]:
        """Make a DELETE request"""
        return await self.request('DELETE', url, **kwargs)
    
    async def head(self, url: str, **kwargs) -> Dict[str, Any]:
        """Make a HEAD request"""
        return await self.request('HEAD', url, **kwargs)
    
    async def options(self, url: str, **kwargs) -> Dict[str, Any]:
        """Make an OPTIONS request"""
        return await self.request('OPTIONS', url, **kwargs)
    
    async def batch_requests(self, requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Make multiple requests concurrently"""
        tasks = []
        
        for req in requests:
            method = req.get('method', 'GET')
            url = req.get('url')
            kwargs = {k: v for k, v in req.items() if k not in ['method', 'url']}
            
            task = self.request(method, url, **kwargs)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Convert exceptions to error responses
        processed_results = []
        for result in results:
            if isinstance(result, Exception):
                processed_results.append({
                    'status_code': 0,
                    'headers': {},
                    'text': '',
                    'url': '',
                    'response_time': 0,
                    'method': '',
                    'error': str(result)
                })
            else:
                processed_results.append(result)
        
        return processed_results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get request statistics"""
        avg_time = self.stats['total_time'] / max(self.stats['requests_made'], 1)
        
        return {
            'total_requests': self.stats['requests_made'],
            'total_time': self.stats['total_time'],
            'average_response_time': avg_time,
            'errors': self.stats['errors'],
            'timeouts': self.stats['timeouts'],
            'success_rate': (self.stats['requests_made'] - self.stats['errors']) / max(self.stats['requests_made'], 1) * 100
        }
    
    def reset_stats(self):
        """Reset request statistics"""
        self.stats = {
            'requests_made': 0,
            'total_time': 0,
            'errors': 0,
            'timeouts': 0
        }
