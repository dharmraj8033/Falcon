"""
Technology Detection Module
"""

import re
import json
import asyncio
from typing import Dict, List, Any
from urllib.parse import urljoin, urlparse

from ..core.http_client import HTTPClient
from ..core.logger import setup_logger

class TechnologyDetector:
    """Detect web technologies using various techniques"""
    
    def __init__(self):
        self.logger = setup_logger('tech-detector')
        self.http_client = HTTPClient()
        self.fingerprints = self._load_fingerprints()
    
    def _load_fingerprints(self) -> Dict[str, Any]:
        """Load technology fingerprints"""
        return {
            'cms': {
                'WordPress': {
                    'headers': ['X-Pingback'],
                    'html': [r'wp-content/', r'wp-includes/', r'/wp-json/'],
                    'paths': ['/wp-admin/', '/wp-login.php', '/xmlrpc.php'],
                    'meta': [r'<meta name="generator" content="WordPress']
                },
                'Drupal': {
                    'headers': ['X-Drupal-Dynamic-Cache'],
                    'html': [r'Drupal.settings', r'/sites/default/files/', r'drupal.js'],
                    'paths': ['/user/login', '/admin', '/node'],
                    'cookies': ['SESS', 'SSESS']
                },
                'Joomla': {
                    'html': [r'/administrator/', r'joomla', r'/components/'],
                    'paths': ['/administrator/', '/components/'],
                    'meta': [r'<meta name="generator" content="Joomla!']
                },
                'Magento': {
                    'html': [r'Mage.Cookies', r'/skin/frontend/', r'Varien'],
                    'paths': ['/admin/', '/downloader/'],
                    'cookies': ['frontend']
                }
            },
            'web_servers': {
                'Apache': {
                    'headers': ['Server: Apache', 'X-Powered-By: Apache']
                },
                'Nginx': {
                    'headers': ['Server: nginx']
                },
                'IIS': {
                    'headers': ['Server: Microsoft-IIS']
                },
                'Cloudflare': {
                    'headers': ['Server: cloudflare', 'CF-Ray']
                }
            },
            'programming_languages': {
                'PHP': {
                    'headers': ['X-Powered-By: PHP'],
                    'html': [r'\.php\b'],
                    'cookies': ['PHPSESSID']
                },
                'ASP.NET': {
                    'headers': ['X-AspNet-Version', 'X-Powered-By: ASP.NET'],
                    'html': [r'__VIEWSTATE', r'__EVENTVALIDATION'],
                    'cookies': ['ASP.NET_SessionId']
                },
                'Java': {
                    'headers': ['X-Powered-By: JSP'],
                    'html': [r'\.jsp\b', r'\.do\b'],
                    'cookies': ['JSESSIONID']
                },
                'Python': {
                    'headers': ['Server: .*Python'],
                    'html': [r'Django', r'Flask']
                },
                'Node.js': {
                    'headers': ['X-Powered-By: Express'],
                    'html': [r'Node.js']
                }
            },
            'databases': {
                'MySQL': {
                    'html': [r'mysql_error', r'MySQL.*Error']
                },
                'PostgreSQL': {
                    'html': [r'PostgreSQL.*Error', r'psql:']
                },
                'MongoDB': {
                    'html': [r'MongoDB', r'mongo']
                },
                'SQLite': {
                    'html': [r'SQLite', r'sqlite']
                }
            },
            'javascript_frameworks': {
                'jQuery': {
                    'html': [r'jquery', r'jQuery']
                },
                'React': {
                    'html': [r'React', r'react', r'data-reactroot']
                },
                'Angular': {
                    'html': [r'ng-app', r'angular', r'Angular']
                },
                'Vue.js': {
                    'html': [r'Vue', r'vue', r'v-']
                },
                'Bootstrap': {
                    'html': [r'bootstrap', r'Bootstrap']
                }
            },
            'analytics': {
                'Google Analytics': {
                    'html': [r'google-analytics', r'gtag', r'ga\(']
                },
                'Adobe Analytics': {
                    'html': [r'omniture', r'Adobe Analytics']
                }
            },
            'security': {
                'Cloudflare': {
                    'headers': ['CF-Ray', 'Server: cloudflare']
                },
                'WAF': {
                    'headers': ['X-WAF-Event']
                }
            }
        }
    
    async def detect_technologies(self, target_url: str) -> Dict[str, List[Dict[str, Any]]]:
        """Main technology detection function"""
        self.logger.info(f"Detecting technologies for {target_url}")
        
        # Get the main page
        response = await self.http_client.get(target_url)
        
        if response['status_code'] == 0:
            self.logger.error(f"Failed to connect to {target_url}")
            return {}
        
        # Analyze response
        results = {
            'cms': [],
            'web_servers': [],
            'programming_languages': [],
            'databases': [],
            'javascript_frameworks': [],
            'analytics': [],
            'security': []
        }
        
        # Run detection methods
        for category, fingerprints in self.fingerprints.items():
            detected = await self._detect_category(response, fingerprints, category)
            results[category] = detected
        
        # Additional checks
        await self._detect_additional_info(target_url, results)
        
        # Remove empty categories
        results = {k: v for k, v in results.items() if v}
        
        self.logger.info(f"Detected {sum(len(v) for v in results.values())} technologies")
        return results
    
    async def _detect_category(self, response: Dict[str, Any], 
                             fingerprints: Dict[str, Dict], 
                             category: str) -> List[Dict[str, Any]]:
        """Detect technologies in a specific category"""
        detected = []
        
        for tech_name, patterns in fingerprints.items():
            confidence = 0
            evidence = []
            
            # Check headers
            if 'headers' in patterns:
                for header_pattern in patterns['headers']:
                    if self._check_headers(response['headers'], header_pattern):
                        confidence += 30
                        evidence.append(f"Header: {header_pattern}")
            
            # Check HTML content
            if 'html' in patterns:
                for html_pattern in patterns['html']:
                    if re.search(html_pattern, response['text'], re.IGNORECASE):
                        confidence += 25
                        evidence.append(f"HTML: {html_pattern}")
            
            # Check meta tags
            if 'meta' in patterns:
                for meta_pattern in patterns['meta']:
                    if re.search(meta_pattern, response['text'], re.IGNORECASE):
                        confidence += 40
                        evidence.append(f"Meta: {meta_pattern}")
            
            # Check cookies
            if 'cookies' in patterns:
                for cookie_pattern in patterns['cookies']:
                    if self._check_cookies(response['headers'], cookie_pattern):
                        confidence += 20
                        evidence.append(f"Cookie: {cookie_pattern}")
            
            # If we have sufficient confidence, add to results
            if confidence >= 20:
                detected.append({
                    'name': tech_name,
                    'category': category,
                    'confidence': min(confidence, 100),
                    'version': self._extract_version(response, tech_name),
                    'evidence': evidence
                })
        
        return detected
    
    def _check_headers(self, headers: Dict[str, str], pattern: str) -> bool:
        """Check if header pattern matches"""
        for header_name, header_value in headers.items():
            combined = f"{header_name}: {header_value}"
            if re.search(pattern, combined, re.IGNORECASE):
                return True
        return False
    
    def _check_cookies(self, headers: Dict[str, str], pattern: str) -> bool:
        """Check if cookie pattern matches"""
        cookie_header = headers.get('Set-Cookie', '') + headers.get('set-cookie', '')
        return pattern.lower() in cookie_header.lower()
    
    def _extract_version(self, response: Dict[str, Any], tech_name: str) -> str:
        """Extract version information for detected technology"""
        version_patterns = {
            'WordPress': [
                r'<meta name="generator" content="WordPress ([0-9.]+)"',
                r'wp-includes/js/[^/]+\?ver=([0-9.]+)'
            ],
            'jQuery': [
                r'jquery[/-]([0-9.]+)',
                r'jQuery v([0-9.]+)'
            ],
            'Apache': [
                r'Server: Apache[/\s]([0-9.]+)'
            ],
            'PHP': [
                r'X-Powered-By: PHP[/\s]([0-9.]+)'
            ],
            'nginx': [
                r'Server: nginx[/\s]([0-9.]+)'
            ]
        }
        
        patterns = version_patterns.get(tech_name, [])
        for pattern in patterns:
            match = re.search(pattern, response['text'], re.IGNORECASE)
            if match:
                return match.group(1)
            
            # Also check headers
            for header_value in response['headers'].values():
                match = re.search(pattern, header_value, re.IGNORECASE)
                if match:
                    return match.group(1)
        
        return 'Unknown'
    
    async def _detect_additional_info(self, target_url: str, results: Dict[str, List]):
        """Detect additional information through specific paths"""
        
        # Common paths to check
        paths_to_check = [
            '/robots.txt',
            '/sitemap.xml',
            '/.well-known/security.txt',
            '/admin/',
            '/wp-admin/',
            '/administrator/',
            '/phpmyadmin/',
            '/server-status',
            '/server-info'
        ]
        
        # Check paths concurrently
        tasks = []
        for path in paths_to_check:
            full_url = urljoin(target_url, path)
            tasks.append(self._check_path(full_url))
        
        path_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Analyze path results
        for i, result in enumerate(path_results):
            if isinstance(result, dict) and result.get('status_code') == 200:
                path = paths_to_check[i]
                self._analyze_path_response(path, result, results)
    
    async def _check_path(self, url: str) -> Dict[str, Any]:
        """Check a specific path"""
        return await self.http_client.get(url)
    
    def _analyze_path_response(self, path: str, response: Dict[str, Any], results: Dict[str, List]):
        """Analyze response from a specific path"""
        
        if path == '/robots.txt':
            # Extract interesting paths from robots.txt
            disallowed = re.findall(r'Disallow: (.+)', response['text'])
            if disallowed:
                self.logger.info(f"Found {len(disallowed)} disallowed paths in robots.txt")
        
        elif path == '/server-status':
            if 'Apache Server Status' in response['text']:
                results['web_servers'].append({
                    'name': 'Apache Status Page',
                    'category': 'web_servers',
                    'confidence': 90,
                    'version': 'Unknown',
                    'evidence': ['Server Status page accessible']
                })
        
        elif path == '/server-info':
            if 'Apache Server Information' in response['text']:
                results['web_servers'].append({
                    'name': 'Apache Info Page',
                    'category': 'web_servers',
                    'confidence': 90,
                    'version': 'Unknown',
                    'evidence': ['Server Info page accessible']
                })
        
        elif path == '/phpmyadmin/':
            if 'phpMyAdmin' in response['text']:
                results['databases'].append({
                    'name': 'phpMyAdmin',
                    'category': 'databases',
                    'confidence': 95,
                    'version': self._extract_phpmyadmin_version(response['text']),
                    'evidence': ['phpMyAdmin interface detected']
                })
    
    def _extract_phpmyadmin_version(self, html: str) -> str:
        """Extract phpMyAdmin version"""
        match = re.search(r'phpMyAdmin ([0-9.]+)', html)
        return match.group(1) if match else 'Unknown'
    
    async def run_whatweb(self, target_url: str) -> Dict[str, Any]:
        """Run external WhatWeb tool if available"""
        try:
            import subprocess
            
            # Check if whatweb is installed
            result = subprocess.run(['which', 'whatweb'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                # Run whatweb
                cmd = ['whatweb', '--log-brief', target_url]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    self.logger.info("WhatWeb scan completed")
                    return self._parse_whatweb_output(result.stdout)
        
        except Exception as e:
            self.logger.error(f"WhatWeb execution failed: {e}")
        
        return {}
    
    def _parse_whatweb_output(self, output: str) -> Dict[str, Any]:
        """Parse WhatWeb output"""
        # Simple parsing of WhatWeb output
        # In production, you'd want more sophisticated parsing
        
        technologies = {}
        for line in output.split('\n'):
            if '[' in line and ']' in line:
                # Extract technology names and versions
                matches = re.findall(r'\[([^\]]+)\]', line)
                for match in matches:
                    if ',' in match:
                        tech_info = match.split(',')
                        tech_name = tech_info[0].strip()
                        tech_version = tech_info[1].strip() if len(tech_info) > 1 else 'Unknown'
                        technologies[tech_name] = tech_version
        
        return technologies
