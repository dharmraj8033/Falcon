"""
Technology Detection Module
Detects web technologies, frameworks, and versions
"""

import asyncio
import aiohttp
import re
import json
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from rich.console import Console

console = Console()

class TechDetectionModule:
    """Technology detection and fingerprinting module"""
    
    def __init__(self, config):
        self.config = config
        self.signatures = {}
        self.load_signatures()
    
    def load_signatures(self):
        """Load technology signatures"""
        self.signatures = {
            'cms': {
                'wordpress': {
                    'headers': ['x-pingback'],
                    'meta': ['generator.*wordpress'],
                    'html': ['wp-content/', 'wp-includes/', '/wp-admin/'],
                    'cookies': ['wordpress_', 'wp-'],
                    'scripts': ['wp-embed.min.js', 'wp-emoji-release.min.js']
                },
                'drupal': {
                    'headers': ['x-drupal-cache', 'x-generator.*drupal'],
                    'meta': ['generator.*drupal'],
                    'html': ['/sites/default/', '/modules/', '/themes/'],
                    'cookies': ['SESS', 'SSESS']
                },
                'joomla': {
                    'meta': ['generator.*joomla'],
                    'html': ['/components/', '/modules/', '/templates/'],
                    'cookies': ['joomla_']
                }
            },
            'web_servers': {
                'apache': {
                    'headers': ['server.*apache'],
                    'html': ['apache.*server']
                },
                'nginx': {
                    'headers': ['server.*nginx']
                },
                'iis': {
                    'headers': ['server.*iis', 'x-aspnet-version', 'x-powered-by.*asp.net']
                }
            },
            'programming_languages': {
                'php': {
                    'headers': ['x-powered-by.*php', 'set-cookie.*phpsessid'],
                    'html': ['\\.php'],
                    'cookies': ['phpsessid']
                },
                'asp.net': {
                    'headers': ['x-aspnet-version', 'x-powered-by.*asp.net'],
                    'html': ['__dopostback', 'aspnetform'],
                    'cookies': ['asp.net_sessionid']
                },
                'java': {
                    'headers': ['x-powered-by.*servlet'],
                    'html': ['\\.jsp', '\\.jsf'],
                    'cookies': ['jsessionid']
                },
                'nodejs': {
                    'headers': ['x-powered-by.*express'],
                    'html': ['node.js']
                },
                'python': {
                    'headers': ['server.*wsgi', 'x-powered-by.*django'],
                    'html': ['django', 'flask']
                }
            },
            'frameworks': {
                'react': {
                    'html': ['react', 'reactdom', '_reactinternalinstance'],
                    'scripts': ['react.min.js', 'react-dom.min.js']
                },
                'angular': {
                    'html': ['ng-', 'angular', 'ng-app'],
                    'scripts': ['angular.min.js']
                },
                'vue': {
                    'html': ['v-', 'vue'],
                    'scripts': ['vue.min.js']
                },
                'jquery': {
                    'scripts': ['jquery', 'jquery.min.js']
                },
                'bootstrap': {
                    'html': ['bootstrap'],
                    'css': ['bootstrap.min.css']
                }
            },
            'security': {
                'cloudflare': {
                    'headers': ['cf-ray', 'server.*cloudflare'],
                    'html': ['cloudflare']
                },
                'aws_waf': {
                    'headers': ['x-amzn-requestid', 'x-amz-cf-id']
                },
                'incapsula': {
                    'headers': ['x-iinfo'],
                    'cookies': ['incap_ses_', 'visid_incap_']
                }
            }
        }
    
    async def scan(self, url: str) -> Dict[str, Any]:
        """Scan URL for technology detection"""
        console.print(f"[cyan]🔧 Detecting technologies for: {url}[/cyan]")
        
        results = {
            'cms': {},
            'web_servers': {},
            'programming_languages': {},
            'frameworks': {},
            'security': {},
            'other': {}
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                # Get main page
                response_data = await self._fetch_page(session, url)
                
                if response_data:
                    # Analyze response
                    detected_techs = await self._analyze_response(response_data)
                    
                    # Organize results by category
                    for category, signatures in self.signatures.items():
                        for tech_name, detection_result in detected_techs.items():
                            if tech_name in signatures:
                                results[category][tech_name] = detection_result
                    
                    # Additional detection methods
                    await self._detect_from_robots_txt(session, url, results)
                    await self._detect_from_common_files(session, url, results)
                    await self._detect_javascript_libraries(response_data, results)
                    
                    console.print(f"[green]✅ Detected {sum(len(cat) for cat in results.values())} technologies[/green]")
                
        except Exception as e:
            console.print(f"[red]❌ Technology detection failed: {e}[/red]")
        
        return results
    
    async def _fetch_page(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict[str, Any]]:
        """Fetch page and return response data"""
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                headers = dict(response.headers)
                content = await response.text()
                cookies = {cookie.key: cookie.value for cookie in response.cookies.values()}
                
                return {
                    'url': url,
                    'status': response.status,
                    'headers': headers,
                    'content': content,
                    'cookies': cookies
                }
        except Exception as e:
            console.print(f"[yellow]⚠️  Failed to fetch {url}: {e}[/yellow]")
            return None
    
    async def _analyze_response(self, response_data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Analyze response for technology signatures"""
        detected = {}
        headers = response_data.get('headers', {})
        content = response_data.get('content', '')
        cookies = response_data.get('cookies', {})
        
        # Convert headers to lowercase for easier matching
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        content_lower = content.lower()
        
        # Check all signature categories
        for category, technologies in self.signatures.items():
            for tech_name, signatures in technologies.items():
                detection_result = await self._check_signatures(
                    tech_name, signatures, headers_lower, content_lower, cookies
                )
                
                if detection_result['detected']:
                    detected[tech_name] = detection_result
        
        return detected
    
    async def _check_signatures(self, tech_name: str, signatures: Dict[str, List[str]], 
                              headers: Dict[str, str], content: str, 
                              cookies: Dict[str, str]) -> Dict[str, Any]:
        """Check if technology signatures match"""
        
        result = {
            'detected': False,
            'confidence': 0.0,
            'version': None,
            'evidence': []
        }
        
        total_checks = 0
        matches = 0
        
        # Check headers
        if 'headers' in signatures:
            for header_pattern in signatures['headers']:
                total_checks += 1
                for header_name, header_value in headers.items():
                    if re.search(header_pattern, f"{header_name}: {header_value}", re.IGNORECASE):
                        matches += 1
                        result['evidence'].append(f"Header: {header_name}")
                        
                        # Try to extract version
                        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', header_value)
                        if version_match and not result['version']:
                            result['version'] = version_match.group(1)
                        break
        
        # Check HTML content
        if 'html' in signatures:
            for html_pattern in signatures['html']:
                total_checks += 1
                if re.search(html_pattern, content, re.IGNORECASE):
                    matches += 1
                    result['evidence'].append(f"HTML: {html_pattern}")
        
        # Check meta tags
        if 'meta' in signatures:
            soup = BeautifulSoup(content, 'html.parser')
            meta_tags = soup.find_all('meta')
            
            for meta_pattern in signatures['meta']:
                total_checks += 1
                for meta in meta_tags:
                    meta_content = str(meta)
                    if re.search(meta_pattern, meta_content, re.IGNORECASE):
                        matches += 1
                        result['evidence'].append(f"Meta: {meta_pattern}")
                        
                        # Try to extract version from meta
                        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', meta_content)
                        if version_match and not result['version']:
                            result['version'] = version_match.group(1)
                        break
        
        # Check cookies
        if 'cookies' in signatures:
            for cookie_pattern in signatures['cookies']:
                total_checks += 1
                for cookie_name in cookies.keys():
                    if re.search(cookie_pattern, cookie_name, re.IGNORECASE):
                        matches += 1
                        result['evidence'].append(f"Cookie: {cookie_name}")
                        break
        
        # Check scripts
        if 'scripts' in signatures:
            soup = BeautifulSoup(content, 'html.parser')
            scripts = soup.find_all('script', src=True)
            
            for script_pattern in signatures['scripts']:
                total_checks += 1
                for script in scripts:
                    src = script.get('src', '')
                    if re.search(script_pattern, src, re.IGNORECASE):
                        matches += 1
                        result['evidence'].append(f"Script: {src}")
                        
                        # Try to extract version from script path
                        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', src)
                        if version_match and not result['version']:
                            result['version'] = version_match.group(1)
                        break
        
        # Calculate confidence
        if total_checks > 0:
            result['confidence'] = matches / total_checks
            result['detected'] = result['confidence'] > 0.0
        
        return result
    
    async def _detect_from_robots_txt(self, session: aiohttp.ClientSession, 
                                    base_url: str, results: Dict[str, Any]):
        """Detect technologies from robots.txt"""
        try:
            robots_url = urljoin(base_url, '/robots.txt')
            async with session.get(robots_url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Look for CMS-specific paths
                    if '/wp-admin/' in content or '/wp-content/' in content:
                        if 'wordpress' not in results['cms']:
                            results['cms']['wordpress'] = {
                                'detected': True,
                                'confidence': 0.8,
                                'evidence': ['robots.txt'],
                                'version': None
                            }
                    
                    if '/administrator/' in content:
                        if 'joomla' not in results['cms']:
                            results['cms']['joomla'] = {
                                'detected': True,
                                'confidence': 0.7,
                                'evidence': ['robots.txt'],
                                'version': None
                            }
        except Exception:
            pass
    
    async def _detect_from_common_files(self, session: aiohttp.ClientSession, 
                                      base_url: str, results: Dict[str, Any]):
        """Detect technologies from common files"""
        
        common_files = {
            'wordpress': ['/wp-login.php', '/wp-admin/', '/wp-content/'],
            'drupal': ['/user/login', '/admin/', '/sites/default/'],
            'joomla': ['/administrator/', '/components/'],
            'apache': ['/.htaccess'],
            'nginx': ['/nginx-status']
        }
        
        for tech, paths in common_files.items():
            for path in paths:
                try:
                    test_url = urljoin(base_url, path)
                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        if response.status in [200, 401, 403]:  # File exists (even if protected)
                            # Determine category
                            category = 'other'
                            if tech in ['wordpress', 'drupal', 'joomla']:
                                category = 'cms'
                            elif tech in ['apache', 'nginx']:
                                category = 'web_servers'
                            
                            if tech not in results[category]:
                                results[category][tech] = {
                                    'detected': True,
                                    'confidence': 0.9,
                                    'evidence': [f'File exists: {path}'],
                                    'version': None
                                }
                            break
                except Exception:
                    continue
    
    async def _detect_javascript_libraries(self, response_data: Dict[str, Any], 
                                         results: Dict[str, Any]):
        """Detect JavaScript libraries and frameworks"""
        
        content = response_data.get('content', '')
        soup = BeautifulSoup(content, 'html.parser')
        
        # Check script tags
        scripts = soup.find_all('script')
        
        js_libraries = {
            'jquery': [r'jquery[.-](\d+\.\d+(?:\.\d+)?)', r'jquery.min.js'],
            'react': [r'react[.-](\d+\.\d+(?:\.\d+)?)', r'react.min.js'],
            'angular': [r'angular[.-](\d+\.\d+(?:\.\d+)?)', r'angular.min.js'],
            'vue': [r'vue[.-](\d+\.\d+(?:\.\d+)?)', r'vue.min.js'],
            'bootstrap': [r'bootstrap[.-](\d+\.\d+(?:\.\d+)?)', r'bootstrap.min.js']
        }
        
        for script in scripts:
            src = script.get('src', '')
            content_inline = script.get_text()
            
            for lib_name, patterns in js_libraries.items():
                for pattern in patterns:
                    # Check script src
                    if src:
                        match = re.search(pattern, src, re.IGNORECASE)
                        if match:
                            version = match.group(1) if match.groups() else None
                            
                            results['frameworks'][lib_name] = {
                                'detected': True,
                                'confidence': 0.9,
                                'evidence': [f'Script: {src}'],
                                'version': version
                            }
                    
                    # Check inline script content
                    if content_inline:
                        if re.search(pattern, content_inline, re.IGNORECASE):
                            if lib_name not in results['frameworks']:
                                results['frameworks'][lib_name] = {
                                    'detected': True,
                                    'confidence': 0.7,
                                    'evidence': ['Inline script'],
                                    'version': None
                                }
    
    async def get_cve_mappings(self, technologies: Dict[str, Any]) -> Dict[str, List[str]]:
        """Get CVE mappings for detected technologies"""
        
        cve_mappings = {}
        
        # CVE database mappings (simplified for demo)
        known_cves = {
            'wordpress': {
                '5.8': ['CVE-2021-39200', 'CVE-2021-39201'],
                '5.7': ['CVE-2021-29447', 'CVE-2021-29448'],
                '5.6': ['CVE-2021-29450']
            },
            'apache': {
                '2.4.49': ['CVE-2021-41773'],
                '2.4.50': ['CVE-2021-42013'],
                '2.4.48': ['CVE-2021-40438']
            },
            'php': {
                '7.4.21': ['CVE-2021-21704', 'CVE-2021-21705'],
                '8.0.8': ['CVE-2021-21703']
            }
        }
        
        for category, techs in technologies.items():
            for tech_name, tech_info in techs.items():
                if tech_name in known_cves and tech_info.get('version'):
                    version = tech_info['version']
                    if version in known_cves[tech_name]:
                        cve_mappings[tech_name] = known_cves[tech_name][version]
        
        return cve_mappings
    
    async def run(self, config: Dict[str, Any]):
        """Run technology detection module"""
        
        url = config.get('url')
        file_path = config.get('file')
        subdomains_file = config.get('subdomains_file')
        
        results = {}
        
        if url:
            results[url] = await self.scan(url)
        elif file_path:
            with open(file_path, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            for target_url in urls:
                results[target_url] = await self.scan(target_url)
        elif subdomains_file:
            with open(subdomains_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
            
            for subdomain in subdomains:
                target_url = f"https://{subdomain}"
                results[target_url] = await self.scan(target_url)
        
        # Check for CVEs if requested
        if config.get('cve_check'):
            for target_url, tech_results in results.items():
                cve_mappings = await self.get_cve_mappings(tech_results)
                if cve_mappings:
                    results[target_url]['cve_mappings'] = cve_mappings
        
        # Export results if requested
        if config.get('export'):
            await self._export_results(results, config['export'])
        
        return results
    
    async def _export_results(self, results: Dict[str, Any], export_format: str):
        """Export technology detection results"""
        
        if export_format == 'json':
            with open('tech_detection_results.json', 'w') as f:
                json.dump(results, f, indent=2)
            console.print("[green]✅ Results exported to tech_detection_results.json[/green]")
        
        elif export_format == 'csv':
            import csv
            
            with open('tech_detection_results.csv', 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['URL', 'Category', 'Technology', 'Version', 'Confidence', 'Evidence'])
                
                for url, categories in results.items():
                    for category, technologies in categories.items():
                        for tech_name, tech_info in technologies.items():
                            if tech_info.get('detected'):
                                writer.writerow([
                                    url,
                                    category,
                                    tech_name,
                                    tech_info.get('version', ''),
                                    tech_info.get('confidence', 0.0),
                                    '; '.join(tech_info.get('evidence', []))
                                ])
            
            console.print("[green]✅ Results exported to tech_detection_results.csv[/green]")
