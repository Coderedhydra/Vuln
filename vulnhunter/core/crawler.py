"""
Web Crawler for VulnHunter
Discovers URLs, forms, API endpoints, and extracts page content
"""

import asyncio
import re
from typing import Optional, Dict, List, Set, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from collections import defaultdict
import json

from bs4 import BeautifulSoup
from loguru import logger

from .http_client import HTTPClient, AsyncHTTPClient, HTTPRequest, HTTPResponse


@dataclass
class FormData:
    """Extracted form information"""
    url: str
    action: str
    method: str
    inputs: List[Dict[str, str]]
    has_file_upload: bool = False
    has_csrf_token: bool = False
    csrf_field_name: str = ""
    enctype: str = ""
    id: str = ""
    name: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "action": self.action,
            "method": self.method,
            "inputs": self.inputs,
            "has_file_upload": self.has_file_upload,
            "has_csrf_token": self.has_csrf_token,
            "enctype": self.enctype,
        }
    
    def get_input_names(self) -> List[str]:
        """Get all input field names"""
        return [inp.get('name', '') for inp in self.inputs if inp.get('name')]
    
    def to_llm_summary(self) -> str:
        """Generate summary for LLM"""
        inputs_str = ", ".join([f"{i.get('name', 'unnamed')}({i.get('type', 'text')})" 
                                for i in self.inputs[:10]])
        return f"Form[{self.method}] -> {self.action} | Inputs: {inputs_str}"


@dataclass
class LinkData:
    """Extracted link information"""
    url: str
    text: str
    is_internal: bool
    is_resource: bool  # js, css, images, etc.
    link_type: str  # href, src, action, etc.
    
    
@dataclass
class APIEndpoint:
    """Discovered API endpoint"""
    url: str
    method: str
    parameters: List[str]
    discovered_from: str  # Where we found this endpoint
    response_type: str = ""


@dataclass
class CrawlResult:
    """Complete crawl results"""
    base_url: str
    pages_crawled: int
    
    # Discovered items
    urls: Set[str] = field(default_factory=set)
    forms: List[FormData] = field(default_factory=list)
    api_endpoints: List[APIEndpoint] = field(default_factory=list)
    links: List[LinkData] = field(default_factory=list)
    
    # Content
    javascript_files: List[str] = field(default_factory=list)
    css_files: List[str] = field(default_factory=list)
    
    # Parameters discovered
    query_parameters: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    
    # Errors
    errors: List[str] = field(default_factory=list)
    
    # Page content cache
    page_content: Dict[str, str] = field(default_factory=dict)
    
    def to_llm_summary(self) -> str:
        """Generate comprehensive summary for LLM"""
        form_summaries = "\n".join([f"  - {f.to_llm_summary()}" for f in self.forms[:20]])
        
        return f"""
=== Crawl Results Summary ===
Base URL: {self.base_url}
Pages Crawled: {self.pages_crawled}

URLs Discovered: {len(self.urls)}
Forms Found: {len(self.forms)}
API Endpoints: {len(self.api_endpoints)}
JavaScript Files: {len(self.javascript_files)}

Top Query Parameters Found:
{self._format_params()}

Forms Detail:
{form_summaries if form_summaries else "  (none found)"}

API Endpoints:
{self._format_endpoints()}
=============================
"""

    def _format_params(self) -> str:
        items = list(self.query_parameters.items())[:10]
        return "\n".join([f"  - {url}: {list(params)[:5]}" for url, params in items])
    
    def _format_endpoints(self) -> str:
        endpoints = [f"  - [{e.method}] {e.url}" for e in self.api_endpoints[:10]]
        return "\n".join(endpoints) if endpoints else "  (none found)"


class WebCrawler:
    """
    Intelligent web crawler for vulnerability discovery
    Easy interface for LLM to explore websites
    """
    
    def __init__(self, http_client: HTTPClient, 
                 max_depth: int = 5,
                 max_pages: int = 500,
                 respect_robots: bool = False):
        
        self.http_client = http_client
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.respect_robots = respect_robots
        
        self.visited: Set[str] = set()
        self.to_visit: List[Tuple[str, int]] = []  # (url, depth)
        self.results = CrawlResult(base_url="", pages_crawled=0)
        
        self.base_domain = ""
        
        # File extensions to skip
        self.skip_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp',
            '.mp4', '.mp3', '.wav', '.avi', '.mov',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx',
            '.zip', '.rar', '.tar', '.gz',
            '.woff', '.woff2', '.ttf', '.eot',
        }
        
        # API patterns to detect
        self.api_patterns = [
            r'/api/v?\d*/',
            r'/rest/',
            r'/graphql',
            r'/ws/',
            r'\.json$',
            r'/ajax/',
        ]
        
    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is in scope"""
        parsed = urlparse(url)
        return parsed.netloc == self.base_domain or parsed.netloc == ""
    
    def _should_skip(self, url: str) -> bool:
        """Check if URL should be skipped"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Skip by extension
        for ext in self.skip_extensions:
            if path.endswith(ext):
                return True
                
        # Skip common non-content paths
        skip_paths = ['/static/', '/assets/', '/cdn/', '/vendor/']
        for skip in skip_paths:
            if skip in path:
                return True
                
        return False
    
    def _normalize_url(self, url: str, base_url: str) -> str:
        """Normalize and absolutize URL"""
        # Remove fragments
        url = url.split('#')[0]
        
        # Make absolute
        if not url.startswith('http'):
            url = urljoin(base_url, url)
            
        # Normalize trailing slash
        parsed = urlparse(url)
        if not parsed.path:
            url = url + '/'
            
        return url
    
    def _extract_links(self, soup: BeautifulSoup, page_url: str) -> List[LinkData]:
        """Extract all links from page"""
        links = []
        
        # <a href>
        for a in soup.find_all('a', href=True):
            href = a['href']
            if href.startswith('javascript:') or href.startswith('mailto:') or href.startswith('tel:'):
                continue
                
            full_url = self._normalize_url(href, page_url)
            
            links.append(LinkData(
                url=full_url,
                text=a.get_text(strip=True)[:100],
                is_internal=self._is_in_scope(full_url),
                is_resource=False,
                link_type='href'
            ))
            
        # <script src>
        for script in soup.find_all('script', src=True):
            src = script['src']
            full_url = self._normalize_url(src, page_url)
            links.append(LinkData(
                url=full_url, text="", is_internal=self._is_in_scope(full_url),
                is_resource=True, link_type='script'
            ))
            
        # <link href> (CSS)
        for link in soup.find_all('link', href=True):
            href = link['href']
            full_url = self._normalize_url(href, page_url)
            links.append(LinkData(
                url=full_url, text="", is_internal=self._is_in_scope(full_url),
                is_resource=True, link_type='css'
            ))
            
        # <form action>
        for form in soup.find_all('form', action=True):
            action = form['action']
            if action:
                full_url = self._normalize_url(action, page_url)
                links.append(LinkData(
                    url=full_url, text="form", is_internal=self._is_in_scope(full_url),
                    is_resource=False, link_type='form'
                ))
                
        return links
    
    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> List[FormData]:
        """Extract all forms from page"""
        forms = []
        
        for form in soup.find_all('form'):
            action = form.get('action', '')
            if action:
                action = self._normalize_url(action, page_url)
            else:
                action = page_url
                
            method = form.get('method', 'GET').upper()
            enctype = form.get('enctype', '')
            
            inputs = []
            has_file = False
            has_csrf = False
            csrf_field = ""
            
            # Extract all input fields
            for inp in form.find_all(['input', 'textarea', 'select']):
                inp_data = {
                    'tag': inp.name,
                    'name': inp.get('name', ''),
                    'type': inp.get('type', 'text'),
                    'value': inp.get('value', ''),
                    'required': inp.has_attr('required'),
                    'placeholder': inp.get('placeholder', ''),
                }
                
                # Check for file upload
                if inp.get('type') == 'file':
                    has_file = True
                    
                # Check for CSRF token
                name_lower = inp.get('name', '').lower()
                if any(csrf in name_lower for csrf in ['csrf', '_token', 'authenticity']):
                    has_csrf = True
                    csrf_field = inp.get('name', '')
                    
                # For select, get options
                if inp.name == 'select':
                    options = [opt.get('value', opt.get_text()) for opt in inp.find_all('option')]
                    inp_data['options'] = options[:10]  # Limit options
                    
                inputs.append(inp_data)
                
            forms.append(FormData(
                url=page_url,
                action=action,
                method=method,
                inputs=inputs,
                has_file_upload=has_file,
                has_csrf_token=has_csrf,
                csrf_field_name=csrf_field,
                enctype=enctype,
                id=form.get('id', ''),
                name=form.get('name', ''),
            ))
            
        return forms
    
    def _extract_api_endpoints_from_js(self, js_content: str, source_url: str) -> List[APIEndpoint]:
        """Extract API endpoints from JavaScript code"""
        endpoints = []
        
        # Common API URL patterns in JS
        patterns = [
            # fetch/axios calls
            r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'axios\.[a-z]+\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'\.get\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'\.post\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'\.put\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'\.delete\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            # URL strings that look like APIs
            r'[\'"`](/api/[^\'"`]+)[\'"`]',
            r'[\'"`](/v\d+/[^\'"`]+)[\'"`]',
            r'url:\s*[\'"`]([^\'"`]+)[\'"`]',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if match.startswith('/') or match.startswith('http'):
                    # Determine method from pattern
                    method = "GET"
                    if '.post' in pattern:
                        method = "POST"
                    elif '.put' in pattern:
                        method = "PUT"
                    elif '.delete' in pattern:
                        method = "DELETE"
                        
                    endpoints.append(APIEndpoint(
                        url=match,
                        method=method,
                        parameters=[],
                        discovered_from=source_url,
                    ))
                    
        return endpoints
    
    def _extract_query_params(self, url: str):
        """Extract and store query parameters"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if params:
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            for param in params.keys():
                self.results.query_parameters[base_url].add(param)
    
    def crawl(self, start_url: str) -> CrawlResult:
        """
        Crawl a website starting from the given URL
        
        LLM Usage:
            results = crawler.crawl("https://target.com")
            print(results.to_llm_summary())
        """
        # Initialize
        parsed = urlparse(start_url)
        self.base_domain = parsed.netloc
        self.results = CrawlResult(base_url=start_url, pages_crawled=0)
        
        self.visited = set()
        self.to_visit = [(start_url, 0)]
        
        logger.info(f"Starting crawl of {start_url}")
        
        while self.to_visit and self.results.pages_crawled < self.max_pages:
            url, depth = self.to_visit.pop(0)
            
            if url in self.visited:
                continue
                
            if depth > self.max_depth:
                continue
                
            if self._should_skip(url):
                continue
                
            self.visited.add(url)
            
            # Fetch page
            response = self.http_client.get(url)
            
            if response.error:
                self.results.errors.append(f"{url}: {response.error}")
                continue
                
            self.results.pages_crawled += 1
            self.results.urls.add(url)
            
            # Extract query parameters
            self._extract_query_params(url)
            
            if response.is_html:
                try:
                    soup = BeautifulSoup(response.body, 'html.parser')
                    
                    # Store page content
                    self.results.page_content[url] = response.body
                    
                    # Extract links
                    links = self._extract_links(soup, url)
                    self.results.links.extend(links)
                    
                    # Queue new URLs
                    for link in links:
                        if (link.is_internal and 
                            not link.is_resource and 
                            link.url not in self.visited):
                            self.to_visit.append((link.url, depth + 1))
                            
                    # Extract forms
                    forms = self._extract_forms(soup, url)
                    self.results.forms.extend(forms)
                    
                    # Track JS files
                    for link in links:
                        if link.link_type == 'script' and link.url not in self.results.javascript_files:
                            self.results.javascript_files.append(link.url)
                            
                    # Track CSS files
                    for link in links:
                        if link.link_type == 'css' and link.url not in self.results.css_files:
                            self.results.css_files.append(link.url)
                            
                except Exception as e:
                    self.results.errors.append(f"Parse error on {url}: {str(e)}")
                    
            logger.debug(f"Crawled {url} (depth={depth})")
            
        logger.info(f"Crawl complete: {self.results.pages_crawled} pages, {len(self.results.forms)} forms")
        return self.results
    
    def crawl_javascript(self, js_urls: Optional[List[str]] = None) -> List[APIEndpoint]:
        """
        Crawl JavaScript files to discover API endpoints
        
        LLM Usage:
            endpoints = crawler.crawl_javascript()
            # or
            endpoints = crawler.crawl_javascript(["/js/app.js", "/js/api.js"])
        """
        urls = js_urls or self.results.javascript_files
        all_endpoints = []
        
        for js_url in urls:
            response = self.http_client.get(js_url)
            
            if response.error or not response.body:
                continue
                
            endpoints = self._extract_api_endpoints_from_js(response.body, js_url)
            all_endpoints.extend(endpoints)
            
        # Deduplicate
        seen = set()
        unique = []
        for ep in all_endpoints:
            key = f"{ep.method}:{ep.url}"
            if key not in seen:
                seen.add(key)
                unique.append(ep)
                
        self.results.api_endpoints.extend(unique)
        logger.info(f"Discovered {len(unique)} API endpoints from JavaScript")
        
        return unique
    
    def get_forms_by_action(self, action_pattern: str) -> List[FormData]:
        """
        Find forms matching an action pattern
        
        LLM Usage:
            login_forms = crawler.get_forms_by_action("login")
        """
        return [f for f in self.results.forms if action_pattern.lower() in f.action.lower()]
    
    def get_forms_with_field(self, field_name: str) -> List[FormData]:
        """
        Find forms containing a specific field
        
        LLM Usage:
            password_forms = crawler.get_forms_with_field("password")
        """
        return [f for f in self.results.forms if field_name.lower() in 
                [inp.get('name', '').lower() for inp in f.inputs]]
    
    def get_urls_with_params(self) -> List[str]:
        """Get all URLs that have query parameters"""
        return list(self.results.query_parameters.keys())
    
    def get_page_content(self, url: str) -> Optional[str]:
        """
        Get cached page content or fetch if not cached
        
        LLM Usage:
            html = crawler.get_page_content("https://target.com/page")
        """
        if url in self.results.page_content:
            return self.results.page_content[url]
            
        response = self.http_client.get(url)
        if not response.error:
            self.results.page_content[url] = response.body
            return response.body
            
        return None
    
    def find_urls_matching(self, pattern: str) -> List[str]:
        r"""
        Find URLs matching a regex pattern
        
        LLM Usage:
            admin_urls = crawler.find_urls_matching(r"/admin/")
            user_urls = crawler.find_urls_matching(r"/user/\d+")
        """
        regex = re.compile(pattern, re.IGNORECASE)
        return [url for url in self.results.urls if regex.search(url)]
    
    def get_sitemap(self) -> Dict[str, List[str]]:
        """
        Get organized sitemap
        
        Returns dict organized by path prefix
        """
        sitemap = defaultdict(list)
        
        for url in self.results.urls:
            parsed = urlparse(url)
            parts = parsed.path.strip('/').split('/')
            prefix = parts[0] if parts else 'root'
            sitemap[prefix].append(url)
            
        return dict(sitemap)
