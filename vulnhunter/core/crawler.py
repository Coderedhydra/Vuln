"""
Web Crawler - Discover URLs, forms, and endpoints
Easy for LLM to explore web applications
"""

import re
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from collections import defaultdict
from .http_client import HTTPClient, Response


@dataclass
class FormData:
    """Parsed form information"""
    action: str
    method: str
    inputs: List[Dict[str, str]]
    id: str = ""
    name: str = ""
    enctype: str = "application/x-www-form-urlencoded"
    
    def to_dict(self) -> Dict:
        return {
            "action": self.action,
            "method": self.method,
            "inputs": self.inputs,
            "id": self.id,
            "name": self.name,
            "enctype": self.enctype
        }

    def get_input_names(self) -> List[str]:
        """Get all input field names"""
        return [i.get("name", "") for i in self.inputs if i.get("name")]

    def get_required_fields(self) -> List[str]:
        """Get required field names"""
        return [i.get("name", "") for i in self.inputs 
                if i.get("required") or i.get("name")]


@dataclass
class PageInfo:
    """Complete page information"""
    url: str
    title: str = ""
    links: List[str] = field(default_factory=list)
    forms: List[FormData] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    parameters: Dict[str, List[str]] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    meta_tags: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "title": self.title,
            "links": self.links,
            "forms": [f.to_dict() for f in self.forms],
            "scripts": self.scripts,
            "comments": self.comments,
            "emails": self.emails,
            "api_endpoints": self.api_endpoints,
            "parameters": self.parameters,
            "technologies": self.technologies,
            "meta_tags": self.meta_tags
        }

    def summary(self) -> str:
        """Quick summary for LLM"""
        return f"""
Page: {self.url}
Title: {self.title}
Links found: {len(self.links)}
Forms found: {len(self.forms)}
Scripts: {len(self.scripts)}
API endpoints: {len(self.api_endpoints)}
Parameters: {list(self.parameters.keys())}
Technologies: {self.technologies}
"""


class WebCrawler:
    """
    Web crawler for discovering application structure
    
    Usage for LLM:
    - crawler.crawl(url) - Crawl single page
    - crawler.crawl_site(url, depth=2) - Crawl entire site
    - crawler.find_forms(url) - Find all forms on page
    - crawler.find_api_endpoints(url) - Find API endpoints
    - crawler.get_sitemap() - Get discovered site structure
    """
    
    def __init__(self, client: Optional[HTTPClient] = None, 
                 max_pages: int = 100, same_domain: bool = True):
        self.client = client or HTTPClient()
        self.max_pages = max_pages
        self.same_domain = same_domain
        self.visited: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.discovered_forms: List[FormData] = []
        self.discovered_params: Dict[str, Set[str]] = defaultdict(set)
        self.sitemap: Dict[str, PageInfo] = {}
        self.base_domain: str = ""
        
        # Patterns for discovery
        self.api_patterns = [
            r'/api/v?\d*/',
            r'/rest/',
            r'/graphql',
            r'/v\d+/',
            r'\.json',
            r'\.xml',
            r'/ws/',
            r'/socket',
        ]
        
        self.interesting_paths = [
            '/admin', '/login', '/register', '/signup', '/auth',
            '/api', '/graphql', '/upload', '/download', '/file',
            '/user', '/account', '/profile', '/settings', '/config',
            '/backup', '/debug', '/test', '/dev', '/staging',
            '/.git', '/.env', '/robots.txt', '/sitemap.xml',
            '/swagger', '/docs', '/api-docs', '/openapi',
            '/wp-admin', '/wp-login', '/administrator',
            '/phpmyadmin', '/adminer', '/console',
        ]

    def _normalize_url(self, url: str, base_url: str) -> str:
        """Normalize and resolve relative URLs"""
        if not url or url.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
            return ""
        return urljoin(base_url, url.split('#')[0])

    def _is_same_domain(self, url: str) -> bool:
        """Check if URL is on same domain"""
        if not self.base_domain:
            return True
        parsed = urlparse(url)
        return parsed.netloc == self.base_domain or parsed.netloc.endswith('.' + self.base_domain)

    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract all links from HTML"""
        links = []
        
        # Find href attributes
        href_pattern = r'href=["\']([^"\']+)["\']'
        for match in re.finditer(href_pattern, html, re.IGNORECASE):
            url = self._normalize_url(match.group(1), base_url)
            if url:
                links.append(url)
        
        # Find src attributes
        src_pattern = r'src=["\']([^"\']+)["\']'
        for match in re.finditer(src_pattern, html, re.IGNORECASE):
            url = self._normalize_url(match.group(1), base_url)
            if url:
                links.append(url)
        
        # Find action attributes
        action_pattern = r'action=["\']([^"\']+)["\']'
        for match in re.finditer(action_pattern, html, re.IGNORECASE):
            url = self._normalize_url(match.group(1), base_url)
            if url:
                links.append(url)
        
        return list(set(links))

    def _extract_forms(self, html: str, base_url: str) -> List[FormData]:
        """Extract all forms from HTML"""
        forms = []
        
        form_pattern = r'<form([^>]*)>(.*?)</form>'
        for match in re.finditer(form_pattern, html, re.IGNORECASE | re.DOTALL):
            attrs = match.group(1)
            content = match.group(2)
            
            # Extract form attributes
            action_match = re.search(r'action=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            id_match = re.search(r'id=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            name_match = re.search(r'name=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            enctype_match = re.search(r'enctype=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            
            action = action_match.group(1) if action_match else ""
            method = method_match.group(1).upper() if method_match else "GET"
            
            # Extract inputs
            inputs = []
            input_pattern = r'<input([^>]*)/?>'
            for input_match in re.finditer(input_pattern, content, re.IGNORECASE):
                input_attrs = input_match.group(1)
                input_data = {}
                
                for attr in ['type', 'name', 'value', 'id', 'placeholder', 'required', 'pattern']:
                    attr_match = re.search(rf'{attr}=["\']([^"\']*)["\']', input_attrs, re.IGNORECASE)
                    if attr_match:
                        input_data[attr] = attr_match.group(1)
                    elif attr == 'required' and 'required' in input_attrs.lower():
                        input_data[attr] = 'true'
                
                if input_data.get('name'):
                    inputs.append(input_data)
            
            # Extract textareas
            textarea_pattern = r'<textarea([^>]*)>([^<]*)</textarea>'
            for ta_match in re.finditer(textarea_pattern, content, re.IGNORECASE):
                ta_attrs = ta_match.group(1)
                name_m = re.search(r'name=["\']([^"\']*)["\']', ta_attrs)
                if name_m:
                    inputs.append({
                        'type': 'textarea',
                        'name': name_m.group(1),
                        'value': ta_match.group(2)
                    })
            
            # Extract select fields
            select_pattern = r'<select([^>]*)>.*?</select>'
            for sel_match in re.finditer(select_pattern, content, re.IGNORECASE | re.DOTALL):
                sel_attrs = sel_match.group(1)
                name_m = re.search(r'name=["\']([^"\']*)["\']', sel_attrs)
                if name_m:
                    inputs.append({
                        'type': 'select',
                        'name': name_m.group(1)
                    })
            
            form = FormData(
                action=self._normalize_url(action, base_url) or base_url,
                method=method,
                inputs=inputs,
                id=id_match.group(1) if id_match else "",
                name=name_match.group(1) if name_match else "",
                enctype=enctype_match.group(1) if enctype_match else "application/x-www-form-urlencoded"
            )
            forms.append(form)
        
        return forms

    def _extract_scripts(self, html: str, base_url: str) -> List[str]:
        """Extract script sources"""
        scripts = []
        pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>'
        for match in re.finditer(pattern, html, re.IGNORECASE):
            url = self._normalize_url(match.group(1), base_url)
            if url:
                scripts.append(url)
        return scripts

    def _extract_comments(self, html: str) -> List[str]:
        """Extract HTML comments (may contain sensitive info)"""
        pattern = r'<!--(.*?)-->'
        comments = re.findall(pattern, html, re.DOTALL)
        # Filter out empty or very short comments
        return [c.strip() for c in comments if len(c.strip()) > 10]

    def _extract_emails(self, html: str) -> List[str]:
        """Extract email addresses"""
        pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        return list(set(re.findall(pattern, html)))

    def _extract_api_endpoints(self, html: str, base_url: str) -> List[str]:
        """Extract potential API endpoints from JS and HTML"""
        endpoints = []
        
        # Look in script content
        script_content_pattern = r'<script[^>]*>(.*?)</script>'
        for match in re.finditer(script_content_pattern, html, re.IGNORECASE | re.DOTALL):
            content = match.group(1)
            
            # Look for API-like URLs
            url_pattern = r'["\'](/[a-zA-Z0-9_/\-\.]+(?:\?[^"\']*)?)["\']'
            for url_match in re.finditer(url_pattern, content):
                path = url_match.group(1)
                if any(re.search(p, path, re.IGNORECASE) for p in self.api_patterns):
                    endpoints.append(self._normalize_url(path, base_url))
            
            # Look for fetch/axios calls
            fetch_pattern = r'(?:fetch|axios\.(?:get|post|put|delete))\s*\(\s*["\']([^"\']+)["\']'
            for fetch_match in re.finditer(fetch_pattern, content):
                endpoints.append(self._normalize_url(fetch_match.group(1), base_url))
        
        return list(set(endpoints))

    def _extract_parameters(self, html: str, base_url: str) -> Dict[str, List[str]]:
        """Extract URL parameters used in the page"""
        params = defaultdict(list)
        
        # From URLs
        url_pattern = r'(?:href|src|action)=["\']([^"\']*\?[^"\']+)["\']'
        for match in re.finditer(url_pattern, html, re.IGNORECASE):
            url = match.group(1)
            parsed = urlparse(url)
            for param, values in parse_qs(parsed.query).items():
                params[param].extend(values)
        
        # From form inputs
        forms = self._extract_forms(html, base_url)
        for form in forms:
            for input_field in form.inputs:
                name = input_field.get('name')
                if name:
                    params[name].append(input_field.get('value', ''))
        
        return {k: list(set(v)) for k, v in params.items()}

    def _detect_technologies(self, html: str, headers: Dict[str, str]) -> List[str]:
        """Detect technologies used by the application"""
        techs = []
        
        # Check headers
        server = headers.get('server', '').lower()
        powered_by = headers.get('x-powered-by', '').lower()
        
        if 'nginx' in server:
            techs.append('nginx')
        if 'apache' in server:
            techs.append('apache')
        if 'php' in powered_by:
            techs.append('php')
        if 'asp.net' in powered_by:
            techs.append('asp.net')
        if 'express' in powered_by:
            techs.append('express/node.js')
        
        # Check HTML
        html_lower = html.lower()
        
        tech_patterns = {
            'react': [r'react', r'_react', r'__react'],
            'vue': [r'vue', r'v-model', r'v-if', r'v-for'],
            'angular': [r'ng-', r'angular', r'\[\(ngModel\)\]'],
            'jquery': [r'jquery', r'\$\('],
            'bootstrap': [r'bootstrap'],
            'wordpress': [r'wp-content', r'wp-includes', r'wordpress'],
            'drupal': [r'drupal', r'/sites/default/'],
            'joomla': [r'joomla', r'/administrator/'],
            'laravel': [r'laravel', r'csrf-token'],
            'django': [r'csrfmiddlewaretoken', r'django'],
            'rails': [r'csrf-token', r'rails', r'authenticity_token'],
            'spring': [r'spring', r'jsessionid'],
        }
        
        for tech, patterns in tech_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html_lower, re.IGNORECASE):
                    if tech not in techs:
                        techs.append(tech)
                    break
        
        return techs

    def _extract_meta_tags(self, html: str) -> Dict[str, str]:
        """Extract meta tags"""
        meta = {}
        pattern = r'<meta\s+([^>]+)>'
        for match in re.finditer(pattern, html, re.IGNORECASE):
            attrs = match.group(1)
            name_match = re.search(r'name=["\']([^"\']+)["\']', attrs)
            content_match = re.search(r'content=["\']([^"\']+)["\']', attrs)
            if name_match and content_match:
                meta[name_match.group(1)] = content_match.group(1)
        return meta

    def crawl(self, url: str) -> PageInfo:
        """
        Crawl a single page and extract all information
        
        Args:
            url: URL to crawl
            
        Returns:
            PageInfo with all extracted data
        """
        if not self.base_domain:
            self.base_domain = urlparse(url).netloc
        
        response = self.client.get(url)
        html = response.body
        
        # Extract title
        title_match = re.search(r'<title>([^<]+)</title>', html, re.IGNORECASE)
        title = title_match.group(1) if title_match else ""
        
        page_info = PageInfo(
            url=url,
            title=title,
            links=self._extract_links(html, url),
            forms=self._extract_forms(html, url),
            scripts=self._extract_scripts(html, url),
            comments=self._extract_comments(html),
            emails=self._extract_emails(html),
            api_endpoints=self._extract_api_endpoints(html, url),
            parameters=self._extract_parameters(html, url),
            technologies=self._detect_technologies(html, response.headers),
            meta_tags=self._extract_meta_tags(html)
        )
        
        # Store in sitemap
        self.sitemap[url] = page_info
        self.visited.add(url)
        
        # Store discovered items
        self.discovered_urls.update(page_info.links)
        self.discovered_forms.extend(page_info.forms)
        for param, values in page_info.parameters.items():
            self.discovered_params[param].update(values)
        
        return page_info

    def crawl_site(self, start_url: str, depth: int = 2) -> Dict[str, Any]:
        """
        Crawl entire site starting from URL
        
        Args:
            start_url: Starting URL
            depth: How deep to crawl
            
        Returns:
            Dict with all discovered information
        """
        self.base_domain = urlparse(start_url).netloc
        to_crawl = [(start_url, 0)]
        
        while to_crawl and len(self.visited) < self.max_pages:
            url, current_depth = to_crawl.pop(0)
            
            if url in self.visited or current_depth > depth:
                continue
            
            if self.same_domain and not self._is_same_domain(url):
                continue
            
            try:
                page_info = self.crawl(url)
                
                # Add discovered links to crawl queue
                if current_depth < depth:
                    for link in page_info.links:
                        if link not in self.visited and self._is_same_domain(link):
                            # Prioritize interesting paths
                            if any(p in link.lower() for p in self.interesting_paths):
                                to_crawl.insert(0, (link, current_depth + 1))
                            else:
                                to_crawl.append((link, current_depth + 1))
            except Exception as e:
                print(f"Error crawling {url}: {e}")
        
        return self.get_summary()

    def find_forms(self, url: str) -> List[Dict]:
        """Find all forms on a page"""
        page_info = self.crawl(url)
        return [f.to_dict() for f in page_info.forms]

    def find_api_endpoints(self, url: str) -> List[str]:
        """Find API endpoints from page"""
        page_info = self.crawl(url)
        return page_info.api_endpoints

    def find_parameters(self) -> Dict[str, List[str]]:
        """Get all discovered parameters"""
        return {k: list(v) for k, v in self.discovered_params.items()}

    def check_interesting_paths(self, base_url: str) -> List[Dict[str, Any]]:
        """Check for interesting/sensitive paths"""
        results = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for path in self.interesting_paths:
            url = base + path
            resp = self.client.get(url)
            if resp.status_code not in [404, 403]:
                results.append({
                    "path": path,
                    "url": url,
                    "status": resp.status_code,
                    "size": len(resp.body)
                })
        
        return results

    def get_sitemap(self) -> Dict[str, Dict]:
        """Get discovered sitemap"""
        return {url: info.to_dict() for url, info in self.sitemap.items()}

    def get_summary(self) -> Dict[str, Any]:
        """Get crawl summary"""
        return {
            "pages_crawled": len(self.visited),
            "total_urls_discovered": len(self.discovered_urls),
            "total_forms": len(self.discovered_forms),
            "parameters": self.find_parameters(),
            "forms": [f.to_dict() for f in self.discovered_forms],
            "technologies": list(set(
                tech 
                for info in self.sitemap.values() 
                for tech in info.technologies
            )),
            "emails": list(set(
                email 
                for info in self.sitemap.values() 
                for email in info.emails
            )),
            "api_endpoints": list(set(
                ep 
                for info in self.sitemap.values() 
                for ep in info.api_endpoints
            ))
        }

    def reset(self):
        """Reset crawler state"""
        self.visited.clear()
        self.discovered_urls.clear()
        self.discovered_forms.clear()
        self.discovered_params.clear()
        self.sitemap.clear()
        self.base_domain = ""
