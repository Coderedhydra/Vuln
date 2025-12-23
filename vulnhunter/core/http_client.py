"""
Advanced HTTP Client for VulnHunter
Provides easy-to-use request/response handling for LLM agents
"""

import asyncio
import time
from typing import Optional, Dict, List, Any, Union
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import json

import requests
import httpx
from loguru import logger


@dataclass
class HTTPResponse:
    """
    Structured HTTP Response - Easy for LLM to understand and process
    """
    url: str
    status_code: int
    headers: Dict[str, str]
    body: str
    elapsed_time: float
    redirects: List[str] = field(default_factory=list)
    cookies: Dict[str, str] = field(default_factory=dict)
    
    # Parsed data for LLM convenience
    content_type: str = ""
    is_json: bool = False
    json_data: Optional[Dict] = None
    is_html: bool = False
    title: str = ""
    forms_count: int = 0
    links_count: int = 0
    
    # Error tracking
    error: Optional[str] = None
    
    def to_llm_summary(self) -> str:
        """Generate a summary string for LLM consumption"""
        summary = f"""
=== HTTP Response Summary ===
URL: {self.url}
Status: {self.status_code}
Content-Type: {self.content_type}
Response Time: {self.elapsed_time:.2f}s
Body Length: {len(self.body)} chars

Key Headers:
{self._format_key_headers()}

{"JSON Response: Yes" if self.is_json else "HTML Page: " + self.title if self.is_html else "Other Content Type"}
{f"Forms Found: {self.forms_count}" if self.is_html else ""}
{f"Links Found: {self.links_count}" if self.is_html else ""}
{f"Error: {self.error}" if self.error else ""}
===========================
"""
        return summary.strip()
    
    def _format_key_headers(self) -> str:
        """Format important headers for display"""
        key_headers = ['server', 'x-powered-by', 'set-cookie', 'x-frame-options', 
                       'content-security-policy', 'x-xss-protection', 'access-control-allow-origin']
        lines = []
        for h in key_headers:
            if h in [k.lower() for k in self.headers.keys()]:
                for key, val in self.headers.items():
                    if key.lower() == h:
                        lines.append(f"  {key}: {val[:100]}...")
                        break
        return "\n".join(lines) if lines else "  (none of interest)"
    
    def get_body_preview(self, max_length: int = 2000) -> str:
        """Get a preview of the response body"""
        if len(self.body) <= max_length:
            return self.body
        return self.body[:max_length] + f"\n... [truncated, {len(self.body) - max_length} more chars]"


@dataclass  
class HTTPRequest:
    """
    Structured HTTP Request - Easy for LLM to construct
    """
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    data: Optional[Union[Dict, str]] = None
    json_data: Optional[Dict] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    timeout: int = 30
    follow_redirects: bool = True
    verify_ssl: bool = False
    
    def to_curl(self) -> str:
        """Convert request to curl command for debugging/reproduction"""
        parts = [f"curl -X {self.method}"]
        
        for k, v in self.headers.items():
            parts.append(f"-H '{k}: {v}'")
            
        for k, v in self.cookies.items():
            parts.append(f"-b '{k}={v}'")
            
        if self.data:
            if isinstance(self.data, dict):
                parts.append(f"-d '{urlencode(self.data)}'")
            else:
                parts.append(f"-d '{self.data}'")
                
        if self.json_data:
            parts.append(f"-d '{json.dumps(self.json_data)}'")
            parts.append("-H 'Content-Type: application/json'")
            
        if not self.verify_ssl:
            parts.append("-k")
            
        url = self.url
        if self.params:
            url += "?" + urlencode(self.params)
        parts.append(f"'{url}'")
        
        return " \\\n  ".join(parts)


class HTTPClient:
    """
    Synchronous HTTP Client with easy-to-use interface for LLM
    """
    
    def __init__(self, 
                 base_url: str = "",
                 default_headers: Optional[Dict[str, str]] = None,
                 cookies: Optional[Dict[str, str]] = None,
                 timeout: int = 30,
                 verify_ssl: bool = False,
                 rate_limit: float = 0.5):
        
        self.base_url = base_url.rstrip('/') if base_url else ""
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.rate_limit = rate_limit
        self._last_request_time = 0
        
        self.session = requests.Session()
        
        # Default headers
        self.session.headers.update({
            'User-Agent': 'VulnHunter/1.0 (Security Research)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        if default_headers:
            self.session.headers.update(default_headers)
            
        if cookies:
            self.session.cookies.update(cookies)
            
        self.session.verify = verify_ssl
        
        # Request/Response history for LLM analysis
        self.history: List[tuple] = []
        
    def _apply_rate_limit(self):
        """Apply rate limiting between requests"""
        elapsed = time.time() - self._last_request_time
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self._last_request_time = time.time()
    
    def _build_url(self, path: str) -> str:
        """Build full URL from path"""
        if path.startswith('http://') or path.startswith('https://'):
            return path
        return urljoin(self.base_url + '/', path.lstrip('/'))
    
    def _parse_response(self, response: requests.Response, elapsed: float) -> HTTPResponse:
        """Parse requests response into HTTPResponse"""
        from bs4 import BeautifulSoup
        
        content_type = response.headers.get('Content-Type', '')
        body = response.text
        
        http_response = HTTPResponse(
            url=str(response.url),
            status_code=response.status_code,
            headers=dict(response.headers),
            body=body,
            elapsed_time=elapsed,
            redirects=[str(r.url) for r in response.history],
            cookies={k: v for k, v in response.cookies.items()},
            content_type=content_type,
        )
        
        # Parse JSON if applicable
        if 'application/json' in content_type:
            http_response.is_json = True
            try:
                http_response.json_data = response.json()
            except:
                pass
                
        # Parse HTML if applicable
        if 'text/html' in content_type:
            http_response.is_html = True
            try:
                soup = BeautifulSoup(body, 'html.parser')
                title_tag = soup.find('title')
                http_response.title = title_tag.get_text(strip=True) if title_tag else ""
                http_response.forms_count = len(soup.find_all('form'))
                http_response.links_count = len(soup.find_all('a', href=True))
            except:
                pass
                
        return http_response
    
    def request(self, req: HTTPRequest) -> HTTPResponse:
        """
        Send an HTTP request - Main method for LLM to use
        
        Example for LLM:
            req = HTTPRequest(
                url="/api/users",
                method="POST",
                json_data={"username": "test", "password": "test123"}
            )
            response = client.request(req)
        """
        self._apply_rate_limit()
        
        url = self._build_url(req.url)
        
        try:
            start_time = time.time()
            
            response = self.session.request(
                method=req.method,
                url=url,
                params=req.params,
                data=req.data if not req.json_data else None,
                json=req.json_data,
                headers=req.headers,
                cookies=req.cookies,
                timeout=req.timeout,
                allow_redirects=req.follow_redirects,
                verify=req.verify_ssl if req.verify_ssl else self.verify_ssl,
            )
            
            elapsed = time.time() - start_time
            http_response = self._parse_response(response, elapsed)
            
        except requests.exceptions.Timeout:
            http_response = HTTPResponse(
                url=url, status_code=0, headers={}, body="",
                elapsed_time=req.timeout, error="Request timed out"
            )
        except requests.exceptions.ConnectionError as e:
            http_response = HTTPResponse(
                url=url, status_code=0, headers={}, body="",
                elapsed_time=0, error=f"Connection error: {str(e)}"
            )
        except Exception as e:
            http_response = HTTPResponse(
                url=url, status_code=0, headers={}, body="",
                elapsed_time=0, error=f"Request failed: {str(e)}"
            )
            
        # Store in history
        self.history.append((req, http_response))
        
        return http_response
    
    # Convenience methods for LLM
    def get(self, url: str, params: Optional[Dict] = None, headers: Optional[Dict] = None) -> HTTPResponse:
        """Simple GET request"""
        req = HTTPRequest(url=url, method="GET", params=params or {}, headers=headers or {})
        return self.request(req)
    
    def post(self, url: str, data: Optional[Dict] = None, json_data: Optional[Dict] = None, 
             headers: Optional[Dict] = None) -> HTTPResponse:
        """Simple POST request"""
        req = HTTPRequest(url=url, method="POST", data=data, json_data=json_data, headers=headers or {})
        return self.request(req)
    
    def put(self, url: str, data: Optional[Dict] = None, json_data: Optional[Dict] = None) -> HTTPResponse:
        """Simple PUT request"""
        req = HTTPRequest(url=url, method="PUT", data=data, json_data=json_data)
        return self.request(req)
    
    def delete(self, url: str, params: Optional[Dict] = None) -> HTTPResponse:
        """Simple DELETE request"""
        req = HTTPRequest(url=url, method="DELETE", params=params or {})
        return self.request(req)
    
    def post_form(self, url: str, form_data: Dict[str, str]) -> HTTPResponse:
        """POST form data (application/x-www-form-urlencoded)"""
        req = HTTPRequest(
            url=url, 
            method="POST", 
            data=form_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        return self.request(req)
    
    def post_json(self, url: str, json_data: Dict) -> HTTPResponse:
        """POST JSON data"""
        req = HTTPRequest(url=url, method="POST", json_data=json_data)
        return self.request(req)
    
    def send_raw(self, method: str, url: str, body: str, content_type: str = "text/plain") -> HTTPResponse:
        """Send raw body content - useful for custom payloads"""
        req = HTTPRequest(
            url=url,
            method=method,
            data=body,
            headers={'Content-Type': content_type}
        )
        return self.request(req)
    
    def set_cookie(self, name: str, value: str):
        """Add a cookie to the session"""
        self.session.cookies.set(name, value)
        
    def set_header(self, name: str, value: str):
        """Add a header to the session"""
        self.session.headers[name] = value
        
    def set_auth_token(self, token: str, header_name: str = "Authorization", prefix: str = "Bearer"):
        """Set authentication token"""
        self.session.headers[header_name] = f"{prefix} {token}" if prefix else token
        
    def set_basic_auth(self, username: str, password: str):
        """Set basic authentication"""
        from base64 import b64encode
        credentials = b64encode(f"{username}:{password}".encode()).decode()
        self.session.headers['Authorization'] = f"Basic {credentials}"
        
    def get_cookies(self) -> Dict[str, str]:
        """Get all session cookies"""
        return {k: v for k, v in self.session.cookies.items()}
    
    def get_history(self) -> List[tuple]:
        """Get request/response history"""
        return self.history
    
    def clear_history(self):
        """Clear request/response history"""
        self.history = []


class AsyncHTTPClient:
    """
    Asynchronous HTTP Client for high-performance scanning
    """
    
    def __init__(self,
                 base_url: str = "",
                 default_headers: Optional[Dict[str, str]] = None,
                 cookies: Optional[Dict[str, str]] = None,
                 timeout: int = 30,
                 verify_ssl: bool = False,
                 max_concurrent: int = 10):
        
        self.base_url = base_url.rstrip('/') if base_url else ""
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_concurrent = max_concurrent
        
        self._semaphore = asyncio.Semaphore(max_concurrent)
        
        self.default_headers = {
            'User-Agent': 'VulnHunter/1.0 (Security Research)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }
        
        if default_headers:
            self.default_headers.update(default_headers)
            
        self.cookies = cookies or {}
        self.history: List[tuple] = []
        
    def _build_url(self, path: str) -> str:
        """Build full URL from path"""
        if path.startswith('http://') or path.startswith('https://'):
            return path
        return urljoin(self.base_url + '/', path.lstrip('/'))
    
    async def request(self, req: HTTPRequest) -> HTTPResponse:
        """Send async HTTP request"""
        async with self._semaphore:
            url = self._build_url(req.url)
            
            try:
                async with httpx.AsyncClient(
                    verify=req.verify_ssl if req.verify_ssl else self.verify_ssl,
                    timeout=req.timeout,
                    follow_redirects=req.follow_redirects,
                ) as client:
                    
                    headers = {**self.default_headers, **req.headers}
                    cookies = {**self.cookies, **req.cookies}
                    
                    start_time = time.time()
                    
                    response = await client.request(
                        method=req.method,
                        url=url,
                        params=req.params,
                        data=req.data if not req.json_data else None,
                        json=req.json_data,
                        headers=headers,
                        cookies=cookies,
                    )
                    
                    elapsed = time.time() - start_time
                    
                    http_response = HTTPResponse(
                        url=str(response.url),
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        body=response.text,
                        elapsed_time=elapsed,
                        cookies={k: v for k, v in response.cookies.items()},
                        content_type=response.headers.get('content-type', ''),
                    )
                    
            except httpx.TimeoutException:
                http_response = HTTPResponse(
                    url=url, status_code=0, headers={}, body="",
                    elapsed_time=req.timeout, error="Request timed out"
                )
            except Exception as e:
                http_response = HTTPResponse(
                    url=url, status_code=0, headers={}, body="",
                    elapsed_time=0, error=f"Request failed: {str(e)}"
                )
                
            self.history.append((req, http_response))
            return http_response
    
    async def get(self, url: str, params: Optional[Dict] = None) -> HTTPResponse:
        """Simple async GET"""
        return await self.request(HTTPRequest(url=url, method="GET", params=params or {}))
    
    async def post(self, url: str, data: Optional[Dict] = None, json_data: Optional[Dict] = None) -> HTTPResponse:
        """Simple async POST"""
        return await self.request(HTTPRequest(url=url, method="POST", data=data, json_data=json_data))
    
    async def batch_get(self, urls: List[str]) -> List[HTTPResponse]:
        """Fetch multiple URLs concurrently"""
        tasks = [self.get(url) for url in urls]
        return await asyncio.gather(*tasks)
