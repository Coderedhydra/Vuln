"""
HTTP Client - Easy request/response handling for LLM
Designed to be simple for AI models to use
"""

import requests
import httpx
import json
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from datetime import datetime
import asyncio


@dataclass
class Response:
    """Simple response object that LLM can easily understand"""
    url: str
    status_code: int
    headers: Dict[str, str]
    body: str
    cookies: Dict[str, str]
    elapsed_ms: float
    request_method: str
    request_headers: Dict[str, str]
    request_body: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "headers": dict(self.headers),
            "body": self.body[:5000] if len(self.body) > 5000 else self.body,
            "body_length": len(self.body),
            "cookies": self.cookies,
            "elapsed_ms": self.elapsed_ms,
            "request_method": self.request_method,
            "request_headers": self.request_headers,
            "request_body": self.request_body
        }
    
    def summary(self) -> str:
        """Quick summary for LLM"""
        return f"""
URL: {self.url}
Status: {self.status_code}
Response Size: {len(self.body)} bytes
Time: {self.elapsed_ms:.2f}ms
Content-Type: {self.headers.get('content-type', 'unknown')}
Cookies Set: {len(self.cookies)}
"""

    def find_in_body(self, pattern: str) -> List[str]:
        """Find regex pattern in body - useful for LLM"""
        return re.findall(pattern, self.body, re.IGNORECASE)
    
    def has_text(self, text: str) -> bool:
        """Check if text exists in body"""
        return text.lower() in self.body.lower()


class HTTPClient:
    """
    Easy HTTP client for LLM to send requests and analyze responses
    
    Usage for LLM:
    - client.get(url) - Simple GET request
    - client.post(url, data={...}) - POST with form data
    - client.post_json(url, json={...}) - POST with JSON
    - client.send(method, url, ...) - Full control
    - client.inject_payload(url, param, payload) - Inject payload into parameter
    """
    
    def __init__(self, timeout: int = 30, follow_redirects: bool = True, 
                 verify_ssl: bool = True, proxy: Optional[str] = None):
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.session = requests.Session()
        self.history: List[Response] = []
        
        # Default headers to look like a real browser
        self.default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        self.session.headers.update(self.default_headers)
        
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        self.session.verify = verify_ssl

    def _make_response(self, resp: requests.Response, method: str, 
                       req_headers: Dict, req_body: Optional[str]) -> Response:
        """Convert requests.Response to our simple Response"""
        return Response(
            url=str(resp.url),
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body=resp.text,
            cookies={c.name: c.value for c in resp.cookies},
            elapsed_ms=resp.elapsed.total_seconds() * 1000,
            request_method=method,
            request_headers=req_headers,
            request_body=req_body
        )

    def get(self, url: str, params: Optional[Dict] = None, 
            headers: Optional[Dict] = None) -> Response:
        """
        Simple GET request
        
        Args:
            url: Target URL
            params: Query parameters as dict
            headers: Additional headers
        
        Returns:
            Response object with all details
        """
        req_headers = {**self.default_headers, **(headers or {})}
        try:
            resp = self.session.get(
                url, 
                params=params, 
                headers=headers,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects
            )
            response = self._make_response(resp, "GET", req_headers, None)
            self.history.append(response)
            return response
        except Exception as e:
            return Response(
                url=url,
                status_code=0,
                headers={},
                body=f"Error: {str(e)}",
                cookies={},
                elapsed_ms=0,
                request_method="GET",
                request_headers=req_headers
            )

    def post(self, url: str, data: Optional[Dict] = None, 
             headers: Optional[Dict] = None) -> Response:
        """
        POST request with form data
        
        Args:
            url: Target URL
            data: Form data as dict
            headers: Additional headers
        """
        req_headers = {**self.default_headers, **(headers or {})}
        req_body = urlencode(data) if data else None
        try:
            resp = self.session.post(
                url,
                data=data,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects
            )
            response = self._make_response(resp, "POST", req_headers, req_body)
            self.history.append(response)
            return response
        except Exception as e:
            return Response(
                url=url,
                status_code=0,
                headers={},
                body=f"Error: {str(e)}",
                cookies={},
                elapsed_ms=0,
                request_method="POST",
                request_headers=req_headers,
                request_body=req_body
            )

    def post_json(self, url: str, json_data: Dict, 
                  headers: Optional[Dict] = None) -> Response:
        """
        POST request with JSON body
        
        Args:
            url: Target URL
            json_data: JSON data as dict
            headers: Additional headers
        """
        req_headers = {**self.default_headers, **(headers or {})}
        req_headers["Content-Type"] = "application/json"
        req_body = json.dumps(json_data)
        try:
            resp = self.session.post(
                url,
                json=json_data,
                headers=req_headers,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects
            )
            response = self._make_response(resp, "POST", req_headers, req_body)
            self.history.append(response)
            return response
        except Exception as e:
            return Response(
                url=url,
                status_code=0,
                headers={},
                body=f"Error: {str(e)}",
                cookies={},
                elapsed_ms=0,
                request_method="POST",
                request_headers=req_headers,
                request_body=req_body
            )

    def send(self, method: str, url: str, 
             params: Optional[Dict] = None,
             data: Optional[Dict] = None,
             json_data: Optional[Dict] = None,
             headers: Optional[Dict] = None,
             cookies: Optional[Dict] = None,
             raw_body: Optional[str] = None) -> Response:
        """
        Full control request - LLM can specify everything
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)
            url: Target URL
            params: Query parameters
            data: Form data
            json_data: JSON body
            headers: Custom headers
            cookies: Custom cookies
            raw_body: Raw body string (overrides data/json_data)
        """
        method = method.upper()
        req_headers = {**self.default_headers, **(headers or {})}
        req_body = None
        
        if raw_body:
            req_body = raw_body
        elif json_data:
            req_body = json.dumps(json_data)
            req_headers["Content-Type"] = "application/json"
        elif data:
            req_body = urlencode(data)
        
        try:
            if cookies:
                for name, value in cookies.items():
                    self.session.cookies.set(name, value)
            
            if raw_body:
                resp = self.session.request(
                    method, url, params=params, data=raw_body,
                    headers=req_headers, timeout=self.timeout,
                    allow_redirects=self.follow_redirects
                )
            else:
                resp = self.session.request(
                    method, url, params=params, data=data, json=json_data,
                    headers=req_headers, timeout=self.timeout,
                    allow_redirects=self.follow_redirects
                )
            
            response = self._make_response(resp, method, req_headers, req_body)
            self.history.append(response)
            return response
        except Exception as e:
            return Response(
                url=url, status_code=0, headers={},
                body=f"Error: {str(e)}", cookies={}, elapsed_ms=0,
                request_method=method, request_headers=req_headers,
                request_body=req_body
            )

    def inject_payload(self, url: str, param: str, payload: str,
                       method: str = "GET", original_value: str = "") -> Response:
        """
        Inject payload into URL parameter - Easy for LLM to test payloads
        
        Args:
            url: Base URL
            param: Parameter name to inject into
            payload: The payload to inject
            method: HTTP method
            original_value: Original parameter value (payload will be appended)
        
        Returns:
            Response from the injected request
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Inject payload
        params[param] = [original_value + payload if original_value else payload]
        
        # Rebuild URL
        new_query = urlencode(params, doseq=True)
        new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        
        if method.upper() == "GET":
            return self.get(new_url)
        else:
            return self.post(new_url)

    def inject_header(self, url: str, header_name: str, payload: str,
                      method: str = "GET") -> Response:
        """Inject payload into a header"""
        headers = {header_name: payload}
        if method.upper() == "GET":
            return self.get(url, headers=headers)
        return self.post(url, headers=headers)

    def set_cookie(self, name: str, value: str, domain: str = None):
        """Set a cookie in the session"""
        self.session.cookies.set(name, value, domain=domain)

    def set_header(self, name: str, value: str):
        """Set a persistent header"""
        self.default_headers[name] = value
        self.session.headers[name] = value

    def set_auth(self, username: str, password: str):
        """Set HTTP Basic Auth"""
        self.session.auth = (username, password)

    def set_bearer_token(self, token: str):
        """Set Bearer token authentication"""
        self.set_header("Authorization", f"Bearer {token}")

    def get_history(self, last_n: int = 10) -> List[Dict]:
        """Get last N requests/responses - useful for LLM context"""
        return [r.to_dict() for r in self.history[-last_n:]]

    def clear_history(self):
        """Clear request history"""
        self.history = []

    def clear_cookies(self):
        """Clear all cookies"""
        self.session.cookies.clear()

    def get_cookies(self) -> Dict[str, str]:
        """Get all current cookies"""
        return {c.name: c.value for c in self.session.cookies}


class AsyncHTTPClient:
    """Async version for parallel requests"""
    
    def __init__(self, timeout: int = 30, max_concurrent: int = 10):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        
    async def get(self, url: str, headers: Optional[Dict] = None) -> Response:
        async with self.semaphore:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers=headers)
                return Response(
                    url=str(resp.url),
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    body=resp.text,
                    cookies=dict(resp.cookies),
                    elapsed_ms=resp.elapsed.total_seconds() * 1000,
                    request_method="GET",
                    request_headers=headers or {}
                )
    
    async def batch_get(self, urls: List[str]) -> List[Response]:
        """Send multiple GET requests in parallel"""
        tasks = [self.get(url) for url in urls]
        return await asyncio.gather(*tasks, return_exceptions=True)
