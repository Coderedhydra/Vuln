"""
LLM Tools for VulnHunter
Simplified interface for LLM to perform all security testing operations
"""

from typing import Optional, Dict, List, Any, Callable
from dataclasses import dataclass, field
import json
from loguru import logger

from ..core.http_client import HTTPClient, HTTPRequest, HTTPResponse
from ..core.session_manager import SessionManager
from ..core.crawler import WebCrawler, CrawlResult, FormData
from ..core.source_analyzer import SourceCodeAnalyzer, SourceAnalysisResult


@dataclass
class ToolResult:
    """Standardized result from any tool"""
    success: bool
    tool_name: str
    data: Any
    summary: str
    error: Optional[str] = None
    
    def to_llm_output(self) -> str:
        """Format result for LLM consumption"""
        if not self.success:
            return f"[{self.tool_name}] ERROR: {self.error}"
        return f"[{self.tool_name}] {self.summary}\n\nData:\n{self._format_data()}"
    
    def _format_data(self) -> str:
        if isinstance(self.data, str):
            return self.data[:5000]
        if isinstance(self.data, dict):
            return json.dumps(self.data, indent=2, default=str)[:5000]
        if isinstance(self.data, list):
            return json.dumps(self.data[:50], indent=2, default=str)[:5000]
        return str(self.data)[:5000]


class LLMToolkit:
    """
    Unified toolkit for LLM to perform security testing
    All methods return ToolResult for consistent handling
    
    Usage Example:
        toolkit = LLMToolkit("https://target.com")
        
        # Fetch a page
        result = toolkit.fetch("https://target.com/login")
        
        # Submit a form
        result = toolkit.submit_form("/login", {"username": "test", "password": "test123"})
        
        # Test for SQLi
        result = toolkit.test_sqli("/search", {"q": "test"})
    """
    
    def __init__(self, base_url: str, config: Optional[Dict] = None):
        self.base_url = base_url.rstrip('/')
        self.config = config or {}
        
        # Initialize components
        self.http = HTTPClient(
            base_url=base_url,
            rate_limit=self.config.get('rate_limit', 0.5)
        )
        self.session_mgr = SessionManager(self.http)
        self.crawler = WebCrawler(self.http)
        self.analyzer = SourceCodeAnalyzer()
        
        # State
        self.crawl_results: Optional[CrawlResult] = None
        self.current_page: Optional[HTTPResponse] = None
        self.findings: List[Dict] = []
        
        logger.info(f"LLMToolkit initialized for {base_url}")
        
    # =================
    # HTTP Operations
    # =================
    
    def fetch(self, url: str, params: Optional[Dict] = None) -> ToolResult:
        """
        Fetch a URL and return the response
        
        LLM Usage:
            result = toolkit.fetch("/api/users")
            result = toolkit.fetch("/search", {"q": "test"})
        """
        try:
            response = self.http.get(url, params=params)
            self.current_page = response
            
            return ToolResult(
                success=response.error is None,
                tool_name="fetch",
                data={
                    "url": response.url,
                    "status": response.status_code,
                    "content_type": response.content_type,
                    "body_preview": response.get_body_preview(2000),
                    "headers": dict(response.headers),
                },
                summary=f"Fetched {response.url} - Status: {response.status_code}",
                error=response.error,
            )
        except Exception as e:
            return ToolResult(False, "fetch", None, "", str(e))
    
    def post(self, url: str, data: Optional[Dict] = None, 
             json_data: Optional[Dict] = None) -> ToolResult:
        """
        Send POST request
        
        LLM Usage:
            result = toolkit.post("/api/login", json_data={"email": "test@test.com", "password": "test"})
        """
        try:
            if json_data:
                response = self.http.post_json(url, json_data)
            else:
                response = self.http.post_form(url, data or {})
            self.current_page = response
            
            return ToolResult(
                success=response.error is None,
                tool_name="post",
                data={
                    "url": response.url,
                    "status": response.status_code,
                    "body_preview": response.get_body_preview(2000),
                    "json_data": response.json_data if response.is_json else None,
                },
                summary=f"POST {response.url} - Status: {response.status_code}",
                error=response.error,
            )
        except Exception as e:
            return ToolResult(False, "post", None, "", str(e))
    
    def request(self, method: str, url: str, data: Optional[Dict] = None,
                headers: Optional[Dict] = None, params: Optional[Dict] = None) -> ToolResult:
        """
        Send custom HTTP request
        
        LLM Usage:
            result = toolkit.request("PUT", "/api/user/1", json_data={"role": "admin"})
            result = toolkit.request("DELETE", "/api/user/1")
        """
        try:
            req = HTTPRequest(
                url=url,
                method=method.upper(),
                data=data,
                params=params or {},
                headers=headers or {},
            )
            response = self.http.request(req)
            self.current_page = response
            
            return ToolResult(
                success=response.error is None,
                tool_name="request",
                data={
                    "url": response.url,
                    "status": response.status_code,
                    "body_preview": response.get_body_preview(2000),
                },
                summary=f"{method} {response.url} - Status: {response.status_code}",
                error=response.error,
            )
        except Exception as e:
            return ToolResult(False, "request", None, "", str(e))
    
    def send_payload(self, url: str, method: str, payload: str, 
                    param_name: str, content_type: str = "form") -> ToolResult:
        """
        Send a payload to test for vulnerabilities
        
        LLM Usage:
            result = toolkit.send_payload("/search", "GET", "' OR 1=1--", "q")
            result = toolkit.send_payload("/comment", "POST", "<script>alert(1)</script>", "text")
        """
        try:
            if method.upper() == "GET":
                response = self.http.get(url, params={param_name: payload})
            elif content_type == "json":
                response = self.http.post_json(url, {param_name: payload})
            else:
                response = self.http.post_form(url, {param_name: payload})
            
            # Check if payload appears in response (for reflection testing)
            payload_reflected = payload in response.body
            
            return ToolResult(
                success=True,
                tool_name="send_payload",
                data={
                    "url": response.url,
                    "status": response.status_code,
                    "payload_reflected": payload_reflected,
                    "response_length": len(response.body),
                    "body_preview": response.get_body_preview(1000),
                },
                summary=f"Payload sent to {url} - Reflected: {payload_reflected}, Status: {response.status_code}",
            )
        except Exception as e:
            return ToolResult(False, "send_payload", None, "", str(e))
    
    # =================
    # Form Operations
    # =================
    
    def get_forms(self, url: Optional[str] = None) -> ToolResult:
        """
        Get all forms from a page or from crawl results
        
        LLM Usage:
            result = toolkit.get_forms("/login")  # Get forms from specific page
            result = toolkit.get_forms()  # Get all forms from crawl
        """
        try:
            if url:
                response = self.http.get(url)
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.body, 'html.parser')
                
                forms = []
                for form in soup.find_all('form'):
                    inputs = []
                    for inp in form.find_all(['input', 'textarea', 'select']):
                        inputs.append({
                            'name': inp.get('name', ''),
                            'type': inp.get('type', 'text'),
                            'value': inp.get('value', ''),
                        })
                    
                    forms.append({
                        'action': form.get('action', url),
                        'method': form.get('method', 'GET').upper(),
                        'inputs': inputs,
                    })
                    
                return ToolResult(
                    success=True,
                    tool_name="get_forms",
                    data=forms,
                    summary=f"Found {len(forms)} forms on {url}",
                )
            else:
                if not self.crawl_results:
                    return ToolResult(False, "get_forms", None, "", "No crawl results. Run crawl first.")
                
                forms_data = [f.to_dict() for f in self.crawl_results.forms]
                return ToolResult(
                    success=True,
                    tool_name="get_forms",
                    data=forms_data,
                    summary=f"Found {len(forms_data)} forms in crawl results",
                )
        except Exception as e:
            return ToolResult(False, "get_forms", None, "", str(e))
    
    def submit_form(self, action: str, data: Dict[str, str], 
                   method: str = "POST") -> ToolResult:
        """
        Submit a form with given data
        
        LLM Usage:
            result = toolkit.submit_form("/login", {
                "username": "test",
                "password": "test123"
            })
        """
        try:
            if method.upper() == "GET":
                response = self.http.get(action, params=data)
            else:
                response = self.http.post_form(action, data)
            
            return ToolResult(
                success=response.error is None,
                tool_name="submit_form",
                data={
                    "url": response.url,
                    "status": response.status_code,
                    "redirected": len(response.redirects) > 0,
                    "redirects": response.redirects,
                    "body_preview": response.get_body_preview(1500),
                },
                summary=f"Form submitted to {action} - Status: {response.status_code}",
                error=response.error,
            )
        except Exception as e:
            return ToolResult(False, "submit_form", None, "", str(e))
    
    # =================
    # Crawling Operations
    # =================
    
    def crawl(self, max_pages: int = 100) -> ToolResult:
        """
        Crawl the target website
        
        LLM Usage:
            result = toolkit.crawl()
            result = toolkit.crawl(max_pages=50)
        """
        try:
            self.crawler.max_pages = max_pages
            self.crawl_results = self.crawler.crawl(self.base_url)
            
            return ToolResult(
                success=True,
                tool_name="crawl",
                data={
                    "pages_crawled": self.crawl_results.pages_crawled,
                    "urls_found": len(self.crawl_results.urls),
                    "forms_found": len(self.crawl_results.forms),
                    "js_files": len(self.crawl_results.javascript_files),
                    "sample_urls": list(self.crawl_results.urls)[:20],
                },
                summary=self.crawl_results.to_llm_summary(),
            )
        except Exception as e:
            return ToolResult(False, "crawl", None, "", str(e))
    
    def get_urls(self, pattern: Optional[str] = None) -> ToolResult:
        r"""
        Get discovered URLs, optionally filtered by pattern
        
        LLM Usage:
            result = toolkit.get_urls()  # All URLs
            result = toolkit.get_urls("/api/")  # Only API URLs
            result = toolkit.get_urls(r"/user/\d+")  # URLs with user IDs
        """
        try:
            if not self.crawl_results:
                return ToolResult(False, "get_urls", None, "", "No crawl results. Run crawl first.")
            
            if pattern:
                urls = self.crawler.find_urls_matching(pattern)
            else:
                urls = list(self.crawl_results.urls)
                
            return ToolResult(
                success=True,
                tool_name="get_urls",
                data=urls,
                summary=f"Found {len(urls)} URLs" + (f" matching '{pattern}'" if pattern else ""),
            )
        except Exception as e:
            return ToolResult(False, "get_urls", None, "", str(e))
    
    def get_endpoints(self) -> ToolResult:
        """
        Get discovered API endpoints from JavaScript analysis
        
        LLM Usage:
            result = toolkit.get_endpoints()
        """
        try:
            if not self.crawl_results:
                return ToolResult(False, "get_endpoints", None, "", "No crawl results. Run crawl first.")
            
            # Crawl JavaScript files for endpoints
            endpoints = self.crawler.crawl_javascript()
            
            endpoint_data = [{"url": e.url, "method": e.method, "source": e.discovered_from} 
                           for e in endpoints]
            
            return ToolResult(
                success=True,
                tool_name="get_endpoints",
                data=endpoint_data,
                summary=f"Discovered {len(endpoints)} API endpoints from JavaScript",
            )
        except Exception as e:
            return ToolResult(False, "get_endpoints", None, "", str(e))
    
    # =================
    # Source Analysis
    # =================
    
    def analyze_page(self, url: Optional[str] = None) -> ToolResult:
        """
        Analyze page source code for vulnerabilities
        
        LLM Usage:
            result = toolkit.analyze_page()  # Analyze current page
            result = toolkit.analyze_page("/admin")  # Analyze specific page
        """
        try:
            if url:
                response = self.http.get(url)
            elif self.current_page:
                response = self.current_page
            else:
                return ToolResult(False, "analyze_page", None, "", "No page to analyze. Fetch a page first.")
            
            analysis = self.analyzer.full_analysis(response.body, response.headers, response.url)
            
            # Store findings
            for finding in analysis.findings:
                self.findings.append(finding.to_dict())
            
            return ToolResult(
                success=True,
                tool_name="analyze_page",
                data={
                    "url": response.url,
                    "findings": [f.to_dict() for f in analysis.findings],
                    "secrets": analysis.secrets,
                    "api_endpoints": analysis.api_endpoints,
                    "frameworks": analysis.frameworks,
                    "hidden_fields": analysis.hidden_fields,
                },
                summary=analysis.to_llm_summary(),
            )
        except Exception as e:
            return ToolResult(False, "analyze_page", None, "", str(e))
    
    def read_source(self, url: str, max_length: int = 10000) -> ToolResult:
        """
        Read and return the source code of a page
        
        LLM Usage:
            result = toolkit.read_source("/login")
        """
        try:
            response = self.http.get(url)
            
            source = response.body
            if len(source) > max_length:
                source = source[:max_length] + f"\n\n... [truncated, {len(response.body) - max_length} more chars]"
            
            return ToolResult(
                success=True,
                tool_name="read_source",
                data={
                    "url": response.url,
                    "content_type": response.content_type,
                    "source": source,
                },
                summary=f"Read source from {response.url} ({len(response.body)} chars)",
            )
        except Exception as e:
            return ToolResult(False, "read_source", None, "", str(e))
    
    # =================
    # Authentication
    # =================
    
    def login(self, url: str, credentials: Dict[str, str], 
              use_json: bool = False) -> ToolResult:
        """
        Perform login with given credentials
        
        LLM Usage:
            result = toolkit.login("/login", {"username": "test", "password": "test123"})
            result = toolkit.login("/api/auth", {"email": "test@test.com", "password": "test"}, use_json=True)
        """
        try:
            # Set credentials
            username = credentials.get('username') or credentials.get('email', '')
            password = credentials.get('password', '')
            self.session_mgr.set_credentials(username=username, password=password)
            
            # Perform login
            if use_json:
                response = self.session_mgr.login_json(
                    url,
                    username_field=list(credentials.keys())[0] if credentials else 'username',
                    password_field='password'
                )
            else:
                # Use form fields as provided
                response = self.http.post_form(url, credentials)
                # Create session from response
                self.session_mgr._create_session_from_response(response)
                if response.is_json and response.json_data:
                    self.session_mgr._extract_tokens_from_json(response.json_data)
            
            is_success = response.status_code in [200, 302, 303]
            
            return ToolResult(
                success=is_success,
                tool_name="login",
                data={
                    "status": response.status_code,
                    "authenticated": self.session_mgr.is_authenticated(),
                    "session_info": self.session_mgr.get_session_info(),
                    "response_preview": response.get_body_preview(500),
                },
                summary=f"Login attempt - {'Success' if is_success else 'Failed'} (Status: {response.status_code})",
            )
        except Exception as e:
            return ToolResult(False, "login", None, "", str(e))
    
    def register(self, url: str, account_data: Dict[str, str],
                 use_json: bool = True) -> ToolResult:
        """
        Register a new account
        
        LLM Usage:
            result = toolkit.register("/api/register", {
                "username": "testuser",
                "email": "test@test.com", 
                "password": "Test123!",
                "confirm_password": "Test123!"
            })
        """
        try:
            response = self.session_mgr.register_account(url, account_data, use_json)
            
            is_success = response.status_code in [200, 201, 302]
            
            return ToolResult(
                success=is_success,
                tool_name="register",
                data={
                    "status": response.status_code,
                    "response": response.json_data if response.is_json else response.get_body_preview(500),
                },
                summary=f"Registration - {'Success' if is_success else 'Failed'} (Status: {response.status_code})",
            )
        except Exception as e:
            return ToolResult(False, "register", None, "", str(e))
    
    def set_auth_token(self, token: str, header: str = "Authorization",
                       prefix: str = "Bearer") -> ToolResult:
        """
        Set authentication token for subsequent requests
        
        LLM Usage:
            result = toolkit.set_auth_token("eyJhbGci...")
            result = toolkit.set_auth_token("api_key_123", header="X-API-Key", prefix="")
        """
        try:
            self.session_mgr.set_token_auth(token, header, prefix)
            
            return ToolResult(
                success=True,
                tool_name="set_auth_token",
                data={"header": header, "token_set": True},
                summary=f"Auth token set in {header} header",
            )
        except Exception as e:
            return ToolResult(False, "set_auth_token", None, "", str(e))
    
    def get_csrf_token(self, url: str) -> ToolResult:
        """
        Extract CSRF token from a page
        
        LLM Usage:
            result = toolkit.get_csrf_token("/login")
        """
        try:
            token = self.session_mgr.get_csrf_token(url)
            
            return ToolResult(
                success=token is not None,
                tool_name="get_csrf_token",
                data={"token": token},
                summary=f"CSRF token {'found' if token else 'not found'}",
            )
        except Exception as e:
            return ToolResult(False, "get_csrf_token", None, "", str(e))
    
    # =================
    # Cookie/Header Management  
    # =================
    
    def set_cookie(self, name: str, value: str) -> ToolResult:
        """Set a cookie for subsequent requests"""
        try:
            self.http.set_cookie(name, value)
            return ToolResult(
                success=True,
                tool_name="set_cookie",
                data={"name": name, "value": value},
                summary=f"Cookie '{name}' set",
            )
        except Exception as e:
            return ToolResult(False, "set_cookie", None, "", str(e))
    
    def set_header(self, name: str, value: str) -> ToolResult:
        """Set a header for subsequent requests"""
        try:
            self.http.set_header(name, value)
            return ToolResult(
                success=True,
                tool_name="set_header", 
                data={"name": name, "value": value},
                summary=f"Header '{name}' set",
            )
        except Exception as e:
            return ToolResult(False, "set_header", None, "", str(e))
    
    def get_cookies(self) -> ToolResult:
        """Get all current cookies"""
        try:
            cookies = self.http.get_cookies()
            return ToolResult(
                success=True,
                tool_name="get_cookies",
                data=cookies,
                summary=f"Found {len(cookies)} cookies",
            )
        except Exception as e:
            return ToolResult(False, "get_cookies", None, "", str(e))
    
    # =================
    # Finding Management
    # =================
    
    def report_finding(self, title: str, description: str, severity: str,
                      url: str, evidence: str = "", 
                      category: str = "other") -> ToolResult:
        """
        Report a security finding
        
        LLM Usage:
            toolkit.report_finding(
                title="SQL Injection in search parameter",
                description="The 'q' parameter is vulnerable to SQL injection...",
                severity="high",
                url="/search?q=test",
                evidence="Response contains SQL error: 'You have an error in your SQL syntax'",
                category="sqli"
            )
        """
        try:
            finding = {
                "title": title,
                "description": description,
                "severity": severity,
                "url": url,
                "evidence": evidence,
                "category": category,
            }
            self.findings.append(finding)
            
            return ToolResult(
                success=True,
                tool_name="report_finding",
                data=finding,
                summary=f"Finding reported: [{severity.upper()}] {title}",
            )
        except Exception as e:
            return ToolResult(False, "report_finding", None, "", str(e))
    
    def get_findings(self) -> ToolResult:
        """Get all reported findings"""
        return ToolResult(
            success=True,
            tool_name="get_findings",
            data=self.findings,
            summary=f"Total findings: {len(self.findings)}",
        )
    
    # =================
    # Utility Methods
    # =================
    
    def get_history(self) -> ToolResult:
        """Get request/response history"""
        history = []
        for req, resp in self.http.get_history()[-20:]:
            history.append({
                "request": {"method": req.method, "url": req.url},
                "response": {"status": resp.status_code, "url": resp.url},
            })
        
        return ToolResult(
            success=True,
            tool_name="get_history",
            data=history,
            summary=f"Last {len(history)} requests",
        )
    
    def get_tool_list(self) -> str:
        """
        Get list of available tools with descriptions
        Returns formatted string for LLM
        """
        tools = """
=== VulnHunter LLM Toolkit ===

HTTP Operations:
  - fetch(url, params) - Fetch a URL with optional query params
  - post(url, data, json_data) - Send POST request (form or JSON)
  - request(method, url, data, headers, params) - Send custom HTTP request
  - send_payload(url, method, payload, param_name) - Send a test payload

Form Operations:
  - get_forms(url) - Get forms from a page or crawl results
  - submit_form(action, data, method) - Submit a form

Crawling:
  - crawl(max_pages) - Crawl the target website
  - get_urls(pattern) - Get discovered URLs, optionally filtered
  - get_endpoints() - Get API endpoints from JavaScript

Source Analysis:
  - analyze_page(url) - Analyze page for vulnerabilities
  - read_source(url) - Read page source code

Authentication:
  - login(url, credentials, use_json) - Perform login
  - register(url, account_data, use_json) - Register new account
  - set_auth_token(token, header, prefix) - Set auth token
  - get_csrf_token(url) - Extract CSRF token

Session Management:
  - set_cookie(name, value) - Set a cookie
  - set_header(name, value) - Set a header
  - get_cookies() - Get all cookies

Findings:
  - report_finding(title, description, severity, url, evidence, category) - Report a finding
  - get_findings() - Get all findings

Utility:
  - get_history() - Get request/response history
  - get_tool_list() - Show this help
================================
"""
        return tools
