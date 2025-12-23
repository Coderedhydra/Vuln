"""
Web Tools - High-level tools for LLM to interact with web applications
Designed for easy use by LLM models
"""

import json
from typing import Dict, List, Optional, Any, Union
from urllib.parse import urlparse

import sys
sys.path.append('..')

from core.http_client import HTTPClient, Response
from core.crawler import WebCrawler, PageInfo
from core.parser import HTMLParser
from core.session import SessionManager
from scanners.xss import XSSScanner
from scanners.sqli import SQLiScanner
from scanners.ssrf import SSRFScanner
from scanners.lfi import LFIScanner
from scanners.auth import AuthScanner
from scanners.idor import IDORScanner
from payloads.generator import PayloadGenerator
from payloads.templates import PayloadTemplates


class WebTools:
    """
    Unified web tools interface for LLM
    
    This class provides all the tools an LLM needs to:
    - Fetch and analyze web pages
    - Send custom requests
    - Scan for vulnerabilities
    - Generate payloads
    - Manage sessions
    
    Usage for LLM:
    - tools.fetch(url) - Fetch a URL
    - tools.crawl(url) - Crawl a website
    - tools.analyze(url) - Deep analysis
    - tools.scan_xss(url, param) - Scan for XSS
    - tools.send_request(method, url, ...) - Send custom request
    """
    
    def __init__(self, proxy: Optional[str] = None, timeout: int = 30):
        self.client = HTTPClient(proxy=proxy, timeout=timeout)
        self.crawler = WebCrawler(client=self.client)
        self.parser = HTMLParser()
        self.session = SessionManager(client=self.client)
        self.payload_gen = PayloadGenerator()
        
        # Initialize scanners
        self.xss_scanner = XSSScanner(client=self.client)
        self.sqli_scanner = SQLiScanner(client=self.client)
        self.ssrf_scanner = SSRFScanner(client=self.client)
        self.lfi_scanner = LFIScanner(client=self.client)
        self.auth_scanner = AuthScanner(client=self.client)
        self.idor_scanner = IDORScanner(client=self.client)
        
        # Store findings
        self.findings: List[Dict] = []
        self.history: List[Dict] = []

    # ==================== FETCH & ANALYZE ====================
    
    def fetch(self, url: str, method: str = "GET",
              headers: Optional[Dict] = None,
              data: Optional[Dict] = None,
              json_data: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Fetch a URL and return response details
        
        Args:
            url: Target URL
            method: HTTP method
            headers: Custom headers
            data: Form data (for POST)
            json_data: JSON body (for POST)
        
        Returns:
            Dict with response details
        """
        response = self.client.send(
            method=method,
            url=url,
            headers=headers,
            data=data,
            json_data=json_data
        )
        
        result = {
            "url": response.url,
            "status": response.status_code,
            "headers": dict(response.headers),
            "body": response.body[:10000],  # Limit for LLM context
            "body_length": len(response.body),
            "cookies": response.cookies,
            "time_ms": response.elapsed_ms
        }
        
        self.history.append({"action": "fetch", "url": url, "result": result})
        return result

    def crawl(self, url: str, depth: int = 2) -> Dict[str, Any]:
        """
        Crawl a website and discover structure
        
        Args:
            url: Starting URL
            depth: Crawl depth
        
        Returns:
            Dict with discovered URLs, forms, etc.
        """
        self.crawler.reset()
        summary = self.crawler.crawl_site(url, depth)
        
        result = {
            "pages_crawled": summary["pages_crawled"],
            "urls_discovered": list(self.crawler.discovered_urls)[:50],
            "forms": summary["forms"][:20],
            "parameters": summary["parameters"],
            "technologies": summary["technologies"],
            "api_endpoints": summary["api_endpoints"][:20],
            "emails": summary["emails"]
        }
        
        self.history.append({"action": "crawl", "url": url, "result": result})
        return result

    def analyze(self, url: str) -> Dict[str, Any]:
        """
        Deep analysis of a single page
        
        Args:
            url: URL to analyze
        
        Returns:
            Comprehensive analysis including security findings
        """
        response = self.client.get(url)
        analysis = self.parser.get_full_analysis(response.body, url)
        
        # Add page info from crawler
        page_info = self.crawler.crawl(url)
        
        result = {
            "url": url,
            "title": page_info.title,
            "technologies": page_info.technologies,
            "forms": [f.to_dict() for f in page_info.forms],
            "links": page_info.links[:30],
            "scripts": analysis["parsed_elements"]["scripts"],
            "comments": analysis["parsed_elements"]["comments"],
            "hidden_inputs": analysis["parsed_elements"]["hidden_inputs"],
            "security_findings": analysis["security_findings"],
            "api_info": analysis["api_info"],
            "summary": analysis["summary"]
        }
        
        self.history.append({"action": "analyze", "url": url})
        return result

    def read_source(self, url: str) -> Dict[str, Any]:
        """
        Read and return page source code for analysis
        
        Args:
            url: URL to read
        
        Returns:
            Page source with extracted components
        """
        response = self.client.get(url)
        
        return {
            "url": url,
            "html": response.body,
            "html_length": len(response.body),
            "scripts": self.parser.get_inline_scripts(response.body),
            "comments": self.parser.get_comments(response.body),
            "hidden_fields": self.parser.get_hidden_inputs(response.body),
            "data_attributes": self.parser.get_data_attributes(response.body)
        }

    # ==================== SEND REQUESTS ====================
    
    def send_request(self, method: str, url: str,
                     headers: Optional[Dict] = None,
                     params: Optional[Dict] = None,
                     data: Optional[Dict] = None,
                     json_data: Optional[Dict] = None,
                     cookies: Optional[Dict] = None,
                     raw_body: Optional[str] = None) -> Dict[str, Any]:
        """
        Send a fully customizable HTTP request
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            url: Target URL
            headers: Custom headers
            params: URL parameters
            data: Form data
            json_data: JSON body
            cookies: Custom cookies
            raw_body: Raw body string
        
        Returns:
            Complete response details
        """
        response = self.client.send(
            method=method,
            url=url,
            headers=headers,
            params=params,
            data=data,
            json_data=json_data,
            cookies=cookies,
            raw_body=raw_body
        )
        
        return response.to_dict()

    def inject_payload(self, url: str, param: str, payload: str,
                       method: str = "GET") -> Dict[str, Any]:
        """
        Inject a payload into a URL parameter
        
        Args:
            url: Target URL
            param: Parameter to inject into
            payload: Payload to inject
            method: HTTP method
        
        Returns:
            Response with analysis
        """
        response = self.client.inject_payload(url, param, payload, method)
        
        return {
            "url": response.url,
            "status": response.status_code,
            "payload": payload,
            "reflected": payload in response.body,
            "body": response.body[:5000],
            "body_length": len(response.body),
            "time_ms": response.elapsed_ms
        }

    # ==================== VULNERABILITY SCANNING ====================
    
    def scan_xss(self, url: str, param: str, method: str = "GET",
                 category: str = "basic") -> Dict[str, Any]:
        """
        Scan a parameter for XSS vulnerabilities
        
        Args:
            url: Target URL
            param: Parameter to test
            method: HTTP method
            category: Payload category (basic, filter_bypass, polyglot)
        
        Returns:
            XSS scan results
        """
        results = self.xss_scanner.test_parameter(url, param, method, category=category)
        summary = self.xss_scanner.get_summary(results)
        
        # Store findings
        for r in results:
            if r.vulnerable:
                self.findings.append({
                    "type": "xss",
                    "url": url,
                    "param": param,
                    "payload": r.payload,
                    "severity": "high" if r.confidence == "high" else "medium"
                })
        
        return {
            "url": url,
            "param": param,
            "results": [r.to_dict() for r in results[:10]],
            "summary": summary
        }

    def scan_sqli(self, url: str, param: str, method: str = "GET",
                  test_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Scan a parameter for SQL injection
        
        Args:
            url: Target URL
            param: Parameter to test
            method: HTTP method
            test_types: Types to test (error, boolean, time, union)
        
        Returns:
            SQLi scan results
        """
        test_types = test_types or ["error", "boolean"]
        results = self.sqli_scanner.test_parameter(url, param, method, test_types)
        summary = self.sqli_scanner.get_summary(results)
        
        for r in results:
            if r.vulnerable:
                self.findings.append({
                    "type": "sqli",
                    "url": url,
                    "param": param,
                    "payload": r.payload,
                    "severity": "critical"
                })
        
        return {
            "url": url,
            "param": param,
            "results": [r.to_dict() for r in results],
            "summary": summary
        }

    def scan_ssrf(self, url: str, param: str, 
                  categories: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Scan for SSRF vulnerabilities
        
        Args:
            url: Target URL
            param: Parameter to test
            categories: Categories to test (localhost, cloud, internal)
        
        Returns:
            SSRF scan results
        """
        categories = categories or ["localhost", "cloud"]
        results = self.ssrf_scanner.test_parameter(url, param, categories=categories)
        summary = self.ssrf_scanner.get_summary(results)
        
        for r in results:
            if r.vulnerable:
                self.findings.append({
                    "type": "ssrf",
                    "url": url,
                    "param": param,
                    "payload": r.payload,
                    "severity": "critical" if "aws" in r.payload else "high"
                })
        
        return {
            "url": url,
            "param": param,
            "results": [r.to_dict() for r in results],
            "summary": summary
        }

    def scan_lfi(self, url: str, param: str,
                 os_type: str = "linux") -> Dict[str, Any]:
        """
        Scan for Local File Inclusion
        
        Args:
            url: Target URL
            param: Parameter to test
            os_type: Target OS (linux/windows)
        
        Returns:
            LFI scan results
        """
        results = self.lfi_scanner.test_parameter(url, param, os_type=os_type)
        summary = self.lfi_scanner.get_summary(results)
        
        for r in results:
            if r.vulnerable:
                self.findings.append({
                    "type": "lfi",
                    "url": url,
                    "param": param,
                    "payload": r.payload,
                    "severity": "high"
                })
        
        return {
            "url": url,
            "param": param,
            "results": [r.to_dict() for r in results],
            "summary": summary
        }

    def scan_auth(self, login_url: str,
                  username_field: str = "username",
                  password_field: str = "password") -> Dict[str, Any]:
        """
        Scan authentication for vulnerabilities
        
        Args:
            login_url: Login form URL
            username_field: Username field name
            password_field: Password field name
        
        Returns:
            Auth scan results
        """
        results = self.auth_scanner.test_login_bypass(
            login_url, username_field, password_field
        )
        summary = self.auth_scanner.get_summary(results)
        
        for r in results:
            if r.vulnerable:
                self.findings.append({
                    "type": "auth",
                    "url": login_url,
                    "vuln_type": r.vuln_type,
                    "severity": r.severity
                })
        
        return {
            "url": login_url,
            "results": [r.to_dict() for r in results],
            "summary": summary
        }

    def scan_idor(self, url: str, param: str,
                  current_id: str) -> Dict[str, Any]:
        """
        Scan for IDOR vulnerabilities
        
        Args:
            url: Target URL
            param: ID parameter
            current_id: Current user's ID
        
        Returns:
            IDOR scan results
        """
        results = self.idor_scanner.test_id_parameter(url, param, current_id)
        summary = self.idor_scanner.get_summary(results)
        
        for r in results:
            if r.vulnerable:
                self.findings.append({
                    "type": "idor",
                    "url": url,
                    "param": param,
                    "severity": r.severity
                })
        
        return {
            "url": url,
            "param": param,
            "results": [r.to_dict() for r in results],
            "summary": summary
        }

    def quick_scan(self, url: str, param: str) -> Dict[str, Any]:
        """
        Quick scan for common vulnerabilities
        
        Tests XSS, SQLi, and LFI with basic payloads
        """
        results = {
            "url": url,
            "param": param,
            "xss": {"vulnerable": False},
            "sqli": {"vulnerable": False},
            "lfi": {"vulnerable": False}
        }
        
        # Quick XSS test
        xss_payload = "<script>alert(1)</script>"
        resp = self.client.inject_payload(url, param, xss_payload)
        if xss_payload in resp.body:
            results["xss"] = {"vulnerable": True, "payload": xss_payload}
        
        # Quick SQLi test
        sqli_payload = "'"
        resp = self.client.inject_payload(url, param, sqli_payload)
        sqli_check = self.sqli_scanner.check_sql_error(resp)
        if sqli_check["has_error"]:
            results["sqli"] = {"vulnerable": True, "database": sqli_check["database"]}
        
        # Quick LFI test
        lfi_payload = "../../../etc/passwd"
        resp = self.client.inject_payload(url, param, lfi_payload)
        if "root:" in resp.body:
            results["lfi"] = {"vulnerable": True, "payload": lfi_payload}
        
        return results

    # ==================== PAYLOAD GENERATION ====================
    
    def generate_payload(self, vuln_type: str, **kwargs) -> Dict[str, Any]:
        """
        Generate a payload for a vulnerability type
        
        Args:
            vuln_type: xss, sqli, ssrf, lfi, cmd, ssti
            **kwargs: Type-specific arguments
        
        Returns:
            Generated payload with variants
        """
        if vuln_type == "xss":
            payload = self.payload_gen.xss(**kwargs)
        elif vuln_type == "sqli":
            payload = self.payload_gen.sqli(**kwargs)
        elif vuln_type == "ssrf":
            payload = self.payload_gen.ssrf(**kwargs)
        elif vuln_type == "lfi":
            payload = self.payload_gen.lfi(**kwargs)
        elif vuln_type == "cmd":
            payload = self.payload_gen.command_injection(**kwargs)
        elif vuln_type == "ssti":
            payload = self.payload_gen.ssti(**kwargs)
        else:
            return {"error": f"Unknown vulnerability type: {vuln_type}"}
        
        return payload.to_dict()

    def get_payloads(self, category: str) -> List[str]:
        """
        Get pre-built payloads for a category
        
        Args:
            category: xss, sqli, ssrf, lfi, cmd
        
        Returns:
            List of payloads
        """
        return PayloadTemplates.get_by_category(category)

    def mutate_payload(self, payload: str, count: int = 5) -> List[str]:
        """
        Generate mutations of a payload
        
        Args:
            payload: Original payload
            count: Number of mutations
        
        Returns:
            List of mutated payloads
        """
        return self.payload_gen.mutate(payload, count)

    # ==================== SESSION MANAGEMENT ====================
    
    def login(self, login_url: str, username: str, password: str,
              username_field: str = "username",
              password_field: str = "password",
              csrf_field: Optional[str] = None) -> Dict[str, Any]:
        """
        Login to a web application
        
        Args:
            login_url: Login form URL
            username: Username
            password: Password
            username_field: Username field name
            password_field: Password field name
            csrf_field: CSRF token field name
        
        Returns:
            Login result
        """
        return self.session.login_form(
            login_url, username, password,
            username_field, password_field,
            csrf_field=csrf_field
        )

    def set_cookie(self, name: str, value: str):
        """Set a cookie"""
        self.client.set_cookie(name, value)
        return {"status": "cookie_set", "name": name}

    def set_header(self, name: str, value: str):
        """Set a header"""
        self.client.set_header(name, value)
        return {"status": "header_set", "name": name}

    def get_session_info(self) -> Dict[str, Any]:
        """Get current session information"""
        return {
            "authenticated": self.session.state.is_authenticated,
            "cookies": self.client.get_cookies(),
            "auth_type": self.session.state.auth_type
        }

    # ==================== UTILITY ====================
    
    def get_findings(self) -> List[Dict]:
        """Get all discovered vulnerabilities"""
        return self.findings

    def get_history(self, last_n: int = 10) -> List[Dict]:
        """Get action history"""
        return self.history[-last_n:]

    def clear_findings(self):
        """Clear findings"""
        self.findings = []
        return {"status": "cleared"}

    def get_request_history(self, last_n: int = 10) -> List[Dict]:
        """Get HTTP request history"""
        return self.client.get_history(last_n)
