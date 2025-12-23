"""
XSS Scanner for VulnHunter
Detects Cross-Site Scripting vulnerabilities (Reflected, Stored, DOM)
"""

import re
import html
from typing import Optional, Dict, List, Any
from datetime import datetime
from loguru import logger

from .base_scanner import BaseScanner, ScanResult, Vulnerability
from ..core.http_client import HTTPClient, HTTPRequest, HTTPResponse


class XSSScanner(BaseScanner):
    """
    Cross-Site Scripting vulnerability scanner
    Detects reflected, stored, and DOM-based XSS
    """
    
    def __init__(self, http_client: HTTPClient):
        super().__init__(http_client)
        self.name = "XSS Scanner"
        self.category = "xss"
        
        # Reflection test payloads with unique markers
        self.reflection_payloads = [
            # Basic reflection tests
            "vuln<>hunter",
            "vuln\"hunter",
            "vuln'hunter",
            "vuln`hunter",
            
            # Script injection
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<script>alert(document.domain)</script>",
            
            # Event handlers
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
            "<video src=x onerror=alert(1)>",
            "<audio src=x onerror=alert(1)>",
            
            # Attribute injection
            "\" onclick=alert(1) \"",
            "' onclick=alert(1) '",
            "\" onmouseover=alert(1) \"",
            
            # JavaScript protocol
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            
            # Encoded payloads
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
            
            # Bypass attempts
            "<ScRiPt>alert(1)</ScRiPt>",
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "<svg/onload=alert(1)>",
            "<<script>script>alert(1)</<script>script>",
            
            # Template injection
            "{{constructor.constructor('alert(1)')()}}",
            "${alert(1)}",
            "#{alert(1)}",
        ]
        
        # Context-specific payloads
        self.context_payloads = {
            "html": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
            ],
            "attribute": [
                "\" onmouseover=\"alert(1)\"",
                "' onmouseover='alert(1)'",
                "\" onfocus=\"alert(1)\" autofocus \"",
            ],
            "javascript": [
                "'-alert(1)-'",
                "\";alert(1);//",
                "'-alert(1)//",
            ],
            "url": [
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
            ],
        }
        
        # DOM XSS sinks to check in JavaScript
        self.dom_sinks = [
            "innerHTML",
            "outerHTML",
            "document.write",
            "document.writeln",
            "eval(",
            "setTimeout(",
            "setInterval(",
            "Function(",
            "location.href",
            "location.replace",
            "location.assign",
        ]
        
        # DOM XSS sources
        self.dom_sources = [
            "location.search",
            "location.hash",
            "location.href",
            "document.URL",
            "document.referrer",
            "window.name",
            "document.cookie",
        ]
        
    def scan_url(self, url: str, method: str = "GET",
                params: Optional[Dict] = None) -> ScanResult:
        """
        Scan a URL for XSS vulnerabilities
        
        LLM Usage:
            scanner = XSSScanner(http_client)
            results = scanner.scan_url("/search", "GET", {"q": "test"})
        """
        self.results = ScanResult(
            scanner_name=self.name,
            target_url=url,
            start_time=datetime.now()
        )
        
        if not params:
            logger.warning("No parameters to test for XSS")
            self.results.end_time = datetime.now()
            return self.results
        
        # Test each parameter
        for param_name, param_value in params.items():
            self._test_parameter(url, method, params, param_name)
        
        # Check for DOM XSS
        self._check_dom_xss(url, method, params)
        
        self.results.end_time = datetime.now()
        return self.results
    
    def scan_form(self, action: str, method: str,
                 inputs: List[Dict]) -> ScanResult:
        """
        Scan a form for XSS vulnerabilities
        """
        self.results = ScanResult(
            scanner_name=self.name,
            target_url=action,
            start_time=datetime.now()
        )
        
        # Build form data
        form_data = {}
        for inp in inputs:
            name = inp.get('name', '')
            if name:
                form_data[name] = inp.get('value', 'test')
        
        # Test each input
        for inp in inputs:
            param_name = inp.get('name', '')
            if param_name and inp.get('type') not in ['hidden', 'submit', 'button', 'file']:
                self._test_parameter(action, method, form_data, param_name)
        
        self.results.end_time = datetime.now()
        return self.results
    
    def _test_parameter(self, url: str, method: str, params: Dict, param_name: str):
        """Test a single parameter for XSS"""
        
        # First, test for reflection
        context = self._detect_reflection_context(url, method, params, param_name)
        
        if context:
            # Test with context-specific payloads
            self._test_context_payloads(url, method, params, param_name, context)
        
        # Also test generic payloads
        self._test_generic_payloads(url, method, params, param_name)
    
    def _detect_reflection_context(self, url: str, method: str, 
                                  params: Dict, param_name: str) -> Optional[str]:
        """Detect where/how input is reflected in the response"""
        
        # Use a unique marker
        marker = "VH_XSS_MARKER_12345"
        test_params = params.copy()
        test_params[param_name] = marker
        
        if method.upper() == "GET":
            response = self.http_client.get(url, params=test_params)
        else:
            response = self.http_client.post_form(url, test_params)
        self.results.requests_made += 1
        
        if marker not in response.body:
            return None  # Not reflected
        
        # Determine context
        body = response.body
        marker_pos = body.find(marker)
        
        # Check surrounding context
        before = body[max(0, marker_pos - 50):marker_pos]
        after = body[marker_pos + len(marker):min(len(body), marker_pos + len(marker) + 50)]
        
        # HTML attribute context
        if re.search(r'["\'][^"\']*$', before) and re.search(r'^[^"\']*["\']', after):
            return "attribute"
        
        # JavaScript context
        if "<script" in before.lower() or "javascript:" in before.lower():
            return "javascript"
        
        # URL context
        if "href=" in before.lower() or "src=" in before.lower():
            return "url"
        
        # Default HTML context
        return "html"
    
    def _test_context_payloads(self, url: str, method: str, params: Dict,
                              param_name: str, context: str):
        """Test payloads specific to the reflection context"""
        
        payloads = self.context_payloads.get(context, [])
        
        for payload in payloads:
            test_params = params.copy()
            test_params[param_name] = payload
            
            if method.upper() == "GET":
                response = self.http_client.get(url, params=test_params)
            else:
                response = self.http_client.post_form(url, test_params)
            self.results.requests_made += 1
            
            # Check if payload is reflected without encoding
            if self._is_xss_successful(payload, response.body):
                vuln = Vulnerability(
                    id=self._create_vuln_id("xss-reflected", url, param_name),
                    title=f"Reflected XSS in '{param_name}' ({context} context)",
                    description=f"The parameter '{param_name}' is vulnerable to reflected XSS. "
                               f"User input is reflected in a {context} context without proper encoding.",
                    severity="high" if context in ["html", "javascript"] else "medium",
                    category="xss",
                    url=url,
                    parameter=param_name,
                    method=method,
                    payload=payload,
                    evidence=f"Payload reflected in {context} context",
                    remediation="Encode output based on context. Use Content-Security-Policy headers. "
                               "Use HttpOnly and Secure flags on cookies.",
                    cvss_score=6.1,
                    cwe_id="CWE-79",
                    confidence="high",
                )
                self.results.add_vulnerability(vuln)
                logger.info(f"[!] XSS found in {param_name} (context: {context})")
                return
    
    def _test_generic_payloads(self, url: str, method: str, params: Dict, param_name: str):
        """Test generic XSS payloads"""
        
        # Check if we already found XSS for this param
        existing = [v for v in self.results.vulnerabilities if v.parameter == param_name]
        if existing:
            return
        
        for payload in self.reflection_payloads[:10]:  # Limit payloads
            test_params = params.copy()
            test_params[param_name] = payload
            
            if method.upper() == "GET":
                response = self.http_client.get(url, params=test_params)
            else:
                response = self.http_client.post_form(url, test_params)
            self.results.requests_made += 1
            
            if self._is_xss_successful(payload, response.body):
                vuln = Vulnerability(
                    id=self._create_vuln_id("xss-reflected", url, param_name),
                    title=f"Reflected XSS in '{param_name}'",
                    description=f"The parameter '{param_name}' is vulnerable to reflected XSS. "
                               f"User input is reflected without proper encoding.",
                    severity="high",
                    category="xss",
                    url=url,
                    parameter=param_name,
                    method=method,
                    payload=payload,
                    evidence="Payload reflected without encoding",
                    remediation="Encode all user input before rendering. "
                               "Implement Content-Security-Policy.",
                    cvss_score=6.1,
                    cwe_id="CWE-79",
                    confidence="medium",
                )
                self.results.add_vulnerability(vuln)
                logger.info(f"[!] XSS found in {param_name}")
                return
    
    def _is_xss_successful(self, payload: str, response_body: str) -> bool:
        """Check if XSS payload was successful"""
        
        # Direct reflection of script tags
        if "<script>" in payload and "<script>" in response_body:
            return True
        
        # Event handlers reflected
        event_handlers = ["onerror=", "onload=", "onclick=", "onmouseover=", "onfocus="]
        for handler in event_handlers:
            if handler in payload and handler in response_body:
                return True
        
        # JavaScript protocol reflected
        if "javascript:" in payload and "javascript:" in response_body:
            return True
        
        # SVG/IMG tags reflected
        if ("<svg" in payload or "<img" in payload) and (
            payload.lower() in response_body.lower()
        ):
            return True
        
        return False
    
    def _check_dom_xss(self, url: str, method: str, params: Dict):
        """Check for DOM-based XSS by analyzing JavaScript"""
        
        response = self.http_client.get(url)
        self.results.requests_made += 1
        
        # Look for dangerous patterns
        for source in self.dom_sources:
            for sink in self.dom_sinks:
                # Simple pattern: source flows to sink
                pattern = rf'{source}.*{sink}'
                if re.search(pattern, response.body, re.IGNORECASE | re.DOTALL):
                    vuln = Vulnerability(
                        id=self._create_vuln_id("xss-dom", url, source),
                        title=f"Potential DOM XSS: {source} -> {sink}",
                        description=f"The page contains JavaScript that may read from {source} "
                                   f"and write to {sink}, creating a potential DOM XSS vulnerability.",
                        severity="medium",
                        category="xss-dom",
                        url=url,
                        parameter=source,
                        evidence=f"Source: {source}, Sink: {sink}",
                        remediation="Validate and encode data from URL parameters before using in DOM. "
                                   "Use textContent instead of innerHTML where possible.",
                        cvss_score=6.1,
                        cwe_id="CWE-79",
                        confidence="low",
                    )
                    self.results.add_vulnerability(vuln)
                    logger.info(f"[!] Potential DOM XSS: {source} -> {sink}")
    
    def get_payloads(self, context: str = "all") -> List[str]:
        """
        Get XSS payloads for manual testing
        
        LLM Usage:
            payloads = scanner.get_payloads("html")  # html, attribute, javascript, url, all
        """
        if context in self.context_payloads:
            return self.context_payloads[context]
        return self.reflection_payloads
