"""
IDOR Scanner for VulnHunter
Detects Insecure Direct Object Reference vulnerabilities
"""

import re
from typing import Optional, Dict, List, Any
from datetime import datetime
from loguru import logger

from .base_scanner import BaseScanner, ScanResult, Vulnerability
from ..core.http_client import HTTPClient, HTTPRequest, HTTPResponse


class IDORScanner(BaseScanner):
    """
    IDOR (Insecure Direct Object Reference) vulnerability scanner
    Detects unauthorized access to resources through ID manipulation
    """
    
    def __init__(self, http_client: HTTPClient, 
                 user_id: Optional[str] = None,
                 other_user_id: Optional[str] = None):
        super().__init__(http_client)
        self.name = "IDOR Scanner"
        self.category = "idor"
        
        # Current user's ID (for authenticated testing)
        self.user_id = user_id
        self.other_user_id = other_user_id or "1"  # Target user ID to test access
        
        # ID parameter patterns
        self.id_patterns = [
            r'[?&]id=(\d+)',
            r'[?&]user[_-]?id=(\d+)',
            r'[?&]account[_-]?id=(\d+)',
            r'[?&]doc[_-]?id=(\d+)',
            r'[?&]file[_-]?id=(\d+)',
            r'[?&]order[_-]?id=(\d+)',
            r'/users?/(\d+)',
            r'/account/(\d+)',
            r'/profile/(\d+)',
            r'/orders?/(\d+)',
            r'/documents?/(\d+)',
            r'/files?/(\d+)',
            r'/api/v\d+/users?/(\d+)',
        ]
        
        # ID manipulation values to try
        self.test_ids = [
            "1", "2", "0", "-1", "999999",
            "admin", "root", "test",
        ]
        
    def scan_url(self, url: str, method: str = "GET",
                params: Optional[Dict] = None) -> ScanResult:
        """
        Scan a URL for IDOR vulnerabilities
        
        LLM Usage:
            scanner = IDORScanner(http_client, user_id="100")
            results = scanner.scan_url("/api/user/100/profile")
        """
        self.results = ScanResult(
            scanner_name=self.name,
            target_url=url,
            start_time=datetime.now()
        )
        
        # Find IDs in URL path
        self._scan_url_path(url, method)
        
        # Find IDs in query params
        if params:
            for param_name, param_value in params.items():
                if self._looks_like_id(param_name, param_value):
                    self._test_param_idor(url, method, params, param_name, param_value)
        
        self.results.end_time = datetime.now()
        return self.results
    
    def scan_form(self, action: str, method: str,
                 inputs: List[Dict]) -> ScanResult:
        """Scan a form for IDOR vulnerabilities"""
        self.results = ScanResult(
            scanner_name=self.name,
            target_url=action,
            start_time=datetime.now()
        )
        
        # Build form data and identify ID fields
        form_data = {}
        id_fields = []
        
        for inp in inputs:
            name = inp.get('name', '')
            value = inp.get('value', '')
            if name:
                form_data[name] = value
                if self._looks_like_id(name, value):
                    id_fields.append((name, value))
        
        # Test each ID field
        for name, value in id_fields:
            self._test_param_idor(action, method, form_data, name, value)
        
        self.results.end_time = datetime.now()
        return self.results
    
    def scan_api_endpoints(self, endpoints: List[Dict]) -> ScanResult:
        """
        Scan multiple API endpoints for IDOR
        
        LLM Usage:
            endpoints = [
                {"url": "/api/users/1", "method": "GET"},
                {"url": "/api/orders/100", "method": "GET"},
            ]
            results = scanner.scan_api_endpoints(endpoints)
        """
        self.results = ScanResult(
            scanner_name=self.name,
            target_url="Multiple endpoints",
            start_time=datetime.now()
        )
        
        for ep in endpoints:
            url = ep.get("url", "")
            method = ep.get("method", "GET")
            
            self._scan_url_path(url, method)
        
        self.results.end_time = datetime.now()
        return self.results
    
    def _looks_like_id(self, param_name: str, param_value: str) -> bool:
        """Check if a parameter looks like an ID"""
        name_lower = param_name.lower()
        
        # Check name patterns
        id_keywords = ['id', 'user', 'account', 'profile', 'order', 'doc', 
                       'file', 'uid', 'pid', 'oid', 'key', 'ref']
        
        for keyword in id_keywords:
            if keyword in name_lower:
                return True
        
        # Check if value looks like an ID (numeric or UUID)
        if param_value:
            if param_value.isdigit():
                return True
            # UUID pattern
            if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', 
                       param_value, re.I):
                return True
        
        return False
    
    def _scan_url_path(self, url: str, method: str):
        """Scan URL path for ID parameters"""
        
        for pattern in self.id_patterns:
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                original_id = match.group(1)
                self._test_path_idor(url, method, original_id, pattern)
    
    def _test_path_idor(self, url: str, method: str, original_id: str, pattern: str):
        """Test for IDOR by manipulating ID in URL path"""
        
        # Get baseline response
        baseline = self.http_client.get(url) if method.upper() == "GET" else \
                  self.http_client.request(HTTPRequest(url=url, method=method))
        self.results.requests_made += 1
        
        if baseline.status_code in [401, 403, 404]:
            return  # Can't access our own resource
        
        # Try accessing other user's resources
        for test_id in self.test_ids:
            if test_id == original_id:
                continue
            
            # Replace ID in URL
            test_url = re.sub(pattern, lambda m: m.group(0).replace(original_id, test_id), url)
            
            if test_url == url:
                continue
            
            test_response = self.http_client.get(test_url) if method.upper() == "GET" else \
                           self.http_client.request(HTTPRequest(url=test_url, method=method))
            self.results.requests_made += 1
            
            # Check for IDOR
            if self._is_idor_successful(baseline, test_response, test_id):
                vuln = Vulnerability(
                    id=self._create_vuln_id("idor", url, original_id),
                    title=f"IDOR - Unauthorized Access to Resource",
                    description=f"The application allows access to other users' resources by modifying "
                               f"the ID parameter in the URL. Changing ID from {original_id} to {test_id} "
                               f"returned accessible content.",
                    severity="high",
                    category="idor",
                    url=url,
                    parameter=f"ID in path ({original_id})",
                    method=method,
                    payload=test_id,
                    evidence=f"Original ID: {original_id}, Test ID: {test_id}, "
                            f"Status: {test_response.status_code}",
                    remediation="Implement proper authorization checks. Verify that the authenticated "
                               "user has permission to access the requested resource.",
                    cvss_score=7.5,
                    cwe_id="CWE-639",
                    confidence="medium",
                )
                self.results.add_vulnerability(vuln)
                logger.info(f"[!] IDOR found: {url} (ID {original_id} -> {test_id})")
                return
    
    def _test_param_idor(self, url: str, method: str, params: Dict,
                        param_name: str, original_value: str):
        """Test for IDOR in query/form parameter"""
        
        # Get baseline
        if method.upper() == "GET":
            baseline = self.http_client.get(url, params=params)
        else:
            baseline = self.http_client.post_form(url, params)
        self.results.requests_made += 1
        
        if baseline.status_code in [401, 403, 404]:
            return
        
        # Try other IDs
        for test_id in self.test_ids:
            if test_id == original_value:
                continue
            
            test_params = params.copy()
            test_params[param_name] = test_id
            
            if method.upper() == "GET":
                test_response = self.http_client.get(url, params=test_params)
            else:
                test_response = self.http_client.post_form(url, test_params)
            self.results.requests_made += 1
            
            if self._is_idor_successful(baseline, test_response, test_id):
                vuln = Vulnerability(
                    id=self._create_vuln_id("idor", url, param_name),
                    title=f"IDOR in Parameter '{param_name}'",
                    description=f"The parameter '{param_name}' is vulnerable to IDOR. "
                               f"Modifying the value from {original_value} to {test_id} "
                               f"allows access to other resources.",
                    severity="high",
                    category="idor",
                    url=url,
                    parameter=param_name,
                    method=method,
                    payload=test_id,
                    evidence=f"Original: {original_value}, Test: {test_id}",
                    remediation="Implement authorization checks before accessing resources.",
                    cvss_score=7.5,
                    cwe_id="CWE-639",
                    confidence="medium",
                )
                self.results.add_vulnerability(vuln)
                logger.info(f"[!] IDOR found in parameter {param_name}")
                return
    
    def _is_idor_successful(self, baseline: HTTPResponse, 
                           test_response: HTTPResponse, test_id: str) -> bool:
        """Determine if IDOR attempt was successful"""
        
        # Access denied = no IDOR
        if test_response.status_code in [401, 403, 404]:
            return False
        
        # Success status codes
        if test_response.status_code in [200, 201]:
            # Check if response contains different data
            if len(test_response.body) > 100:
                # Response has substantial content
                # Check if it's different from baseline (might be another user's data)
                if test_response.body != baseline.body:
                    # Look for indicators of different user data
                    if test_id in test_response.body:
                        return True
                    # Different content length suggests different data
                    if abs(len(test_response.body) - len(baseline.body)) > 50:
                        return True
            return True  # Got 200, might be IDOR
        
        return False
    
    def test_horizontal_idor(self, url_template: str, 
                            user_ids: List[str]) -> ScanResult:
        """
        Test for horizontal IDOR with specific user IDs
        
        LLM Usage:
            # Test if user 100 can access user 101's data
            results = scanner.test_horizontal_idor(
                "/api/users/{id}/profile",
                ["100", "101", "102"]
            )
        """
        self.results = ScanResult(
            scanner_name=self.name,
            target_url=url_template,
            start_time=datetime.now()
        )
        
        accessible_ids = []
        
        for uid in user_ids:
            url = url_template.replace("{id}", uid)
            response = self.http_client.get(url)
            self.results.requests_made += 1
            
            if response.status_code == 200:
                accessible_ids.append(uid)
        
        if len(accessible_ids) > 1:
            vuln = Vulnerability(
                id=self._create_vuln_id("idor-horizontal", url_template, "id"),
                title="Horizontal IDOR - Multiple User Resources Accessible",
                description=f"The authenticated user can access resources belonging to "
                           f"multiple user IDs: {accessible_ids}. This indicates a lack of "
                           f"proper authorization checks.",
                severity="critical",
                category="idor",
                url=url_template,
                parameter="User ID",
                evidence=f"Accessible IDs: {accessible_ids}",
                remediation="Verify that the authenticated user owns or has permission "
                           "to access each requested resource.",
                cvss_score=8.1,
                cwe_id="CWE-639",
                confidence="high",
            )
            self.results.add_vulnerability(vuln)
        
        self.results.end_time = datetime.now()
        return self.results
