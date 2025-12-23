"""
Authentication Scanner for VulnHunter
Tests for authentication and authorization vulnerabilities
"""

import re
from typing import Optional, Dict, List, Any
from datetime import datetime
from loguru import logger

from .base_scanner import BaseScanner, ScanResult, Vulnerability
from ..core.http_client import HTTPClient, HTTPRequest, HTTPResponse


class AuthScanner(BaseScanner):
    """
    Authentication and Authorization vulnerability scanner
    Tests for auth bypass, weak passwords, session issues, etc.
    """
    
    def __init__(self, http_client: HTTPClient):
        super().__init__(http_client)
        self.name = "Auth Scanner"
        self.category = "auth"
        
        # Common weak credentials
        self.default_credentials = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("admin", "admin123"),
            ("root", "root"),
            ("root", "toor"),
            ("test", "test"),
            ("user", "user"),
            ("guest", "guest"),
            ("demo", "demo"),
            ("administrator", "administrator"),
        ]
        
        # SQL injection auth bypass payloads
        self.auth_bypass_payloads = [
            ("' OR '1'='1", "' OR '1'='1"),
            ("admin'--", "anything"),
            ("' OR 1=1--", "' OR 1=1--"),
            ("\" OR \"\"=\"", "\" OR \"\"=\""),
            ("' OR ''='", "' OR ''='"),
            ("admin' #", "anything"),
            ("admin'/*", "anything"),
            ("' OR '1'='1' /*", "anything"),
        ]
        
        # Password field names to detect
        self.password_fields = ['password', 'passwd', 'pwd', 'pass', 'secret']
        self.username_fields = ['username', 'user', 'login', 'email', 'name', 'account']
        
    def scan_login_form(self, url: str, form_data: Dict[str, str],
                       method: str = "POST") -> ScanResult:
        """
        Scan a login form for authentication vulnerabilities
        
        LLM Usage:
            results = scanner.scan_login_form("/login", {
                "username": "",
                "password": ""
            })
        """
        self.results = ScanResult(
            scanner_name=self.name,
            target_url=url,
            start_time=datetime.now()
        )
        
        # Identify username and password fields
        username_field = None
        password_field = None
        
        for field in form_data.keys():
            field_lower = field.lower()
            for uf in self.username_fields:
                if uf in field_lower:
                    username_field = field
                    break
            for pf in self.password_fields:
                if pf in field_lower:
                    password_field = field
                    break
        
        if not username_field or not password_field:
            logger.warning("Could not identify username/password fields")
            self.results.end_time = datetime.now()
            return self.results
        
        # Test for default credentials
        self._test_default_credentials(url, form_data, username_field, password_field, method)
        
        # Test for SQL injection bypass
        self._test_auth_bypass(url, form_data, username_field, password_field, method)
        
        # Test for username enumeration
        self._test_username_enumeration(url, form_data, username_field, password_field, method)
        
        # Test for weak password policy
        self._test_password_policy(url, form_data, username_field, password_field, method)
        
        self.results.end_time = datetime.now()
        return self.results
    
    def scan_url(self, url: str, method: str = "GET",
                params: Optional[Dict] = None) -> ScanResult:
        """Scan URL for auth issues (redirects to scan_login_form if POST)"""
        if method.upper() == "POST" and params:
            return self.scan_login_form(url, params, method)
        
        self.results = ScanResult(
            scanner_name=self.name,
            target_url=url,
            start_time=datetime.now()
        )
        
        # Check for authentication bypass via URL manipulation
        self._test_path_bypass(url)
        
        self.results.end_time = datetime.now()
        return self.results
    
    def scan_form(self, action: str, method: str,
                 inputs: List[Dict]) -> ScanResult:
        """Scan form for auth vulnerabilities"""
        form_data = {}
        for inp in inputs:
            name = inp.get('name', '')
            if name:
                form_data[name] = inp.get('value', '')
        
        return self.scan_login_form(action, form_data, method)
    
    def _test_default_credentials(self, url: str, form_data: Dict,
                                  username_field: str, password_field: str, method: str):
        """Test for default/common credentials"""
        
        for username, password in self.default_credentials[:5]:  # Limit attempts
            test_data = form_data.copy()
            test_data[username_field] = username
            test_data[password_field] = password
            
            response = self.http_client.post_form(url, test_data)
            self.results.requests_made += 1
            
            if self._is_login_successful(response):
                vuln = Vulnerability(
                    id=self._create_vuln_id("auth-default", url, username_field),
                    title=f"Default Credentials: {username}/{password}",
                    description=f"The application allows login with default credentials: "
                               f"username='{username}', password='{password}'",
                    severity="critical",
                    category="auth",
                    url=url,
                    parameter=username_field,
                    method=method,
                    payload=f"{username}:{password}",
                    evidence="Successful login with default credentials",
                    remediation="Disable default accounts or force password change on first login.",
                    cvss_score=9.8,
                    cwe_id="CWE-798",
                    confidence="high",
                )
                self.results.add_vulnerability(vuln)
                logger.info(f"[!] Default credentials found: {username}/{password}")
                return
    
    def _test_auth_bypass(self, url: str, form_data: Dict,
                         username_field: str, password_field: str, method: str):
        """Test for SQL injection auth bypass"""
        
        for bypass_user, bypass_pass in self.auth_bypass_payloads:
            test_data = form_data.copy()
            test_data[username_field] = bypass_user
            test_data[password_field] = bypass_pass
            
            response = self.http_client.post_form(url, test_data)
            self.results.requests_made += 1
            
            if self._is_login_successful(response):
                vuln = Vulnerability(
                    id=self._create_vuln_id("auth-bypass", url, username_field),
                    title="Authentication Bypass via SQL Injection",
                    description=f"The login form is vulnerable to SQL injection authentication bypass. "
                               f"Payload: username='{bypass_user}'",
                    severity="critical",
                    category="auth",
                    url=url,
                    parameter=username_field,
                    method=method,
                    payload=bypass_user,
                    evidence="Successful login with SQL injection payload",
                    remediation="Use parameterized queries for authentication.",
                    cvss_score=10.0,
                    cwe_id="CWE-89",
                    confidence="high",
                )
                self.results.add_vulnerability(vuln)
                logger.info(f"[!] Auth bypass found with: {bypass_user}")
                return
    
    def _test_username_enumeration(self, url: str, form_data: Dict,
                                  username_field: str, password_field: str, method: str):
        """Test for username enumeration"""
        
        # Test with valid-looking username and invalid password
        test_data = form_data.copy()
        test_data[username_field] = "admin"
        test_data[password_field] = "wrongpassword123456"
        
        response_valid_user = self.http_client.post_form(url, test_data)
        self.results.requests_made += 1
        
        # Test with invalid username
        test_data[username_field] = "nonexistentuser12345"
        
        response_invalid_user = self.http_client.post_form(url, test_data)
        self.results.requests_made += 1
        
        # Compare responses
        if len(response_valid_user.body) != len(response_invalid_user.body):
            # Different response lengths might indicate enumeration
            vuln = Vulnerability(
                id=self._create_vuln_id("auth-enum", url, username_field),
                title="Username Enumeration",
                description="The application returns different responses for valid vs invalid usernames, "
                           "allowing attackers to enumerate valid accounts.",
                severity="medium",
                category="auth",
                url=url,
                parameter=username_field,
                evidence=f"Response lengths differ: valid={len(response_valid_user.body)}, "
                        f"invalid={len(response_invalid_user.body)}",
                remediation="Return identical error messages for invalid username and password.",
                cvss_score=5.3,
                cwe_id="CWE-204",
                confidence="medium",
            )
            self.results.add_vulnerability(vuln)
            logger.info("[!] Username enumeration possible")
    
    def _test_password_policy(self, url: str, form_data: Dict,
                             username_field: str, password_field: str, method: str):
        """Test for weak password policy"""
        
        weak_passwords = ["a", "123", "pass"]
        
        for weak_pass in weak_passwords:
            test_data = form_data.copy()
            test_data[username_field] = "testuser_policy_check"
            test_data[password_field] = weak_pass
            
            # This would need a registration form, but check login for hints
            response = self.http_client.post_form(url, test_data)
            self.results.requests_made += 1
            
            # Look for "password too short" type messages that might reveal policy
            if "short" not in response.body.lower() and "weak" not in response.body.lower():
                if "policy" not in response.body.lower() and "requirements" not in response.body.lower():
                    # No clear rejection of weak password
                    vuln = Vulnerability(
                        id=self._create_vuln_id("auth-policy", url, password_field),
                        title="Potentially Weak Password Policy",
                        description="The application may not enforce strong password requirements. "
                                   "Weak passwords like '123' do not trigger policy errors.",
                        severity="low",
                        category="auth",
                        url=url,
                        parameter=password_field,
                        confidence="low",
                        remediation="Enforce minimum password length, complexity requirements.",
                        cwe_id="CWE-521",
                    )
                    self.results.add_vulnerability(vuln)
                    break
    
    def _test_path_bypass(self, url: str):
        """Test for auth bypass via URL path manipulation"""
        
        bypass_paths = [
            # Case variations
            url.replace('/admin', '/Admin'),
            url.replace('/admin', '/ADMIN'),
            
            # Path traversal
            url + "/../",
            url + "/./",
            url + "/%2e%2e/",
            
            # HTTP method override headers
        ]
        
        # Get baseline (should be 401/403)
        baseline = self.http_client.get(url)
        self.results.requests_made += 1
        
        if baseline.status_code in [401, 403]:
            for bypass_url in bypass_paths:
                response = self.http_client.get(bypass_url)
                self.results.requests_made += 1
                
                if response.status_code == 200:
                    vuln = Vulnerability(
                        id=self._create_vuln_id("auth-path-bypass", url, "path"),
                        title="Authentication Bypass via Path Manipulation",
                        description=f"Protected resource can be accessed by manipulating the URL path. "
                                   f"Original: {url}, Bypass: {bypass_url}",
                        severity="high",
                        category="auth",
                        url=url,
                        payload=bypass_url,
                        evidence=f"Bypass URL returned 200 instead of 401/403",
                        remediation="Normalize URLs before authorization checks.",
                        cvss_score=7.5,
                        cwe_id="CWE-863",
                        confidence="medium",
                    )
                    self.results.add_vulnerability(vuln)
                    return
    
    def _is_login_successful(self, response: HTTPResponse) -> bool:
        """Determine if login was successful"""
        
        # Check for redirect to dashboard/home (common after login)
        if response.status_code in [302, 303]:
            for redirect in response.redirects:
                if any(path in redirect.lower() for path in ['dashboard', 'home', 'account', 'profile']):
                    return True
        
        # Check for success indicators in response
        success_indicators = [
            'welcome', 'dashboard', 'logged in', 'login successful',
            'my account', 'profile', 'logout',
        ]
        
        body_lower = response.body.lower()
        for indicator in success_indicators:
            if indicator in body_lower:
                return True
        
        # Check for absence of error indicators
        error_indicators = [
            'invalid', 'incorrect', 'wrong', 'failed', 'error',
            'denied', 'unauthorized', 'try again',
        ]
        
        has_error = any(err in body_lower for err in error_indicators)
        
        # If 200 with no error, might be successful
        if response.status_code == 200 and not has_error:
            return True
        
        return False
    
    def test_session_security(self, login_url: str, credentials: Dict,
                             protected_url: str) -> ScanResult:
        """
        Test session security after login
        
        LLM Usage:
            results = scanner.test_session_security(
                "/login",
                {"username": "test", "password": "test123"},
                "/api/user/profile"
            )
        """
        self.results = ScanResult(
            scanner_name=self.name,
            target_url=login_url,
            start_time=datetime.now()
        )
        
        # Login
        login_response = self.http_client.post_form(login_url, credentials)
        self.results.requests_made += 1
        
        # Check session cookies
        cookies = self.http_client.get_cookies()
        
        for name, value in cookies.items():
            # Check if session cookie has HttpOnly flag
            # (Would need to check Set-Cookie header for this)
            
            # Check for predictable session IDs
            if len(value) < 20:
                vuln = Vulnerability(
                    id=self._create_vuln_id("session-weak", login_url, name),
                    title="Weak Session Token",
                    description=f"Session cookie '{name}' appears to have weak entropy "
                               f"(length: {len(value)} chars)",
                    severity="medium",
                    category="auth",
                    url=login_url,
                    parameter=name,
                    evidence=f"Session token length: {len(value)}",
                    remediation="Use cryptographically secure random session tokens of at least 128 bits.",
                    cwe_id="CWE-330",
                    confidence="medium",
                )
                self.results.add_vulnerability(vuln)
        
        self.results.end_time = datetime.now()
        return self.results
